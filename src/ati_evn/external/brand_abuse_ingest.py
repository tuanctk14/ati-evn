"""Full 3-stage brand abuse pipeline:

  Stage 1: Typosquat check (deterministic, Levenshtein vs real EVN
           domains) -- computed first since it can promote severity
           independent of the YAML rule engine.
  Stage 2: YAML rule engine (deterministic severity, brand_abuse_rules.yaml)
  Stage 3: LLM classifier (conditional -- only when rule engine did NOT
           match, or matched at LOW severity)

Combination logic (mirrors document_ingest.py):
  rule/typosquat match + LLM relevant     -> ThreatIndicator at matched severity
  rule/typosquat match + LLM NOT relevant -> skip (false positive)
  no match + LLM relevant                 -> ThreatIndicator at MEDIUM
  no match + LLM NOT relevant             -> skip

Rule matched at HIGH/CRITICAL -> skip LLM entirely (deterministic pass).
Typosquat detection alone (HIGH) also skips LLM, same reasoning.

Slice 15B: this pipeline creates ThreatIndicator rows (not Finding) --
brand abuse is a read-only signal an analyst can acknowledge/note, not
a CVE-on-an-asset they can patch and close.

Dedup note: ThreatIndicator.metadata_ is a plain JSON column (not
JSONB), so a SQL-level `->>`/astext filter isn't reliable via
SQLAlchemy -- this follows the same pre-load-then-filter-in-Python
pattern established in document_ingest.py / exposure_rules/finding_creator.py
rather than repeating that bug here.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from ati_evn.alerts.dedupe import compute_dedupe_key, find_existing_dispatch
from ati_evn.alerts.dispatch_rule import should_dispatch_ti
from ati_evn.brand_rules.llm_classifier import check_relevance
from ati_evn.brand_rules.matcher import match_brand_rule
from ati_evn.brand_rules.typosquat import is_typosquat
from ati_evn.config import get_settings
from ati_evn.db.models import (
    AlertQueue,
    BrandAbuseSighting,
    Customer,
    CustomerAsset,
    Severity,
    ThreatIndicator,
)
from ati_evn.db.session import async_session
from ati_evn.db.threat_indicator_ttl import compute_expires_at

logger = logging.getLogger("ati_evn.external.brand_abuse_ingest")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

TYPOSQUAT_RULE = {
    "id": "typosquat_detected",
    "severity": "high",
    "title": "Typosquat domain detected",
    "description": (
        "Domain is a close edit-distance match to a real EVN domain -- "
        "likely typosquatting for phishing. Verify manually."
    ),
}


async def _evn_domains(session) -> list[str]:
    rows = await session.execute(
        select(Customer.primary_domain).where(Customer.primary_domain.isnot(None))
    )
    return [d for (d,) in rows if d]


async def _attribute_by_keyword(session, keyword: str) -> tuple[int | None, int | None]:
    """Return (asset_id, customer_id) for the matched keyword, via
    case-insensitive exact match against CustomerAsset.asset_value."""
    row = await session.execute(
        select(CustomerAsset).where(
            CustomerAsset.asset_value.ilike(keyword),
            CustomerAsset.deleted_at.is_(None),
        ).limit(1)
    )
    asset = row.scalar_one_or_none()
    if asset:
        return asset.id, asset.customer_id
    return None, None


def _needs_llm(rule_matched: dict | None) -> bool:
    """Skip LLM only when a rule/typosquat matched at HIGH/CRITICAL --
    otherwise verify relevance (no match, or a future LOW rule)."""
    if not rule_matched:
        return True
    return rule_matched.get("severity") not in ("high", "critical")


async def _existing_ti_keys() -> set[str]:
    """Load all brand_abuse_ti_key values already recorded, by scanning
    ThreatIndicator.metadata_ in Python (see module docstring)."""
    async with async_session() as session:
        rows = await session.execute(select(ThreatIndicator.metadata_))
        keys: set[str] = set()
        for (meta,) in rows:
            if meta and meta.get("brand_abuse_ti_key"):
                keys.add(meta["brand_abuse_ti_key"])
        return keys


async def ingest_brand_abuse(sightings: list[dict]) -> dict:
    """Full pipeline: typosquat -> rule -> LLM -> upsert -> ThreatIndicators.

    Post slice 15A, brand abuse sightings create ThreatIndicator rows,
    not Finding rows -- stats["indicators_created"] reflects that (was
    misleadingly named "findings_created" until this was caught during
    manual testing, when a scan reported "3 finding mới" to the analyst
    despite the Finding table having no new rows).
    """
    settings = get_settings()
    stats = {
        "new": 0, "updated": 0,
        "typosquat_matched": 0, "rule_matched": 0,
        "llm_calls": 0, "llm_relevant": 0,
        "indicators_created": 0, "queued_for_alert": 0,
    }
    now = datetime.now(timezone.utc)

    existing_ti_keys = await _existing_ti_keys()

    async with async_session() as session:
        evn_domains = await _evn_domains(session)

        for sighting in sightings:
            typosquat_hit, typosquat_dist = is_typosquat(
                sighting.get("domain") or "", evn_domains, settings.typosquat_max_distance,
            )

            rule = match_brand_rule(sighting, evn_domains)
            if typosquat_hit and (not rule or rule["severity"] not in ("critical",)):
                # Typosquat (HIGH) takes precedence over anything below
                # CRITICAL from the YAML rule engine.
                rule = TYPOSQUAT_RULE
            if typosquat_hit:
                stats["typosquat_matched"] += 1
            if rule and rule["id"] != "typosquat_detected":
                stats["rule_matched"] += 1

            llm_checked = False
            llm_reason = None
            if _needs_llm(rule):
                llm_relevant, llm_reason = await check_relevance(sighting)
                llm_checked = True
                stats["llm_calls"] += 1
                if llm_relevant:
                    stats["llm_relevant"] += 1
            else:
                llm_relevant = True  # deterministic pass

            should_create_finding = False
            severity = Severity.MEDIUM
            if rule and llm_relevant:
                should_create_finding = True
                severity = SEVERITY_MAP.get(rule["severity"], Severity.MEDIUM)
            elif (not rule) and llm_relevant:
                should_create_finding = True
                severity = Severity.MEDIUM

            asset_id, customer_id = await _attribute_by_keyword(session, sighting["keyword_matched"])

            stmt = select(BrandAbuseSighting).where(BrandAbuseSighting.url == sighting["url"])
            existing = (await session.execute(stmt)).scalar_one_or_none()

            if existing:
                existing.last_seen_local = now
                existing.status = "active"
                existing.scan_uuid = sighting.get("scan_uuid") or existing.scan_uuid
                existing.page_title = sighting.get("page_title") or existing.page_title
                existing.rule_matched = rule["id"] if rule else None
                existing.rule_severity = rule["severity"] if rule else None
                existing.llm_classified = llm_checked
                existing.llm_relevant = llm_relevant
                existing.llm_reasoning = llm_reason
                existing.verdict_malicious = sighting.get("verdict_malicious", False)
                existing.verdict_score = sighting.get("verdict_score")
                existing.engines_malicious_total = sighting.get("engines_malicious_total")
                existing.typosquat_distance = typosquat_dist
                existing.matched_asset_id = asset_id
                existing.customer_id = customer_id
                existing.urlscan_raw = sighting.get("result_raw") or sighting.get("raw") or {}
                existing.updated_at = now
                sight_row = existing
                stats["updated"] += 1
            else:
                sight_row = BrandAbuseSighting(
                    scan_uuid=sighting.get("scan_uuid") or "",
                    url=sighting["url"],
                    domain=sighting.get("domain") or "",
                    page_title=sighting.get("page_title"),
                    keyword_matched=sighting["keyword_matched"],
                    matched_asset_id=asset_id,
                    customer_id=customer_id,
                    rule_matched=rule["id"] if rule else None,
                    rule_severity=rule["severity"] if rule else None,
                    llm_classified=llm_checked,
                    llm_relevant=llm_relevant,
                    llm_reasoning=llm_reason,
                    verdict_malicious=sighting.get("verdict_malicious", False),
                    verdict_score=sighting.get("verdict_score"),
                    engines_malicious_total=sighting.get("engines_malicious_total"),
                    typosquat_distance=typosquat_dist,
                    first_seen_local=now,
                    last_seen_local=now,
                    status="active",
                    urlscan_raw=sighting.get("result_raw") or sighting.get("raw") or {},
                )
                session.add(sight_row)
                await session.flush()
                stats["new"] += 1

            if should_create_finding and sight_row.customer_id:
                key = f"brand_abuse:{sight_row.id}"
                if key not in existing_ti_keys:
                    title = rule["title"] if rule else "Possible EVN brand abuse detected"
                    description = (
                        rule["description"] if rule
                        else "URL appears related to EVN brand based on LLM assessment."
                    )
                    ti = ThreatIndicator(
                        indicator_type="brand_abuse",
                        indicator_value=sight_row.url[:2000],
                        source_entity_type="brand_abuse_sighting",
                        source_entity_id=sight_row.id,
                        customer_id=sight_row.customer_id,
                        matched_asset_value=f"keyword:{sight_row.keyword_matched}",
                        source="urlscan",
                        sources=["brand_abuse"],
                        source_count=1,
                        title=f"{title}: {sight_row.domain}",
                        detection_reason=(
                            f"Brand abuse -- url={sight_row.url}, "
                            f"rule={sight_row.rule_matched or 'none'}, "
                            f"typosquat_dist={sight_row.typosquat_distance}, "
                            f"LLM relevant={sight_row.llm_relevant}"
                        ),
                        severity=severity,
                        status="active",
                        first_seen=sight_row.first_seen_local,
                        last_seen=sight_row.last_seen_local,
                        expires_at=compute_expires_at("brand_abuse", sight_row.first_seen_local),
                        metadata_={
                            "brand_abuse_ti_key": key,
                            "brand_abuse_id": sight_row.id,
                            "url": sight_row.url,
                            "domain": sight_row.domain,
                            "page_title": sight_row.page_title,
                            "keyword_matched": sight_row.keyword_matched,
                            "rule_id": sight_row.rule_matched,
                            "rule_description": description,
                            "typosquat_distance": sight_row.typosquat_distance,
                            "llm_relevant": sight_row.llm_relevant,
                            "llm_reasoning": sight_row.llm_reasoning,
                        },
                    )
                    session.add(ti)
                    await session.flush()
                    existing_ti_keys.add(key)
                    stats["indicators_created"] += 1

                    # Push to alert_queue -- Bot 1 (telegram/bot_alert.py)
                    # polls this table and never talks to this pipeline
                    # directly (same contract as match/customer_router.py's
                    # slice 5A dispatch step).
                    ok, reason = should_dispatch_ti(ti)
                    if ok:
                        dedupe_key = compute_dedupe_key(
                            ti.customer_id, ti.indicator_value, sight_row.matched_asset_id,
                        )
                        existing_id = await find_existing_dispatch(
                            session, dedupe_key, settings.alert_dedupe_window_minutes,
                        )
                        state = "deduped" if existing_id else "pending"
                        session.add(AlertQueue(
                            threat_indicator_id=ti.id,
                            customer_id=ti.customer_id,
                            state=state,
                            dispatch_reason=reason,
                            dedupe_key=dedupe_key,
                            deduped_of_id=existing_id,
                        ))
                        stats["queued_for_alert"] += 1

        await session.commit()

    return stats
