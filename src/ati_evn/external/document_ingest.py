"""Full 3-stage document leak pipeline:

  Stage 1: Bucket whitelist filter (deterministic)
  Stage 2: Rule engine (deterministic severity)
  Stage 3: LLM classifier (conditional -- only when the deterministic
           stages aren't confident enough)

Combination logic:
  rule match + LLM relevant     -> ThreatIndicator at rule severity
  rule match + LLM NOT relevant -> skip (false positive)
  no rule match + LLM relevant  -> ThreatIndicator at MEDIUM
  no rule match + LLM NOT relevant -> skip

Rule high/critical + bucket whitelisted -> skip LLM entirely
(deterministic pass, saves a call).

Slice 15B: this pipeline creates ThreatIndicator rows (not Finding) --
document leaks are a read-only signal an analyst can acknowledge/note,
not a CVE-on-an-asset they can patch and close.

Dedup note: ThreatIndicator.metadata_ is a plain JSON column (not
JSONB), so a SQL-level `->>`/astext filter isn't reliable via
SQLAlchemy -- this follows the same pre-load-then-filter-in-Python
pattern established in exposure_rules/finding_creator.py (slice 9B)
rather than repeating that bug here.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from ati_evn.alerts.dedupe import compute_dedupe_key, find_existing_dispatch
from ati_evn.alerts.dispatch_rule import should_dispatch_ti
from ati_evn.config import get_settings
from ati_evn.db.models import AlertQueue, CustomerAsset, ExposedDocument, Severity, ThreatIndicator
from ati_evn.db.session import async_session
from ati_evn.db.threat_indicator_ttl import compute_expires_at
from ati_evn.document_rules.llm_classifier import check_relevance
from ati_evn.document_rules.matcher import match_document_rule
from ati_evn.document_rules.whitelist import bucket_matches_whitelist

logger = logging.getLogger("ati_evn.external.document_ingest")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


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


def _needs_llm(rule_matched: dict | None, whitelist_pass: bool) -> bool:
    """Decide if the LLM classifier should run. Skip only when a rule
    matched HIGH/CRITICAL and the bucket is whitelisted (deterministic
    pass); otherwise verify relevance."""
    if not rule_matched:
        return True
    sev = rule_matched.get("severity", "")
    if sev in ("high", "critical") and whitelist_pass:
        return False
    return True


async def _existing_ti_keys() -> set[str]:
    """Load all document_ti_key values already recorded, by scanning
    ThreatIndicator.metadata_ in Python (see module docstring)."""
    async with async_session() as session:
        rows = await session.execute(select(ThreatIndicator.metadata_))
        keys: set[str] = set()
        for (meta,) in rows:
            if meta and meta.get("document_ti_key"):
                keys.add(meta["document_ti_key"])
        return keys


async def ingest_documents(files: list[dict]) -> dict:
    """Full pipeline: whitelist -> rule -> LLM -> upsert -> ThreatIndicators.

    Post slice 15A, document leaks create ThreatIndicator rows, not
    Finding rows -- stats["indicators_created"] reflects that (renamed
    from "findings_created", same rename as brand_abuse_ingest.py).
    """
    settings = get_settings()
    stats = {
        "new": 0, "updated": 0,
        "whitelisted": 0, "rule_matched": 0,
        "llm_calls": 0, "llm_relevant": 0,
        "indicators_created": 0, "queued_for_alert": 0,
    }
    now = datetime.now(timezone.utc)

    existing_ti_keys = await _existing_ti_keys()

    async with async_session() as session:
        for doc in files:
            wl = bucket_matches_whitelist(doc["bucket_url"])
            if wl:
                stats["whitelisted"] += 1

            rule = match_document_rule(doc)
            if rule:
                stats["rule_matched"] += 1

            llm_checked = False
            llm_reason = None
            if _needs_llm(rule, wl):
                llm_relevant, llm_reason = await check_relevance(doc)
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

            asset_id, customer_id = await _attribute_by_keyword(session, doc["keyword_matched"])

            stmt = select(ExposedDocument).where(
                ExposedDocument.bucket_url == doc["bucket_url"],
                ExposedDocument.file_path == doc["file_path"],
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()

            if existing:
                existing.last_seen_local = now
                existing.status = "active"
                existing.file_size = doc.get("file_size") or existing.file_size
                existing.last_modified = doc.get("last_modified") or existing.last_modified
                existing.bucket_whitelisted = wl
                existing.rule_matched = rule["id"] if rule else None
                existing.rule_severity = rule["severity"] if rule else None
                existing.llm_relevance_checked = llm_checked
                existing.llm_relevance_score = llm_relevant
                existing.llm_reasoning = llm_reason
                existing.matched_asset_id = asset_id
                existing.customer_id = customer_id
                existing.grayhat_raw = doc.get("raw") or {}
                existing.updated_at = now
                doc_row = existing
                stats["updated"] += 1
            else:
                doc_row = ExposedDocument(
                    bucket_url=doc["bucket_url"],
                    file_path=doc["file_path"],
                    filename=doc["filename"],
                    file_extension=doc.get("file_extension"),
                    file_size=doc.get("file_size"),
                    last_modified=doc.get("last_modified"),
                    keyword_matched=doc["keyword_matched"],
                    matched_asset_id=asset_id,
                    customer_id=customer_id,
                    bucket_whitelisted=wl,
                    rule_matched=rule["id"] if rule else None,
                    rule_severity=rule["severity"] if rule else None,
                    llm_relevance_checked=llm_checked,
                    llm_relevance_score=llm_relevant,
                    llm_reasoning=llm_reason,
                    first_seen_local=now,
                    last_seen_local=now,
                    status="active",
                    grayhat_raw=doc.get("raw") or {},
                )
                session.add(doc_row)
                await session.flush()
                stats["new"] += 1

            if should_create_finding and doc_row.customer_id:
                key = f"doc:{doc_row.id}"
                if key not in existing_ti_keys:
                    title = rule["title"] if rule else "Public exposure of potentially EVN-related document"
                    description = (
                        rule["description"] if rule
                        else "Document appears related to EVN based on LLM assessment."
                    )
                    ti = ThreatIndicator(
                        indicator_type="exposed_document",
                        indicator_value=f"{doc_row.bucket_url}/{doc_row.file_path}"[:2000],
                        source_entity_type="exposed_document",
                        source_entity_id=doc_row.id,
                        customer_id=doc_row.customer_id,
                        matched_asset_value=f"keyword:{doc_row.keyword_matched}",
                        source="grayhatwarfare",
                        sources=["exposed_document"],
                        source_count=1,
                        title=f"{title}: {doc_row.filename}",
                        detection_reason=(
                            f"Document leak -- bucket={doc_row.bucket_url}, "
                            f"file={doc_row.file_path}, "
                            f"rule={doc_row.rule_matched or 'none'}, "
                            f"LLM relevant={doc_row.llm_relevance_score}"
                        ),
                        severity=severity,
                        status="active",
                        first_seen=doc_row.first_seen_local,
                        last_seen=doc_row.last_seen_local,
                        expires_at=compute_expires_at("exposed_document", doc_row.first_seen_local),
                        metadata_={
                            "document_ti_key": key,
                            "document_id": doc_row.id,
                            "bucket_url": doc_row.bucket_url,
                            "file_path": doc_row.file_path,
                            "filename": doc_row.filename,
                            "keyword_matched": doc_row.keyword_matched,
                            "rule_id": doc_row.rule_matched,
                            "rule_description": description,
                            "llm_relevance": doc_row.llm_relevance_score,
                            "llm_reasoning": doc_row.llm_reasoning,
                        },
                    )
                    session.add(ti)
                    await session.flush()
                    existing_ti_keys.add(key)
                    stats["indicators_created"] += 1

                    # Push to alert_queue -- Bot 1 (telegram/bot_alert.py)
                    # polls this table and never talks to this pipeline
                    # directly (same contract as match/customer_router.py's
                    # slice 5A dispatch step, and brand_abuse_ingest.py).
                    ok, reason = should_dispatch_ti(ti)
                    if ok:
                        dedupe_key = compute_dedupe_key(
                            ti.customer_id, ti.indicator_value, doc_row.matched_asset_id,
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
