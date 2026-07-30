"""Create Findings/ThreatIndicators from exposures via rule + vuln matches.

For each Exposure:
  1. Match rule engine (service + configuration) -> 0-N rule matches
     -> ThreatIndicator (slice 15B: read-only exposure signal, not a
     CVE-on-an-asset the analyst can patch and close).
  2. Match vuln (product+version) -> 0-N CVE matches -> Finding (still
     Finding: a real CVE matched to a customer asset, full lifecycle).
  3. For each match: dedupe by (exposure_id, rule_id_or_cve).

Dedup note: Finding.metadata_/ThreatIndicator.metadata_ are plain JSON
columns (not JSONB), so they don't support Postgres's `->>` / astext
SQL-level filter reliably via SQLAlchemy. Existing dedup logic in this
codebase (enrichment/orchestrator.py, add_ioc.py) always loads rows and
inspects metadata_ in Python instead -- this follows the same pattern
rather than querying by key at the SQL level.
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from ati_evn.db.models import Exposure, Finding, FindingStatus, Severity, ThreatIndicator
from ati_evn.db.session import async_session
from ati_evn.db.threat_indicator_ttl import compute_expires_at
from ati_evn.exposure_rules.matcher import match_rules
from ati_evn.exposure_rules.vuln_matcher import batch_match_cves

logger = logging.getLogger("ati_evn.exposure_rules.finding_creator")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _rule_ti_key(exposure_id: int, rule_id: str) -> str:
    return f"exposure:{exposure_id}:rule:{rule_id}"


def _cve_finding_key(exposure_id: int, cve_id: str) -> str:
    return f"exposure:{exposure_id}:cve:{cve_id.upper()}"


async def process_exposures(exposure_ids: list[int]) -> dict:
    """Process a batch of exposures: match rules -> ThreatIndicator,
    vuln match -> Finding (CVE). Returns stats dict.

    service_findings/config_findings are misleadingly named -- both
    create ThreatIndicator rows (post slice 15A), not Finding rows.
    Only vuln_findings creates an actual Finding. Kept as-is (not
    renamed to indicators_*) since these two names are the public
    contract of this stats dict and are read by callers (e.g.
    weekly_scan.py); see the ThreatIndicator vs Finding note in this
    function's body for where each is actually created.
    """
    stats = {
        "processed": 0, "service_findings": 0, "config_findings": 0,
        "vuln_findings": 0, "vuln_llm_calls": 0, "skipped_dedup": 0,
    }

    async with async_session() as session:
        stmt = select(Exposure).where(Exposure.id.in_(exposure_ids))
        exposures = list((await session.execute(stmt)).scalars())

    if not exposures:
        return stats

    vuln_matches = await batch_match_cves(exposures)
    stats["vuln_llm_calls"] = len(vuln_matches)

    # Pre-load existing dedup keys for ALL exposures up front, in one pass,
    # before any Finding/ThreatIndicator is added to the session. Doing
    # this per-exposure inside the loop below (as originally written)
    # triggers SQLAlchemy autoflush on the SELECT, which tries to flush
    # prior iterations' not-yet-committed rows early -- surfacing
    # constraint violations (e.g. orphan exposures' NULL customer_id, see
    # the skip below) at the wrong point and mid-transaction.
    #
    # Two separate dedup key sets (slice 15B): rule matches now live in
    # ThreatIndicator (exposure_ti_key), CVE vuln matches still live in
    # Finding (exposure_finding_key).
    async with async_session() as session:
        existing_ti_keys_by_exposure: dict[int, set[str]] = {e.id: set() for e in exposures}
        ti_rows = await session.execute(select(ThreatIndicator.metadata_))
        for (meta,) in ti_rows:
            if not meta:
                continue
            eid = meta.get("exposure_id")
            key = meta.get("exposure_ti_key")
            if eid in existing_ti_keys_by_exposure and key:
                existing_ti_keys_by_exposure[eid].add(key)

        existing_keys_by_exposure: dict[int, set[str]] = {e.id: set() for e in exposures}
        rows = await session.execute(select(Finding.metadata_))
        for (meta,) in rows:
            if not meta:
                continue
            eid = meta.get("exposure_id")
            key = meta.get("exposure_finding_key")
            if eid in existing_keys_by_exposure and key:
                existing_keys_by_exposure[eid].add(key)

    async with async_session() as session:
        for exp in exposures:
            stats["processed"] += 1

            # Findings.customer_id is NOT NULL — an exposure with no asset
            # match (orphan, e.g. a scanned IP outside EVN's inventory)
            # has no customer to attribute a Finding to. Skip rule/vuln
            # matching for it rather than violate the constraint; the raw
            # Exposure row is still persisted and visible via
            # search_exposures/get_exposure_detail.
            if not exp.customer_id:
                logger.info(
                    "Skipping Finding creation for orphan exposure #%d (%s:%s) "
                    "-- no customer attribution", exp.id, exp.ip, exp.port,
                )
                continue

            existing_ti_keys = existing_ti_keys_by_exposure[exp.id]
            existing_keys = existing_keys_by_exposure[exp.id]

            rule_matches = match_rules(exp)
            for rule in rule_matches:
                key = _rule_ti_key(exp.id, rule["id"])
                if key in existing_ti_keys:
                    stats["skipped_dedup"] += 1
                    continue

                severity = SEVERITY_MAP.get(rule["severity"], Severity.MEDIUM)
                indicator_value = f"{exp.ip}:{exp.port}"

                ti = ThreatIndicator(
                    indicator_type="exposure",
                    indicator_value=indicator_value,
                    source_entity_type="exposure",
                    source_entity_id=exp.id,
                    customer_id=exp.customer_id,
                    matched_asset_value=(f"asset#{exp.asset_id}" if exp.asset_id else "orphan"),
                    source="censys",
                    sources=[f"exposure_{rule['type']}_rule"],
                    source_count=1,
                    title=rule["title"],
                    detection_reason=(
                        f"Exposure rule '{rule['id']}': service={exp.service_name}, "
                        f"port={exp.port}"
                    ),
                    severity=severity,
                    status="active",
                    first_seen=exp.first_seen_local,
                    last_seen=exp.last_seen_local,
                    expires_at=compute_expires_at("exposure", exp.first_seen_local),
                    metadata_={
                        "exposure_ti_key": key,
                        "exposure_id": exp.id,
                        "rule_id": rule["id"],
                        "rule_type": rule["type"],
                        "rule_description": rule["description"],
                        "ip": exp.ip, "port": exp.port,
                        "service": exp.service_name,
                        "product": exp.product, "version": exp.version,
                    },
                )
                session.add(ti)
                existing_ti_keys.add(key)
                if rule["type"] == "service":
                    stats["service_findings"] += 1
                else:
                    stats["config_findings"] += 1

            if exp.product and exp.version:
                key_tuple = (exp.product.lower(), exp.version.lower())
                cve_matches = vuln_matches.get(key_tuple) or []
                for cve_match in cve_matches:
                    cve_id = cve_match["cve_id"]
                    key = _cve_finding_key(exp.id, cve_id)
                    if key in existing_keys:
                        stats["skipped_dedup"] += 1
                        continue

                    cve_sev = cve_match.get("severity")
                    try:
                        severity = Severity(cve_sev) if cve_sev else Severity.MEDIUM
                    except (ValueError, TypeError):
                        severity = Severity.MEDIUM

                    title = (
                        f"{exp.product} {exp.version} — {cve_id} "
                        f"(confidence {cve_match['confidence']:.2f})"
                    )

                    finding = Finding(
                        customer_id=exp.customer_id,
                        ioc_type="cve_id",
                        ioc_value=cve_id.lower(),
                        title=title,
                        severity=severity,
                        status=FindingStatus.OPEN,
                        matched_asset=(f"asset#{exp.asset_id}" if exp.asset_id else "orphan"),
                        detection_reason=(
                            f"Exposure vuln match — {exp.product} v{exp.version} "
                            f"at {exp.ip}:{exp.port}. LLM: {cve_match['reason']}"
                        ),
                        sources=["exposure_vuln"],
                        source_count=1,
                        first_seen=exp.first_seen_local,
                        last_seen=exp.last_seen_local,
                        metadata_={
                            "exposure_finding_key": key,
                            "exposure_id": exp.id,
                            "cve_id": cve_id,
                            "cve_confidence": cve_match["confidence"],
                            "cve_reason": cve_match["reason"],
                            "ip": exp.ip, "port": exp.port,
                            "product": exp.product, "version": exp.version,
                        },
                    )
                    session.add(finding)
                    existing_keys.add(key)
                    stats["vuln_findings"] += 1

        await session.commit()

    return stats
