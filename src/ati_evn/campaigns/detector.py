"""Campaign detection algorithm.

Clusters findings within customer + time window by ATT&CK technique
overlap. Applies false-positive filters A (bulk-ingest heuristic) + C
(single-source rejection except analyst-driven).

Public API:
  async def detect_campaigns(...) -> list[dict]
  async def persist_campaigns(...) -> tuple[int, int]  # (created, updated)
  async def run_detection_once() -> dict
"""
from __future__ import annotations

import logging
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import Campaign, CampaignFinding, CampaignStatus, Detection, Finding
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.campaigns.detector")

# Config knobs (surface to settings if needed)
WINDOW_HOURS = 6
MIN_FINDINGS = 3
MIN_TECHNIQUE_OVERLAP = 0.5      # 50%
BULK_INGEST_TIME_WINDOW_SEC = 60  # A3 heuristic
BULK_INGEST_MAJORITY = 0.8       # >=80% findings in +-60s = bulk artifact
NOTIFICATION_THRESHOLD = 0.75
LOOKBACK_HOURS = 24               # scan last 24h of findings

ANALYST_INTENT_SOURCES = {"internal", "article_ingested"}


async def _load_recent_findings(
    session: AsyncSession, lookback_hours: int,
) -> list[dict]:
    """Fetch findings from last N hours with attack_context.

    Returns list of dicts with keys needed for clustering:
      finding_id, customer_id, first_seen, created_at, severity,
      technique_ids (set), source, matched_asset, ioc_value
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    stmt = select(Finding).where(
        Finding.first_seen >= cutoff,
    ).order_by(Finding.first_seen)
    rows = list((await session.execute(stmt)).scalars())

    out = []
    for f in rows:
        meta = f.metadata_ or {}
        ac = meta.get("attack_context") or {}
        techs = ac.get("techniques") or []
        if not techs:
            continue
        technique_ids = {t.get("id") for t in techs if t.get("id")}
        if not technique_ids:
            continue

        # Get source from Detection (the primary source is what we care
        # about for filter C)
        det_result = await session.execute(
            select(Detection.source, Detection.created_at)
            .where(Detection.finding_id == f.id)
            .order_by(Detection.created_at)
            .limit(1)
        )
        det_row = det_result.first()
        source = (det_row[0] if det_row else "unknown")
        det_created = det_row[1] if det_row else f.first_seen

        tactics = set()
        for t in techs:
            from ati_evn.enrichment.attack_catalog import get_tactics_for_technique
            tactics.update(get_tactics_for_technique(t.get("id", "")))

        out.append({
            "finding_id": f.id,
            "customer_id": f.customer_id,
            "first_seen": f.first_seen,
            "created_at": det_created,
            "severity": f.severity,
            "matched_asset": f.matched_asset or "",
            "ioc_value": f.ioc_value,
            "technique_ids": technique_ids,
            "tactics": tactics,
            "source": source,
        })
    return out


def _bulk_ingest_check(findings: list[dict]) -> bool:
    """Filter A3: return True if this cluster is likely a bulk ingest
    artifact (>= BULK_INGEST_MAJORITY of findings created within
    BULK_INGEST_TIME_WINDOW_SEC of each other)."""
    if len(findings) < 2:
        return False
    timestamps = sorted(
        (f["created_at"] or f["first_seen"]).timestamp() for f in findings
    )
    median = statistics.median(timestamps)
    within = sum(1 for t in timestamps if abs(t - median) <= BULK_INGEST_TIME_WINDOW_SEC)
    ratio = within / len(timestamps)
    return ratio >= BULK_INGEST_MAJORITY


def _technique_overlap_ratio(findings: list[dict]) -> float:
    """Fraction of techniques shared by >=50% of findings in the cluster.

    For each technique in the union, if it appears in >=50% of findings,
    count it. Return count / total_union.
    """
    if len(findings) < 2:
        return 0.0
    counter: Counter = Counter()
    for f in findings:
        counter.update(f["technique_ids"])
    total_union = len(counter)
    if total_union == 0:
        return 0.0
    threshold = len(findings) / 2
    shared = sum(1 for _, c in counter.items() if c >= threshold)
    return shared / total_union


def _compute_confidence(findings: list[dict]) -> tuple[float, str]:
    """Weighted confidence + reason string."""
    n = len(findings)
    # 1. Technique overlap
    tech_overlap = _technique_overlap_ratio(findings)

    # 2. Temporal density: findings per hour normalized (max 1.0)
    timestamps = [(f["first_seen"] or f["created_at"]).timestamp() for f in findings]
    span_hours = (max(timestamps) - min(timestamps)) / 3600 or 0.01
    density_per_hour = n / span_hours
    temporal_density = min(density_per_hour / 5.0, 1.0)  # 5/h -> 1.0

    # 3. Asset diversity: distinct matched_assets, normalized at 5
    assets = {f["matched_asset"] for f in findings if f["matched_asset"]}
    asset_diversity = min(len(assets) / 5.0, 1.0)

    # 4. Source diversity: distinct sources, normalized at 3
    sources = {f["source"] for f in findings}
    source_diversity = min(len(sources) / 3.0, 1.0)

    confidence = (
        tech_overlap * 0.4 +
        temporal_density * 0.3 +
        asset_diversity * 0.2 +
        source_diversity * 0.1
    )

    reason = (
        f"{n} findings, {span_hours:.1f}h window, "
        f"technique overlap {tech_overlap:.0%}, "
        f"{len(assets)} assets, {len(sources)} sources "
        f"({','.join(sorted(sources))})"
    )
    return confidence, reason


def _cluster_by_technique(customer_findings: list[dict]) -> list[list[dict]]:
    """Greedy cluster within a customer's findings.

    Algorithm:
      1. Sort by first_seen
      2. For each finding, look at findings within WINDOW_HOURS AFTER it
      3. Group if >=50% technique overlap
      4. Return only clusters with >=3 findings
    """
    sorted_findings = sorted(customer_findings, key=lambda f: f["first_seen"])
    used = set()
    clusters: list[list[dict]] = []

    for i, seed in enumerate(sorted_findings):
        if seed["finding_id"] in used:
            continue
        window_end = seed["first_seen"] + timedelta(hours=WINDOW_HOURS)
        cluster = [seed]
        for j in range(i + 1, len(sorted_findings)):
            candidate = sorted_findings[j]
            if candidate["finding_id"] in used:
                continue
            if candidate["first_seen"] > window_end:
                break
            # Compute overlap with current cluster's shared techniques
            cluster_common = set.intersection(*(c["technique_ids"] for c in cluster))
            overlap_with_candidate = (
                len(cluster_common & candidate["technique_ids"])
                / max(len(candidate["technique_ids"]), 1)
            )
            if overlap_with_candidate >= MIN_TECHNIQUE_OVERLAP:
                cluster.append(candidate)
        if len(cluster) >= MIN_FINDINGS:
            for c in cluster:
                used.add(c["finding_id"])
            clusters.append(cluster)

    return clusters


async def detect_campaigns(
    session: AsyncSession, lookback_hours: int = LOOKBACK_HOURS,
) -> list[dict]:
    """Return list of campaign dicts (not yet persisted).

    Each: {customer_id, window_start, window_end, findings [list of dicts],
           technique_ids, tactic_ids, source_ids, confidence, reason,
           severities, asset_count}
    """
    findings = await _load_recent_findings(session, lookback_hours)
    logger.info("Loaded %d recent findings with attack_context", len(findings))

    # Group by customer
    by_customer: dict[int, list[dict]] = defaultdict(list)
    for f in findings:
        by_customer[f["customer_id"]].append(f)

    campaigns_out: list[dict] = []
    for customer_id, cust_findings in by_customer.items():
        if len(cust_findings) < MIN_FINDINGS:
            continue

        clusters = _cluster_by_technique(cust_findings)
        for cluster in clusters:
            # Filter A: bulk-ingest heuristic
            if _bulk_ingest_check(cluster):
                logger.debug(
                    "Cluster (customer=%d, %d findings) filtered as bulk ingest",
                    customer_id, len(cluster),
                )
                continue

            # Filter C: single-source rejection unless analyst intent
            sources = {f["source"] for f in cluster}
            if len(sources) == 1:
                only_source = next(iter(sources))
                if only_source not in ANALYST_INTENT_SOURCES:
                    logger.debug(
                        "Cluster (customer=%d) filtered as single-source '%s'",
                        customer_id, only_source,
                    )
                    continue

            confidence, reason = _compute_confidence(cluster)

            # Aggregate
            all_techs = set()
            all_tactics = set()
            severities: Counter = Counter()
            for f in cluster:
                all_techs.update(f["technique_ids"])
                all_tactics.update(f["tactics"])
                sev = f["severity"]
                severities[sev.value if hasattr(sev, "value") else str(sev)] += 1

            assets = {f["matched_asset"] for f in cluster if f["matched_asset"]}

            campaigns_out.append({
                "customer_id": customer_id,
                "window_start": min(f["first_seen"] for f in cluster),
                "window_end": max(f["first_seen"] for f in cluster),
                "findings": cluster,
                "technique_ids": sorted(all_techs),
                "tactic_ids": sorted(all_tactics),
                "source_ids": sorted(sources),
                "severities": dict(severities),
                "confidence": round(confidence, 3),
                "detection_reason": reason,
                "asset_count": len(assets),
            })

    logger.info("Detected %d candidate campaigns after filters", len(campaigns_out))
    return campaigns_out


async def persist_campaigns(
    session: AsyncSession, detected: list[dict],
) -> tuple[int, int, list[int]]:
    """Persist campaign dicts to DB. Return (created, updated, new_ids).

    Dedupe by (customer_id, window_start, technique_ids) — if a matching
    candidate exists in CANDIDATE status, update finding list rather
    than creating duplicate. If status is CONFIRMED/REJECTED, skip
    (analyst already reviewed).

    new_ids is only the campaigns created fresh this run — used by the
    caller to gate Bot 1 alert dispatch to newly-detected campaigns,
    not ones that already got their initial notification.
    """
    created = 0
    updated = 0
    new_ids: list[int] = []

    for c in detected:
        # Look for existing candidate campaign with same window + tech set
        stmt = select(Campaign).where(
            Campaign.customer_id == c["customer_id"],
            Campaign.status == CampaignStatus.CANDIDATE,
            Campaign.window_start >= c["window_start"] - timedelta(hours=1),
            Campaign.window_start <= c["window_start"] + timedelta(hours=1),
        )
        existing = (await session.execute(stmt)).scalars().first()

        if existing:
            # Update aggregates if same technique set (Jaccard >= 0.7)
            old_techs = set(existing.technique_ids or [])
            new_techs = set(c["technique_ids"])
            jaccard = (
                len(old_techs & new_techs) / max(len(old_techs | new_techs), 1)
            )
            if jaccard >= 0.7:
                existing.finding_count = len(c["findings"])
                existing.asset_count = c["asset_count"]
                existing.technique_ids = c["technique_ids"]
                existing.tactic_ids = c["tactic_ids"]
                existing.source_ids = c["source_ids"]
                existing.severities = c["severities"]
                existing.confidence = c["confidence"]
                existing.detection_reason = c["detection_reason"]
                existing.window_end = c["window_end"]
                existing.updated_at = datetime.now(timezone.utc)
                # Re-link findings (delete old links, add new)
                await session.execute(
                    delete(CampaignFinding).where(
                        CampaignFinding.campaign_id == existing.id
                    )
                )
                for f in c["findings"]:
                    session.add(CampaignFinding(
                        campaign_id=existing.id,
                        finding_id=f["finding_id"],
                    ))
                updated += 1
                continue

        # Create new
        campaign = Campaign(
            customer_id=c["customer_id"],
            window_start=c["window_start"],
            window_end=c["window_end"],
            finding_count=len(c["findings"]),
            asset_count=c["asset_count"],
            technique_ids=c["technique_ids"],
            tactic_ids=c["tactic_ids"],
            source_ids=c["source_ids"],
            severities=c["severities"],
            confidence=c["confidence"],
            detection_reason=c["detection_reason"],
            status=CampaignStatus.CANDIDATE,
        )
        session.add(campaign)
        await session.flush()  # get campaign.id

        for f in c["findings"]:
            session.add(CampaignFinding(
                campaign_id=campaign.id,
                finding_id=f["finding_id"],
            ))
        created += 1
        new_ids.append(campaign.id)

    await session.commit()
    return created, updated, new_ids


async def expire_stale_candidates(session: AsyncSession) -> int:
    """Mark candidates as EXPIRED if created >7 days ago and still
    CANDIDATE status."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    result = await session.execute(
        update(Campaign)
        .where(
            Campaign.status == CampaignStatus.CANDIDATE,
            Campaign.created_at < cutoff,
        )
        .values(status=CampaignStatus.EXPIRED, updated_at=datetime.now(timezone.utc))
    )
    await session.commit()
    return result.rowcount or 0


async def run_detection_once() -> dict:
    """Full detection cycle: detect -> persist -> expire stale -> notify.
    Returns stats dict."""
    from ati_evn.campaigns.notify import dispatch_campaign_alerts_if_high

    async with async_session() as session:
        detected = await detect_campaigns(session)
        created, updated, new_ids = await persist_campaigns(session, detected)
        expired = await expire_stale_candidates(session)

    # Dispatch alerts for newly created high-confidence campaigns only —
    # updates to an already-notified candidate don't re-notify.
    dispatched = await dispatch_campaign_alerts_if_high(new_ids)

    stats = {
        "detected": len(detected),
        "created": created,
        "updated": updated,
        "expired": expired,
        "alerts_dispatched": dispatched,
    }
    logger.info("Campaign detection run: %s", stats)
    return stats
