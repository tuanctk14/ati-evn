"""Provider-agnostic aggregate computation.

Input: IpEnrichment rows for one IP.
Output: IpAggregatedScore upsert.

Logic:
  - Weight normalize: only sum weights for providers with a valid verdict.
    Scale result back to the full [0, 100] range.
  - confidence = positive_count / responded_count
  - coverage = responded_count / enabled_count

KEY PROPERTY: this function has ZERO provider name hardcoded. Every
provider name it touches comes from enrichment_config.yaml (via
get_weights()) or from the IpEnrichment rows themselves. Add a new
adapter + a weight entry in the YAML -> 0 change here.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from ati_evn.db.models import IpAggregatedScore, IpEnrichment
from ati_evn.db.session import async_session
from ati_evn.enrichment_v2.config import get_weights

logger = logging.getLogger("ati_evn.enrichment_v2.aggregator")


def compute_consensus_status(provider_verdicts: dict[str, str]) -> str:
    """Classify provider AGREEMENT, independent of aggregate_risk_score.

    Risk score answers "how dangerous is this IP?" (a weighted average,
    which a strong minority verdict can get diluted into a low number).
    Consensus status answers "do providers agree?" -- it looks only at
    the verdict labels, never at scores or weights, so a 2-malicious /
    2-benign split is flagged as disputed even if the weighted score
    lands in "moderate" or "clean" territory.

    - disputed: at least one "malicious" AND at least one "benign"
      verdict present at the same time (real disagreement, not just
      differing confidence).
    - consensus: no disagreement -- either every responded provider is
      benign, or malicious/suspicious are present but no provider
      called it benign outright.
    - partial_consensus: everything else (e.g. only suspicious+benign,
      or only suspicious+malicious without an outright benign call --
      some difference in strength, but not a flat contradiction).
    """
    verdicts = [v for v in provider_verdicts.values() if v in ("benign", "suspicious", "malicious")]
    if not verdicts:
        return "consensus"

    has_malicious = "malicious" in verdicts
    has_suspicious = "suspicious" in verdicts
    has_benign = "benign" in verdicts

    if has_malicious and has_benign:
        return "disputed"
    if has_benign and not has_malicious and not has_suspicious:
        return "consensus"          # every responded provider says benign
    if has_malicious and not has_benign:
        return "consensus"          # malicious/suspicious agree, no outright benign call
    return "partial_consensus"      # e.g. suspicious+benign mix, weaker disagreement


def compute_aggregate_from_rows(enrichments: list[IpEnrichment]) -> dict:
    """Pure function: compute aggregate stats from a list of enrichment
    rows. Returns dict ready for upsert. Does NOT touch DB.

    Rules:
      - responded = rows for a provider present in the weights config
        (i.e. we've queried this provider -- data OR error, either counts)
      - enabled = all providers in weights config
      - weight_used = sum(weight for provider) over rows with a concrete
        verdict (benign/suspicious/malicious) -- unknown/error rows are
        excluded from the score sum but still count toward "responded"
      - aggregate_risk = sum(score*weight) / weight_used * sum(all weights)
        (rescale back to 0-100 as if every provider had responded)
    """
    weights = get_weights()  # e.g. {virustotal: 0.35, abuseipdb: 0.30, ...}
    enabled_providers = set(weights.keys())
    enabled_count = len(enabled_providers)

    responded_rows = [e for e in enrichments if e.provider in enabled_providers]
    responded_count = len(responded_rows)

    aggregate_sum = 0.0
    weight_used = 0.0
    max_score = 0.0
    positive_count = 0
    supporting_count = 0
    provider_mask_parts: list[str] = []
    provider_verdicts_dict: dict = {}

    for e in responded_rows:
        provider_verdicts_dict[e.provider] = e.verdict or "unknown"

        if e.verdict in ("benign", "suspicious", "malicious"):
            weight = weights.get(e.provider, 0)
            score = e.risk_score or 0
            aggregate_sum += score * weight
            weight_used += weight
            if score > max_score:
                max_score = score

            if e.verdict == "malicious":
                positive_count += 1
                supporting_count += 1
                provider_mask_parts.append(e.provider)
            elif e.verdict == "suspicious":
                supporting_count += 1

    total_weight = sum(weights.values())
    if weight_used > 0:
        aggregate_risk = aggregate_sum / weight_used * total_weight
    else:
        aggregate_risk = 0.0

    confidence = positive_count / responded_count if responded_count > 0 else 0.0
    coverage = responded_count / enabled_count if enabled_count > 0 else 0.0

    return {
        "aggregate_risk_score": round(aggregate_risk, 2),
        "max_provider_score": round(max_score, 2),
        "confidence_score": round(confidence, 3),
        "positive_provider_count": positive_count,
        "supporting_provider_count": supporting_count,
        "coverage_score": round(coverage, 3),
        "responded_provider_count": responded_count,
        "enabled_provider_count": enabled_count,
        "provider_mask": "|".join(sorted(provider_mask_parts)) or None,
        "provider_verdicts": provider_verdicts_dict,
        "consensus_status": compute_consensus_status(provider_verdicts_dict),
    }


async def compute_and_store(ip: str) -> IpAggregatedScore | None:
    """Read IpEnrichment rows for ip, compute aggregate, upsert
    IpAggregatedScore. Returns row or None if no enrichments exist.
    """
    async with async_session() as session:
        enrich_stmt = select(IpEnrichment).where(IpEnrichment.ip == ip)
        enrichments = list((await session.execute(enrich_stmt)).scalars())

    if not enrichments:
        return None

    agg_dict = compute_aggregate_from_rows(enrichments)
    now = datetime.now(timezone.utc)

    async with async_session() as session:
        existing = await session.get(IpAggregatedScore, ip)
        if existing:
            for k, v in agg_dict.items():
                setattr(existing, k, v)
            existing.last_calculated_at = now
            row = existing
        else:
            row = IpAggregatedScore(ip=ip, **agg_dict, last_calculated_at=now)
            session.add(row)
        await session.commit()
        await session.refresh(row)

    logger.debug(
        "Aggregate for %s: risk=%.1f, conf=%.2f, cov=%.2f, positive=%d/%d",
        ip, row.aggregate_risk_score, row.confidence_score,
        row.coverage_score, row.positive_provider_count, row.responded_provider_count,
    )
    return row
