"""Severity computation for Findings — thin dispatch layer over two models.

Two deliberately different approaches:

1. CVE Findings use `severity.scorer.score_from_context()` — a weighted,
   benchmarked formula (CVSS + exploitability + asset criticality + network
   exposure) that's been validated against 8 real incidents. This is
   appropriate because a CVE gives us enough structured signal (CVSS score,
   KEV status) to justify a real formula.

2. IOC Findings (malware hash, C&C IP, malicious URL, etc.) do NOT get that
   treatment. We only have a feed's severity_hint (e.g. ThreatFox confidence
   bucket) plus asset context — nowhere near the structured input a CVSS-style
   formula needs. Inventing a weighted formula here would look precise but
   be arbitrary. Instead we take the feed's severity as the base and apply
   two honest, explainable bumps (internet-facing, critical asset), capped
   at CRITICAL. This is easier for an analyst to audit than a fake formula.
"""
from __future__ import annotations

from ati_evn.db.models import Detection, Severity
from ati_evn.match.strategies import MatchResult
from ati_evn.severity.scorer import score_from_context

_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

_LABEL_TO_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _bump(severity: Severity, levels: int) -> Severity:
    idx = _ORDER.index(severity)
    return _ORDER[min(idx + levels, len(_ORDER) - 1)]


def compute_finding_severity(det: Detection, match: MatchResult) -> tuple[Severity, str]:
    """Return (severity, breakdown_text)."""
    if det.ioc_type == "cve_id" and match.cve_context:
        ctx = match.cve_context
        cvss_score = ctx.get("cvss_score")
        if cvss_score is None:
            cvss_score = 5.0
        actively_exploited = bool(ctx.get("actively_exploited", False))

        risk = score_from_context(
            cvss_score=cvss_score,
            actively_exploited=actively_exploited,
            asset_criticality=match.asset.criticality,
            network_segment=match.asset.network_segment.value if match.asset.network_segment else None,
            is_internet_facing=bool(match.asset.is_internet_facing),
            has_public_exploit=actively_exploited,
            patch_available=False,
        )
        severity = _LABEL_TO_SEVERITY.get(risk.severity_label, Severity.MEDIUM)
        return severity, risk.breakdown

    # IOC finding: base severity from the feed, bumped by asset context.
    base_severity = det.severity or Severity.MEDIUM
    bumps = 0
    bump_reasons = []

    if match.asset.is_internet_facing:
        bumps += 1
        bump_reasons.append("internet_facing=True (+1)")
    if (match.asset.criticality or "").lower() == "critical":
        bumps += 1
        bump_reasons.append("asset_criticality=critical (+1)")

    final_severity = _bump(base_severity, bumps)

    breakdown = (
        f"IOC severity: {base_severity.value} (from feed {det.source})\n"
        f"Asset context: criticality={match.asset.criticality}, "
        f"internet_facing={match.asset.is_internet_facing}\n"
        f"Bumps applied: {', '.join(bump_reasons) if bump_reasons else 'none'}\n"
        f"Final: {final_severity.value}"
    )
    return final_severity, breakdown
