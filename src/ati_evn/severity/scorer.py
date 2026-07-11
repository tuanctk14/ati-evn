"""Severity / risk scoring engine.

Ported and adapted from CyberGuard's `risk_engine_py.py` — a weighted
formula benchmarked against 8 real-world incidents (Log4Shell, EternalBlue,
Heartbleed, Struts/Equifax, PrintNightmare, ProxyShell, MOVEit, Fortinet
SSL-VPN). See `tests/data/risk_scoring_benchmark.json` and
`tests/smoke/test_severity_benchmark.py` for the evaluation harness.

Adaptations for ATI-EVN
-----------------------
- Exposure model extended for EVN's OT/ICS reality: `NetworkSegment`
  from our schema maps to CyberGuard's 3-way exposure axis:
    dmz / internal_it       -> "internal"       (1.0×)
    internet_facing (flag)  -> "internet-facing"(1.15×)
    ot_process / ot_control -> "air-gapped"     (0.7×)  (assumes proper
      network segmentation; SCADA reachable from IT is a separate finding.)

- Function `finding_risk_from_context()` takes ATI-EVN Finding +
  CustomerAsset + CveProductMap so callers don't have to build the input
  dict by hand.

- Text explanation is emitted in Vietnamese for Telegram alerts, but with
  English technical terms kept (per project convention).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional


# ═══════════════════════════════════════════════════════════════════════════
# Constants — must match CyberGuard for benchmark parity
# ═══════════════════════════════════════════════════════════════════════════

RISK_WEIGHTS = {
    "cvss": 0.30,
    "exploitability": 0.25,
    "asset_criticality": 0.25,
    "threat_intel": 0.20,
}

SEVERITY_THRESHOLDS = {
    "CRITICAL": 70,
    "HIGH": 50,
    "MEDIUM": 30,
    "LOW": 0,
}

# SLA hours per severity — how long analyst has to respond
RESPONSE_SLA_HOURS = {
    "CRITICAL": 4,
    "HIGH": 24,
    "MEDIUM": 336,   # 2 weeks
    "LOW": 2160,     # 90 days
}

EXPLOIT_SCORE_MAP = {
    "PUBLIC": 10,       # weaponized: Metasploit/ExploitDB module
    "POC_ONLY": 6,      # PoC published, not weaponized
    "THEORETICAL": 2,   # academic, no public code
    "NONE": 0,
}

ASSET_CRITICALITY_MAP = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 5,
    "LOW": 2,
}

EXPOSURE_MULTIPLIERS = {
    "internet-facing": 1.15,
    "internal": 1.0,
    "air-gapped": 0.7,
}


# ═══════════════════════════════════════════════════════════════════════════
# Types
# ═══════════════════════════════════════════════════════════════════════════

SeverityLabel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ExploitAvailability = Literal["PUBLIC", "POC_ONLY", "THEORETICAL", "NONE"]
AssetCriticality = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
NetworkExposure = Literal["internet-facing", "internal", "air-gapped"]


@dataclass
class RiskInput:
    cvss_score: float
    exploit_availability: ExploitAvailability
    asset_criticality: AssetCriticality
    active_exploitation: bool = False    # KEV listed or confirmed in wild
    targeted_campaign: bool = False      # seen in TI feeds targeting this sector
    patch_available: bool = False
    network_exposure: NetworkExposure = "internal"


@dataclass
class RiskScore:
    risk_score: int              # 0-100
    severity_label: SeverityLabel
    sla_hours: int
    cvss_component: float
    exploit_component: float
    asset_component: float
    threat_intel_component: float
    exposure_multiplier: float
    breakdown: str               # human-readable explanation


# ═══════════════════════════════════════════════════════════════════════════
# Core scorer
# ═══════════════════════════════════════════════════════════════════════════

def classify_severity(score: int) -> SeverityLabel:
    if score >= SEVERITY_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(inp: RiskInput) -> RiskScore:
    """Compute the weighted risk score for a single CVE-asset pair.

    Formula:
        Base    = 0.30·S_v + 0.25·E_x + 0.25·A_c + 0.20·T_i
        Final   = min(100, round(Base × 10 × exposure_multiplier))
    """
    # Clamp CVSS to 0-10
    sv = max(0.0, min(10.0, inp.cvss_score))

    # Exploitability
    ex = EXPLOIT_SCORE_MAP.get(inp.exploit_availability, 0)

    # Asset criticality
    ac = ASSET_CRITICALITY_MAP.get(inp.asset_criticality, 5)

    # Threat intel context: active exploitation (10) > targeted campaign (6) > generic (2)
    ti = 2
    if inp.targeted_campaign:
        ti = 6
    if inp.active_exploitation:
        ti = 10

    exposure_mult = EXPOSURE_MULTIPLIERS.get(inp.network_exposure, 1.0)

    base = (
        RISK_WEIGHTS["cvss"] * sv
        + RISK_WEIGHTS["exploitability"] * ex
        + RISK_WEIGHTS["asset_criticality"] * ac
        + RISK_WEIGHTS["threat_intel"] * ti
    )
    final_score = min(100, round(base * 10 * exposure_mult))
    label = classify_severity(final_score)

    return RiskScore(
        risk_score=final_score,
        severity_label=label,
        sla_hours=RESPONSE_SLA_HOURS[label],
        cvss_component=sv,
        exploit_component=ex,
        asset_component=ac,
        threat_intel_component=ti,
        exposure_multiplier=exposure_mult,
        breakdown=_build_explanation(inp, sv, ex, ac, ti, final_score, exposure_mult),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Explainable AI — human-readable breakdown (Vietnamese for Telegram)
# ═══════════════════════════════════════════════════════════════════════════

def _build_explanation(inp, sv, ex, ac, ti, final_score, exposure_mult) -> str:
    label = classify_severity(final_score)
    lines = [
        f"Risk Score: {final_score}/100 ({label})",
        "",
        "Thành phần điểm:",
        f"  • CVSS Base:         {sv:.1f}/10  × {RISK_WEIGHTS['cvss']}  = {sv * RISK_WEIGHTS['cvss']:.2f}",
        f"  • Exploitability:    {ex:.1f}/10  × {RISK_WEIGHTS['exploitability']}  = {ex * RISK_WEIGHTS['exploitability']:.2f}  ({inp.exploit_availability})",
        f"  • Asset Criticality: {ac:.1f}/10  × {RISK_WEIGHTS['asset_criticality']}  = {ac * RISK_WEIGHTS['asset_criticality']:.2f}  ({inp.asset_criticality})",
        f"  • Threat Intel:      {ti:.1f}/10  × {RISK_WEIGHTS['threat_intel']}  = {ti * RISK_WEIGHTS['threat_intel']:.2f}  "
        f"({'Active exploitation' if inp.active_exploitation else 'Targeted campaign' if inp.targeted_campaign else 'Generic threat'})",
        f"  • Network Exposure:  {inp.network_exposure} (×{exposure_mult})",
        "",
    ]

    if final_score >= 70:
        lines.append("  → CRITICAL: cần response ngay trong 4h. Escalate & bật playbook.")
    elif final_score >= 50:
        lines.append("  → HIGH: remediate trong 24h. Assign owner.")
    elif final_score >= 30:
        lines.append("  → MEDIUM: xử lý trong sprint hiện tại (2 tuần).")
    else:
        lines.append("  → LOW: theo dõi, patch trong maintenance window.")

    if not inp.patch_available:
        lines.append("  ⚠ Chưa có patch — cần compensating control ngay.")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# ATI-EVN integration wrapper
# ═══════════════════════════════════════════════════════════════════════════

def _segment_to_exposure(segment: Optional[str], is_internet_facing: bool) -> NetworkExposure:
    """Map ATI-EVN NetworkSegment → CyberGuard exposure axis."""
    if is_internet_facing:
        return "internet-facing"
    if segment in ("ot_process", "ot_control", "isolated"):
        return "air-gapped"
    return "internal"


def _criticality_str(criticality: Optional[str]) -> AssetCriticality:
    if not criticality:
        return "MEDIUM"
    up = criticality.upper()
    return up if up in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"


def score_from_context(
    *,
    cvss_score: float,
    actively_exploited: bool,
    asset_criticality: Optional[str],
    network_segment: Optional[str] = None,
    is_internet_facing: bool = False,
    has_public_exploit: bool = False,
    has_poc: bool = False,
    targeted_campaign: bool = False,
    patch_available: bool = False,
) -> RiskScore:
    """Convenience wrapper — takes ATI-EVN's Finding+CustomerAsset+CveProductMap
    columns directly rather than requiring the caller to build a RiskInput.
    """
    if has_public_exploit:
        exploit = "PUBLIC"
    elif has_poc:
        exploit = "POC_ONLY"
    elif cvss_score > 0:
        exploit = "THEORETICAL"
    else:
        exploit = "NONE"

    return calculate_risk_score(RiskInput(
        cvss_score=cvss_score,
        exploit_availability=exploit,
        asset_criticality=_criticality_str(asset_criticality),
        active_exploitation=actively_exploited,
        targeted_campaign=targeted_campaign,
        patch_available=patch_available,
        network_exposure=_segment_to_exposure(network_segment, is_internet_facing),
    ))
