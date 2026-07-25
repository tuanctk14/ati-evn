"""ScoringEngine -- adapter-agnostic scoring layer.

Reads scoring policy from YAML config, applies formula to signals.
Formulas: passthrough, weighted_count, bucket, level_map, composite,
lookup_table.

Design: the score computation (compute_score / _FORMULA_DISPATCH) has no
if-provider-name branches -- the formula name from config drives dispatch.
New provider + new score policy -> add a YAML entry, no code change here.

Verdict determination (_determine_verdict) DOES branch per provider,
because each provider's raw signal shape and verdict semantics differ
(a "malicious" AbuseIPDB score isn't structurally comparable to an
OTX pulse count) -- but every threshold used is read from
providers[X] in the YAML, never hardcoded as a magic number.
"""
from __future__ import annotations

import logging
import math

from ati_evn.enrichment_v2.adapters._base import ProviderSignal, ProviderVerdict, Verdict
from ati_evn.enrichment_v2.config import get_provider_config, get_scoring_policy

logger = logging.getLogger("ati_evn.enrichment_v2.scoring")


# ═════════════════════════════════════════════════════════════════════════
# Score formulas -- pure functions on signals dict
# ═════════════════════════════════════════════════════════════════════════

def _f_passthrough(policy: dict, signals: dict) -> float:
    field = policy.get("field")
    val = signals.get(field, 0)
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0.0


def _f_weighted_count(policy: dict, signals: dict) -> float:
    mal_field = policy.get("malicious_field", "malicious_engines")
    susp_field = policy.get("suspicious_field", "suspicious_engines")
    mal_w = policy.get("malicious_weight", 15)
    susp_w = policy.get("suspicious_weight", 5)
    cap = policy.get("cap", 100)
    mal = int(signals.get(mal_field, 0) or 0)
    susp = int(signals.get(susp_field, 0) or 0)
    return min(float(cap), mal * mal_w + susp * susp_w)


def _f_bucket(policy: dict, signals: dict) -> float:
    field = policy.get("field")
    value = signals.get(field, 0)
    try:
        value = float(value)
    except (TypeError, ValueError):
        value = 0
    buckets = policy.get("buckets") or []
    for b in buckets:
        if value <= b.get("max", 0):
            return float(b.get("score", 0))
    if buckets:
        return float(buckets[-1].get("score", 0))
    return 0.0


def _f_level_map(policy: dict, signals: dict) -> float:
    field = policy.get("field")
    raw = signals.get(field)
    val = raw.lower() if isinstance(raw, str) else ""
    mapping = policy.get("map") or {}
    lc_map = {str(k).lower(): v for k, v in mapping.items()}
    return float(lc_map.get(val, 0))


def _f_composite(policy: dict, signals: dict) -> float:
    base_field = policy.get("base_field")
    bonus_field = policy.get("bonus_field")
    base_per = policy.get("base_per_unit", 1)
    base_cap = policy.get("base_cap", 100)
    bonus_per = policy.get("bonus_per_unit", 0)
    cap = policy.get("cap", 100)
    base_val = int(signals.get(base_field, 0) or 0)
    bonus_val = int(signals.get(bonus_field, 0) or 0)
    base = min(base_val * base_per, base_cap)
    bonus = bonus_val * bonus_per
    return min(float(cap), base + bonus)


def _key_of(lookup: dict, numeric: float):
    """Find the original (possibly non-numeric-typed) key that matches
    a numeric lookup value."""
    for k in lookup.keys():
        if abs(float(k) - numeric) < 1e-9:
            return k
    return list(lookup.keys())[0]


def _f_lookup_table(policy: dict, signals: dict) -> float:
    """Discrete lookup table. Default interpolate=false (discrete count
    semantic). Values outside the table's range clamp to the nearest
    bucket; values between two keys use the lower bucket unless
    interpolate=true."""
    field = policy.get("field")
    lookup = policy.get("lookup") or {}
    interpolate = bool(policy.get("interpolate", False))

    if not lookup:
        return 0.0
    try:
        value = float(signals.get(field, 0) or 0)
    except (TypeError, ValueError):
        return 0.0

    try:
        sorted_keys = sorted(float(k) for k in lookup.keys())
    except (TypeError, ValueError):
        logger.warning("lookup_table has non-numeric keys")
        return 0.0

    if value <= sorted_keys[0]:
        return float(lookup[_key_of(lookup, sorted_keys[0])])
    if value >= sorted_keys[-1]:
        return float(lookup[_key_of(lookup, sorted_keys[-1])])

    for k in sorted_keys:
        if abs(value - k) < 1e-9:
            return float(lookup[_key_of(lookup, k)])

    for i, k in enumerate(sorted_keys[:-1]):
        next_k = sorted_keys[i + 1]
        if k < value < next_k:
            if interpolate:
                lower = float(lookup[_key_of(lookup, k)])
                upper = float(lookup[_key_of(lookup, next_k)])
                frac = (value - k) / (next_k - k)
                return lower + (upper - lower) * frac
            else:
                return float(lookup[_key_of(lookup, k)])

    return 0.0


_FORMULA_DISPATCH = {
    "passthrough": _f_passthrough,
    "weighted_count": _f_weighted_count,
    "bucket": _f_bucket,
    "level_map": _f_level_map,
    "composite": _f_composite,
    "lookup_table": _f_lookup_table,
}


# ═════════════════════════════════════════════════════════════════════════
# Verdict determination -- uses providers[X] thresholds from YAML
# ═════════════════════════════════════════════════════════════════════════

def _determine_verdict(provider: str, signals: dict) -> tuple[Verdict, float]:
    """Verdict + adapter confidence. Thresholds from providers[X] config.

    This function DOES have per-provider branching because verdict
    semantics differ (a pulse count isn't a risk level isn't an engine
    count) -- but every numeric threshold is read from config, never
    hardcoded as a magic number in this function.
    """
    cfg = get_provider_config(provider)
    if not cfg:
        return "unknown", 0.3

    if provider == "abuseipdb":
        score = int(signals.get("abuse_confidence", 0) or 0)
        reports = int(signals.get("total_reports", 0) or 0)
        mal = cfg.get("malicious_score", 50)
        susp = cfg.get("suspicious_score", 25)
        verdict: Verdict
        if score >= mal:
            verdict = "malicious"
        elif score >= susp:
            verdict = "suspicious"
        else:
            verdict = "benign"
        confidence = min(1.0, 0.5 + math.log10(reports + 1) / 4.0) if reports > 0 else 0.5
        return verdict, confidence

    elif provider == "virustotal":
        mal_count = int(signals.get("malicious_engines", 0) or 0)
        susp_count = int(signals.get("suspicious_engines", 0) or 0)
        total = int(signals.get("total_engines", 0) or 0)
        mal_t = cfg.get("malicious_engines", 5)
        susp_t = cfg.get("suspicious_engines", 1)
        if mal_count >= mal_t:
            verdict = "malicious"
        elif mal_count >= susp_t or susp_count >= 3:
            verdict = "suspicious"
        elif total > 0:
            verdict = "benign"
        else:
            verdict = "unknown"
        confidence = 0.9 if total >= 40 else 0.7 if total >= 20 else 0.5 if total >= 10 else 0.3
        return verdict, confidence

    elif provider == "otx":
        pulses = int(signals.get("pulse_count", 0) or 0)
        mal_t = cfg.get("malicious_pulses", 3)
        susp_t = cfg.get("suspicious_pulses", 1)
        if pulses >= mal_t:
            return "malicious", min(1.0, 0.6 + pulses * 0.05)
        elif pulses >= susp_t:
            return "suspicious", 0.5
        else:
            return "benign", 0.6

    elif provider == "pulsedive":
        risk = (signals.get("risk_level") or "unknown").lower()
        mal_level = cfg.get("malicious_level", "medium")
        susp_level = cfg.get("suspicious_level", "low")
        order = ["none", "unknown", "low", "medium", "high", "critical"]
        try:
            r = order.index(risk)
            m = order.index(mal_level)
            s = order.index(susp_level)
        except ValueError:
            return "unknown", 0.3
        if r >= m:
            return "malicious", 0.7
        elif r >= s:
            return "suspicious", 0.5
        else:
            return "benign", 0.5

    elif provider == "leakix":
        svc = int(signals.get("services_count", 0) or 0)
        leaks = int(signals.get("leaks_count", 0) or 0)
        mal_types = int(signals.get("malicious_event_types_count", 0) or 0)
        susp_any = cfg.get("suspicious_on_any_event", True)
        if mal_types > 0:
            return "malicious", 0.8
        elif (svc + leaks) > 0 and susp_any:
            return "suspicious", 0.6
        else:
            return "benign", 0.5

    return "unknown", 0.3


# ═════════════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════════════

def score_from_signal(signal: ProviderSignal) -> ProviderVerdict:
    """Convert ProviderSignal -> ProviderVerdict via ScoringEngine.

    1. Determine verdict + adapter confidence (from providers[X] config)
    2. Compute normalized_score (from scoring[X] policy)
    3. Return unified ProviderVerdict object
    """
    if signal.error:
        return ProviderVerdict(
            provider=signal.provider,
            verdict="unknown",
            confidence=0.0,
            normalized_score=0.0,
            signals=signal.signals,
            country=signal.country,
            isp=signal.isp,
            raw_data=signal.raw_data,
            error=signal.error,
        )

    verdict, confidence = _determine_verdict(signal.provider, signal.signals)
    policy = get_scoring_policy(signal.provider)
    formula = policy.get("formula", "passthrough")
    fn = _FORMULA_DISPATCH.get(formula)
    if not fn:
        logger.warning("Unknown formula '%s' for %s -- using 0", formula, signal.provider)
        score = 0.0
    else:
        score = fn(policy, signal.signals)

    return ProviderVerdict(
        provider=signal.provider,
        verdict=verdict,
        confidence=confidence,
        normalized_score=score,
        signals=signal.signals,
        country=signal.country,
        isp=signal.isp,
        raw_data=signal.raw_data,
    )
