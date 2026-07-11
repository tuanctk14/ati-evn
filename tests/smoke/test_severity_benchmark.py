"""Benchmark harness for the severity scorer.

Validates the weighted risk formula against 8 well-documented real-world
incidents where industry consensus severity is unambiguous. This is NOT
train/test accuracy — the formula is rule-based — this is face-validity
against reality.

Ground truth file (tests/data/risk_scoring_benchmark.json) is shared with
CyberGuard (its origin), which lets us cross-check that our port of the
formula didn't drift from the reference implementation.

Run with:
    pytest tests/smoke/test_severity_benchmark.py -v
Or standalone (no pytest):
    python tests/smoke/test_severity_benchmark.py
"""
from __future__ import annotations

import json
from pathlib import Path

from ati_evn.severity.scorer import calculate_risk_score, RiskInput

BENCHMARK_PATH = Path(__file__).resolve().parents[1] / "data" / "risk_scoring_benchmark.json"


def _load_cases() -> list[dict]:
    with BENCHMARK_PATH.open("r", encoding="utf-8") as f:
        bundle = json.load(f)
    return bundle["cases"]


def _to_input(case: dict) -> RiskInput:
    inp = case["input"]
    return RiskInput(
        cvss_score=inp["cvss_score"],
        exploit_availability=inp["exploit_availability"],
        asset_criticality=inp["asset_criticality"],
        active_exploitation=inp["active_exploitation"],
        targeted_campaign=inp["targeted_campaign"],
        patch_available=inp.get("patch_available", False),
        network_exposure=inp["network_exposure"],
    )


def test_all_benchmark_cases_pass():
    cases = _load_cases()
    failures = []
    for case in cases:
        result = calculate_risk_score(_to_input(case))
        if result.severity_label != case["expected_severity"]:
            failures.append(
                f"{case['id']:20s} expected={case['expected_severity']:8s} "
                f"got={result.severity_label:8s} score={result.risk_score}"
            )
    assert not failures, "Benchmark failures:\n  " + "\n  ".join(failures)


def test_monotonicity_active_exploitation_never_lowers_score():
    """Turning active_exploitation ON must never DECREASE the score."""
    base = RiskInput(
        cvss_score=7.5,
        exploit_availability="POC_ONLY",
        asset_criticality="HIGH",
        active_exploitation=False,
        targeted_campaign=False,
        network_exposure="internal",
    )
    before = calculate_risk_score(base).risk_score
    active = calculate_risk_score(RiskInput(**{**base.__dict__, "active_exploitation": True})).risk_score
    assert active >= before, f"active_exploitation flipped: {before} → {active} (regression)"


def test_monotonicity_exposure_air_gapped_lowest():
    base_kwargs = dict(
        cvss_score=9.0,
        exploit_availability="PUBLIC",
        asset_criticality="CRITICAL",
        active_exploitation=True,
        targeted_campaign=True,
        patch_available=False,
    )
    air = calculate_risk_score(RiskInput(**base_kwargs, network_exposure="air-gapped")).risk_score
    internal = calculate_risk_score(RiskInput(**base_kwargs, network_exposure="internal")).risk_score
    facing = calculate_risk_score(RiskInput(**base_kwargs, network_exposure="internet-facing")).risk_score
    assert air <= internal <= facing, f"exposure ordering broken: {air}/{internal}/{facing}"


if __name__ == "__main__":
    # Standalone runner — no pytest required
    cases = _load_cases()
    print(f"\nBenchmark cases: {len(cases)}\n")
    print(f"{'ID':20s} {'CVE':18s} {'Expected':10s} {'Actual':10s} {'Score':6s} {'Pass':5s}")
    print("-" * 80)
    correct = 0
    for case in cases:
        r = calculate_risk_score(_to_input(case))
        ok = r.severity_label == case["expected_severity"]
        correct += int(ok)
        print(f"{case['id']:20s} {case['cve']:18s} {case['expected_severity']:10s} "
              f"{r.severity_label:10s} {r.risk_score:3d}    {'PASS' if ok else 'FAIL'}")
    print("-" * 80)
    print(f"Total: {correct}/{len(cases)}  ({correct * 100 // len(cases)}% accuracy)")
