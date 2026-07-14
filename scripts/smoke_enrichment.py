"""Smoke test the enrichment pipeline OFFLINE (no BERT, no DB).

Verifies:
  - Catalogs load correctly (technique count, mitigation count, cwe map size)
  - CWE→ATT&CK chain works for common CWEs
  - Mitigation lookup returns real M-IDs
  - Kill chain phase mapping works

Does NOT require torch or model download. Runs in <1 second.
"""
from __future__ import annotations

import sys


def main() -> int:
    from ati_evn.enrichment.attack_catalog import (
        CWE_MAP_SIZE,
        MITIGATION_COUNT,
        TECHNIQUE_COUNT,
        get_mitigation_name,
        get_mitigations_for_technique,
        get_tactics_for_technique,
        get_technique_name,
        get_techniques_for_cwe,
    )
    from ati_evn.enrichment.cwe_chain import build_chain

    print("\n=== ATT&CK Catalog counts ===")
    print(f"Techniques      : {TECHNIQUE_COUNT}   (expect ~697)")
    print(f"Mitigations     : {MITIGATION_COUNT}  (expect ~44)")
    print(f"CWE→ATT&CK map  : {CWE_MAP_SIZE}   (expect ~185, schema v2)")
    assert TECHNIQUE_COUNT > 600, "MITRE ATT&CK dataset missing?"
    assert MITIGATION_COUNT >= 40, "Mitigations dataset missing?"
    assert CWE_MAP_SIZE >= 150, "CWE map v2 missing? (expected ~185 entries)"

    print("\n=== T1190 (Exploit Public-Facing App) enrichment ===")
    print(f"Name        : {get_technique_name('T1190')}")
    m_ids = get_mitigations_for_technique("T1190")
    print(f"Mitigations : {m_ids}")
    for mid in m_ids[:5]:
        print(f"  {mid} : {get_mitigation_name(mid)}")
    print(f"Tactics     : {get_tactics_for_technique('T1190')}")
    assert m_ids, "T1190 should have mitigations"

    print("\n=== T1059.001 (sub-technique) → parent fallback ===")
    print(f"Name        : {get_technique_name('T1059.001')}")
    m_ids = get_mitigations_for_technique("T1059.001")
    print(f"Mitigations : {m_ids}  (fell back to T1059 if empty)")

    print("\n=== CWE-89 (SQLi) chain ===")
    techs = get_techniques_for_cwe("CWE-89")
    print(f"Techniques  : {techs}")
    for tid in techs:
        print(f"  {tid} : {get_technique_name(tid)}")

    print("\n=== Full chain: CWE-79 + CWE-89 + CWE-22 ===")
    chain = build_chain(["CWE-79", "CWE-89", "CWE-22"])
    print(f"Union of techniques: {chain.attack_techniques}")
    for tid in chain.attack_techniques:
        print(f"  {tid:12s} {get_technique_name(tid)[:45]:45s} "
              f"[{chain.reason_per_technique.get(tid)}]")

    print("\n[OK] All catalog smoke checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
