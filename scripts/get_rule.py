"""CLI: get Sigma rule for a CVE.

Usage:
  python scripts/get_rule.py CVE-2022-42475
  python scripts/get_rule.py CVE-2022-42475 --regen
  python scripts/get_rule.py CVE-2022-42475 --json    # machine-readable
"""
from __future__ import annotations

import argparse
import asyncio
import json
import textwrap

from ati_evn.rules.orchestrator import get_rule_for_cve


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cve_id")
    ap.add_argument("--regen", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = await get_rule_for_cve(args.cve_id, force_regen=args.regen)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"\n=== Rule for {result['cve_id']} ({result['source']}, "
          f"match_confidence={result.get('match_confidence', 0):.2f}) ===\n")

    if result["source"] == "community_behavioral":
        print("⚠ Behavioral match (rule not tagged with this CVE, but targets")
        print("  the same ATT&CK techniques). Analyst review recommended before")
        print("  deploying — may need field/parameter adjustment for this CVE.\n")

    p = result["primary_rule"]
    print(f"Title:  {p['title']}")
    if p.get("source_ref"):
        print(f"Source: {p['source_ref']}")
    if p.get("reasoning"):
        print(f"Score:  {p.get('score')} — {p['reasoning']}")

    print("\n--- Sigma YAML ---")
    print(p["yaml"])

    if p.get("aql"):
        print("\n--- QRadar AQL ---")
        print(p["aql"])
    else:
        print("\n(QRadar AQL not available — pysigma backend disabled or "
              "conversion failed. Copy the YAML into `sigma-cli convert -t "
              "qradar` locally.)")

    if result.get("ai_metadata"):
        m = result["ai_metadata"]
        print("\n--- AI Metadata ---")
        print(f"Model:    {m['model']}")
        print(f"Confidence: {m['confidence']}")
        print("\nAnalyst notes:")
        print(textwrap.fill(m["analyst_notes"], width=100,
                             initial_indent="  ", subsequent_indent="  "))

    if result.get("alternates"):
        print(f"\n--- {len(result['alternates'])} alternate community rule(s) ---")
        for i, a in enumerate(result["alternates"], 1):
            print(f"  [{i}] {a['title'][:80]}")
            print(f"      score={a['score']} — {a['reasoning']}")
            print(f"      {a['source_ref']}")


if __name__ == "__main__":
    asyncio.run(main())
