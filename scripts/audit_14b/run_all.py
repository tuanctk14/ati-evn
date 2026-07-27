"""Orchestrate all audit checks + produce a markdown report.

Usage:
  python -m scripts.audit_14b.run_all                 # dry-run, report only
  python -m scripts.audit_14b.run_all --fix-critical   # also execute F.1/F.2 backfills
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

from scripts.audit_14b import (
    category_a_data,
    category_b_dup,
    category_c_config,
    category_d_resource,
    category_e_error,
    category_f_backfill,
)

OUTPUT_DIR = Path("scripts")
REPORT_PATH = OUTPUT_DIR / "audit_14b_report.md"
BACKLOG_PATH = OUTPUT_DIR / "audit_14b_backlog.md"


def _write_report(results: list[tuple[str, list[dict]]]) -> tuple[list[dict], list[dict]]:
    all_issues = []
    for cat_name, cat_issues in results:
        for i in cat_issues:
            i["category"] = cat_name
            all_issues.append(i)

    critical = [i for i in all_issues if i["severity"] == "CRITICAL"]
    high = [i for i in all_issues if i["severity"] == "HIGH"]
    medium = [i for i in all_issues if i["severity"] == "MEDIUM"]
    low = [i for i in all_issues if i["severity"] == "LOW"]
    info = [i for i in all_issues if i["severity"] == "INFO"]

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("# ATI-EVN Slice 14B Audit Report\n\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write("## Summary\n\n")
        f.write(f"- CRITICAL: {len(critical)} issue(s)\n")
        f.write(f"- HIGH: {len(high)} issue(s)\n")
        f.write(f"- MEDIUM: {len(medium)} issue(s) — deferred to backlog\n")
        f.write(f"- LOW: {len(low)} issue(s) — deferred to backlog\n")
        f.write(f"- INFO: {len(info)} note(s)\n\n")

        for cat_name, cat_issues in results:
            f.write(f"## {cat_name}\n\n")
            if not cat_issues:
                f.write("_No issues found — category clean._\n\n")
                continue
            for i in cat_issues:
                f.write(f"### [{i['severity']}] {i['check_id']}: {i['title']}\n")
                if i.get("description"):
                    f.write(f"{i['description']}\n\n")
                if i.get("evidence"):
                    f.write(f"**Evidence:**\n```\n{i['evidence']}\n```\n\n")
                if i.get("fix_action"):
                    f.write(f"**Recommended fix:** {i['fix_action']}\n\n")

    deferred = medium + low
    with open(BACKLOG_PATH, "w", encoding="utf-8") as f:
        f.write("# ATI-EVN Audit Backlog (14B deferred issues)\n\n")
        f.write("Deferred to future work / thesis Limitations chapter.\n\n")
        for i in deferred:
            f.write(f"- [{i['severity']}] **{i['check_id']}**: {i['title']}\n")
            if i.get("description"):
                f.write(f"  {i['description'][:200]}\n")
            f.write("\n")

    return critical, high


async def main() -> int:
    fix_mode = "--fix-critical" in sys.argv

    results: list[tuple[str, list[dict]]] = []
    results.append(("A. Data consistency", await category_a_data.run_all()))
    results.append(("B. Code duplication", await category_b_dup.run_all()))
    results.append(("C. Configuration", await category_c_config.run_all()))
    results.append(("D. Resource management", await category_d_resource.run_all()))
    results.append(("E. Error handling", await category_e_error.run_all()))

    f1 = await category_f_backfill.check_f1(execute=fix_mode)
    f2 = await category_f_backfill.check_f2(execute=fix_mode)
    f_results = [r for r in (f1, f2) if r["severity"] != "PASS"]
    results.append(("F. Backfill", f_results))

    critical, high = _write_report(results)

    print(f"Report: {REPORT_PATH}")
    print(f"Backlog: {BACKLOG_PATH}")
    print(f"Critical: {len(critical)}, High: {len(high)}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
