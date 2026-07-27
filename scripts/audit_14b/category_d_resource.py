"""Category D -- resource management checks (3 checks). DB-backed
counts use ORM `select(func.count(...))`, not raw text() COUNT(*).
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, select

from ati_evn.config import get_settings
from ati_evn.db.models import Detection, Finding
from ati_evn.db.session import async_session


async def check_d1() -> dict:
    """D.1 -- reports/ folder size + retention policy."""
    settings = get_settings()
    reports_dir = Path(settings.reports_output_dir)
    if not reports_dir.exists():
        return {"check_id": "D.1", "severity": "PASS"}

    total_bytes = 0
    file_count = 0
    for f in reports_dir.rglob("*"):
        if f.is_file():
            total_bytes += f.stat().st_size
            file_count += 1

    total_mb = total_bytes / (1024 * 1024)
    if total_mb > 100:
        return {
            "check_id": "D.1",
            "title": f"reports/ folder = {total_mb:.1f} MB, {file_count} files",
            "severity": "MEDIUM",
            "description": "No retention policy — grows unbounded, manual cleanup needed.",
            "evidence": f"size_mb={total_mb:.1f}, files={file_count}",
            "fix_action": (
                "Add retention: delete report files older than 90d and "
                "clear the corresponding html_path/pdf_path on the Report row."
            ),
        }
    return {
        "check_id": "D.1", "severity": "INFO",
        "title": f"reports/ folder = {total_mb:.1f} MB, {file_count} files",
        "description": "Within acceptable range for now.",
        "evidence": None, "fix_action": None,
    }


async def check_d2() -> dict:
    """D.2 -- Log files exist and grow unbounded (no rotation configured)."""
    log_paths = [Path("logs"), Path("ati_evn.log"), Path("bot.log")]
    found = [p for p in log_paths if p.exists()]
    big = []
    for p in found:
        if p.is_file():
            size_mb = p.stat().st_size / (1024 * 1024)
            if size_mb > 50:
                big.append((str(p), size_mb))
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file():
                    size_mb = f.stat().st_size / (1024 * 1024)
                    if size_mb > 50:
                        big.append((str(f), size_mb))

    if big:
        return {
            "check_id": "D.2",
            "title": f"{len(big)} large log file(s) — no rotation",
            "severity": "MEDIUM",
            "description": "Log rotation not configured.",
            "evidence": "\n".join(f"  {p}: {sz:.1f} MB" for p, sz in big),
            "fix_action": "Add logrotate, or a Python RotatingFileHandler in logging config.",
        }
    if not found:
        return {
            "check_id": "D.2", "severity": "INFO",
            "title": "No dedicated log files found on disk",
            "description": "Logging may go to stdout/journald only — check deployment setup.",
            "evidence": None, "fix_action": None,
        }
    return {"check_id": "D.2", "severity": "PASS"}


async def check_d3() -> dict:
    """D.3 -- DB row growth without an archive policy (informational threshold)."""
    async with async_session() as session:
        det_count = (await session.execute(select(func.count(Detection.id)))).scalar() or 0
        find_count = (await session.execute(select(func.count(Finding.id)))).scalar() or 0

    if det_count > 100_000 or find_count > 10_000:
        return {
            "check_id": "D.3",
            "title": f"Large table sizes (detections={det_count}, findings={find_count})",
            "severity": "LOW",
            "description": "Tables grow unbounded — future performance risk, no archive policy.",
            "evidence": f"detections={det_count}, findings={find_count}",
            "fix_action": (
                "Consider archiving detections older than 6 months to a "
                "detections_archive table once volume becomes a query-latency issue."
            ),
        }
    return {
        "check_id": "D.3", "severity": "INFO",
        "title": f"Table sizes: detections={det_count}, findings={find_count}",
        "description": "Below the archive-policy threshold for now.",
        "evidence": None, "fix_action": None,
    }


async def run_all() -> list[dict]:
    results = []
    for check in [check_d1, check_d2, check_d3]:
        r = await check()
        if r["severity"] not in ("PASS",):
            results.append(r)
    return results
