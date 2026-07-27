"""Category B -- code duplication / static-analysis checks (5 checks).

Pure static analysis on src/ati_evn -- no DB access needed.
"""
from __future__ import annotations

import ast
import subprocess
from collections import Counter
from pathlib import Path

SRC = Path("src/ati_evn")

_SKIP_FN_NAMES = {
    "__init__", "setup", "teardown", "main", "run", "fetch",
    "handler", "wrapper", "decorator", "cmd", "router",
}


async def check_b1() -> dict:
    """B.1 -- Files with duplicate top-level import statements."""
    problems = []
    for py_file in SRC.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue

        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.names:
                    imports.append(f"{node.module}.{node.names[0].name}")

        counts = Counter(imports)
        dups = {k: v for k, v in counts.items() if v > 1}
        if dups:
            problems.append((str(py_file), dups))

    if problems:
        return {
            "check_id": "B.1",
            "title": f"{len(problems)} file(s) with duplicate import statements",
            "severity": "LOW",
            "description": "Duplicate import statements clutter files.",
            "evidence": "\n".join(
                f"  {f}: {dict(list(d.items())[:3])}" for f, d in problems[:10]
            ),
            "fix_action": "Manual cleanup or `ruff check --select F811 --fix`.",
        }
    return {"check_id": "B.1", "severity": "PASS"}


async def check_b2() -> dict:
    """B.2 -- Same function name defined in many files (potential duplication)."""
    fn_files: dict[str, list[str]] = {}
    for py_file in SRC.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    fn_files.setdefault(node.name, []).append(str(py_file))

    conflicts = {
        name: paths for name, paths in fn_files.items()
        if len(paths) > 1 and name not in _SKIP_FN_NAMES
    }

    if len(conflicts) > 5:
        return {
            "check_id": "B.2",
            "title": f"{len(conflicts)} function names appear in multiple files",
            "severity": "LOW",
            "description": (
                "Same non-private function name defined in 2+ files. Many "
                "are intentional (per-adapter fetch, per-command handler) "
                "but worth a manual scan for accidental duplication."
            ),
            "evidence": "\n".join(
                f"  {name}: {len(paths)} files" for name, paths in list(conflicts.items())[:15]
            ),
            "fix_action": "Review — move truly shared logic to a common module.",
        }
    return {"check_id": "B.2", "severity": "PASS"}


async def check_b3() -> dict:
    """B.3 -- renderer.py has two near-identical output-path builders."""
    renderer = SRC / "reports" / "renderer.py"
    if not renderer.exists():
        return {"check_id": "B.3", "severity": "PASS"}

    content = renderer.read_text(encoding="utf-8")
    if "_output_paths" in content and "_customer_output_paths" in content:
        return {
            "check_id": "B.3",
            "title": "renderer.py has 2 similar path builders",
            "severity": "LOW",
            "description": (
                "`_output_paths` and `_customer_output_paths` share nearly "
                "identical logic (day-folder + timestamped filename). "
                "Could be unified with a prefix parameter."
            ),
            "evidence": "Both functions found in src/ati_evn/reports/renderer.py",
            "fix_action": "Unify to _output_paths(prefix='global'|f'customer_{code}').",
        }
    return {"check_id": "B.3", "severity": "PASS"}


async def check_b4() -> dict:
    """B.4 -- Unused imports via pyflakes, if installed."""
    try:
        result = subprocess.run(
            ["python", "-m", "pyflakes", str(SRC)],
            capture_output=True, text=True, timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {
            "check_id": "B.4", "severity": "INFO",
            "title": "pyflakes not available",
            "description": "Install pyflakes for unused-import detection.",
            "evidence": None, "fix_action": "pip install pyflakes",
        }
    except Exception as e:
        return {
            "check_id": "B.4", "severity": "INFO",
            "title": "pyflakes check failed to run",
            "description": str(e)[:200],
            "evidence": None, "fix_action": None,
        }

    output = result.stdout + result.stderr
    unused = [l for l in output.split("\n") if "imported but unused" in l]

    if len(unused) > 20:
        return {
            "check_id": "B.4",
            "title": f"{len(unused)} unused imports across codebase",
            "severity": "LOW",
            "description": "Dead imports increase cognitive load, no runtime impact.",
            "evidence": "\n".join(unused[:15]),
            "fix_action": "Run `ruff check --select F401 --fix` or manual cleanup.",
        }
    if unused:
        return {
            "check_id": "B.4", "severity": "INFO",
            "title": f"{len(unused)} unused imports (minor)",
            "description": None, "evidence": "\n".join(unused[:10]),
            "fix_action": "Cleanup optional.",
        }
    return {"check_id": "B.4", "severity": "PASS"}


async def check_b5() -> dict:
    """B.5 -- Schema naming inconsistency (informational only).

    Finding uses first_seen/last_seen; Exposure/ExposedDocument/
    BrandAbuseSighting use first_seen_local/last_seen_local (they also
    track first_seen_censys/last_seen_censys separately). This is a
    known, intentional distinction (external-source timestamp vs.
    locally-observed timestamp), documented here rather than "fixed"
    since renaming would be a breaking schema change.
    """
    from ati_evn.db import models

    insight = []
    for entity in ["Finding", "Exposure", "ExposedDocument", "BrandAbuseSighting", "Detection"]:
        cls = getattr(models, entity, None)
        if not cls:
            continue
        time_fields = [
            col.name for col in cls.__table__.columns
            if col.name.startswith("first_") or col.name.startswith("last_")
        ]
        insight.append(f"  {entity}: {time_fields}")

    return {
        "check_id": "B.5",
        "title": "Schema naming inconsistency (informational)",
        "severity": "INFO",
        "description": (
            "Finding uses first_seen/last_seen; Exposure/ExposedDocument/"
            "BrandAbuseSighting use first_seen_local/last_seen_local "
            "(distinct from first_seen_censys/last_seen_censys on Exposure)."
        ),
        "evidence": "\n".join(insight),
        "fix_action": (
            "Deferred — rename would be a breaking change. Document in "
            "thesis Limitations chapter."
        ),
    }


async def run_all() -> list[dict]:
    results = []
    for check in [check_b1, check_b2, check_b3, check_b4, check_b5]:
        r = await check()
        if r["severity"] != "PASS":
            results.append(r)
    return results
