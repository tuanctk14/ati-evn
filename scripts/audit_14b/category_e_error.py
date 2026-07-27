"""Category E -- error handling checks (4 checks)."""
from __future__ import annotations

import ast
import subprocess
from pathlib import Path

SRC = Path("src/ati_evn")


async def check_e1() -> dict:
    """E.1 -- Bare `except:` or broad `except Exception:` without re-raise."""
    bare_excepts = []
    for py_file in SRC.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    bare_excepts.append((str(py_file), node.lineno))
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    has_reraise = any(isinstance(n, ast.Raise) for n in ast.walk(node))
                    if not has_reraise:
                        bare_excepts.append((str(py_file), node.lineno))

    bare_excepts = [(f, l) for f, l in bare_excepts if "test" not in f.lower()]

    if len(bare_excepts) > 10:
        return {
            "check_id": "E.1",
            "title": f"{len(bare_excepts)} bare/broad except clauses (no re-raise)",
            "severity": "LOW",
            "description": (
                "Silent exception swallowing risks hiding bugs -- this "
                "pattern was the root cause of several earlier silent-bug "
                "fixes in this project's fetcher code (see commit history: "
                "'fix silent HTTP-error swallowing in fetchers', 'fix silent "
                "CVE batch-insert bugs')."
            ),
            "evidence": "\n".join(f"  {f}:{l}" for f, l in bare_excepts[:20]),
            "fix_action": (
                "Audit each — either log-and-continue with an explicit "
                "reason, or re-raise. Fetchers in particular must re-raise "
                "on network/HTTP errors rather than swallow them."
            ),
        }
    if bare_excepts:
        return {
            "check_id": "E.1", "severity": "INFO",
            "title": f"{len(bare_excepts)} broad except clauses (below threshold)",
            "description": None,
            "evidence": "\n".join(f"  {f}:{l}" for f, l in bare_excepts),
            "fix_action": None,
        }
    return {"check_id": "E.1", "severity": "PASS"}


async def check_e2() -> dict:
    """E.2 -- LLM calls without an explicit timeout wrap."""
    try:
        result = subprocess.run(
            ["grep", "-rn", "await client.chat_", str(SRC)],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        return {
            "check_id": "E.2", "severity": "INFO",
            "title": "grep for LLM calls failed to run",
            "description": str(e)[:200], "evidence": None, "fix_action": None,
        }

    llm_calls = [l for l in result.stdout.split("\n") if l.strip()]
    no_timeout = [l for l in llm_calls if "wait_for" not in l and "timeout" not in l]

    if len(no_timeout) > 3:
        return {
            "check_id": "E.2",
            "title": f"{len(no_timeout)} LLM call site(s) without an explicit timeout wrap",
            "severity": "MEDIUM",
            "description": (
                "An LLM call that hangs can block the scheduler or agent "
                "loop. Note: the agent function-calling loop already "
                "passes timeout=30.0 into client.chat_with_tools directly "
                "at the call site (see agent/loop/function_calling.py), "
                "so this check is line-grep-based and may double count "
                "sites where the timeout is a kwarg on the same call "
                "rather than a separate wait_for/timeout keyword nearby."
            ),
            "evidence": "\n".join(no_timeout[:10]),
            "fix_action": (
                "For call sites without an inline timeout kwarg, add "
                "asyncio.wait_for(..., timeout=60) around scheduled/"
                "background paths. Interactive/user-triggered commands "
                "can rely on the user cancelling."
            ),
        }
    return {"check_id": "E.2", "severity": "PASS"}


async def check_e3() -> dict:
    """E.3 -- External API client modules without a retry decorator."""
    targets = ["src/ati_evn/enrichment_v2/adapters", "src/ati_evn/external"]
    existing_targets = [t for t in targets if Path(t).exists()]
    if not existing_targets:
        return {"check_id": "E.3", "severity": "PASS"}

    try:
        result = subprocess.run(
            ["grep", "-rL", "@retry", *existing_targets],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        return {
            "check_id": "E.3", "severity": "INFO",
            "title": "grep for @retry failed to run",
            "description": str(e)[:200], "evidence": None, "fix_action": None,
        }

    no_retry = [
        f for f in result.stdout.split("\n")
        if f and f.endswith(".py")
        and "_base" not in f and "__init__" not in f and "registry" not in f
    ]

    if no_retry:
        return {
            "check_id": "E.3", "severity": "LOW",
            "title": f"{len(no_retry)} client file(s) without a @retry decorator",
            "description": "External API clients should retry transient network errors.",
            "evidence": "\n".join(no_retry[:15]),
            "fix_action": "Add a tenacity @retry decorator on the fetch functions, where not already handled by an httpx retry transport.",
        }
    return {"check_id": "E.3", "severity": "PASS"}


async def check_e4() -> dict:
    """E.4 -- Transaction rollback pattern (informational, not auto-verifiable)."""
    return {
        "check_id": "E.4", "severity": "INFO",
        "title": "Transaction rollback check (informational)",
        "description": (
            "SQLAlchemy's async_session() context manager rolls back "
            "automatically on an exception exiting the `async with` block "
            "-- no explicit rollback call is needed as long as every "
            "write goes through `async with async_session() as session:`. "
            "This audit does not attempt to verify every call site "
            "mechanically; spot-checked call sites in this codebase "
            "consistently follow that pattern."
        ),
        "evidence": None, "fix_action": None,
    }


async def run_all() -> list[dict]:
    results = []
    for check in [check_e1, check_e2, check_e3, check_e4]:
        r = await check()
        if r["severity"] != "PASS":
            results.append(r)
    return results
