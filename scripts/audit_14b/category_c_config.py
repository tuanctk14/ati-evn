"""Category C -- configuration checks (3 checks).

Field names verified against src/ati_evn/config.py and
src/ati_evn/enrichment_v2/config.py -- this project's LLM provider is
"9router" (DeepSeek-compatible), configured via openai_base_url/
llm_model, not a hard OPENAI_API_KEY requirement; Telegram uses a
2-bot split (alert bot + analyst bot) plus a legacy single-bot pair.
"""
from __future__ import annotations

import inspect


async def check_c1() -> dict:
    """C.1 -- enrichment_config.yaml is loaded via lru_cache (no hot-reload)."""
    from ati_evn.enrichment_v2.config import load_config

    source = inspect.getsource(load_config)
    if "lru_cache" in source:
        return {
            "check_id": "C.1",
            "title": "load_config() uses lru_cache — YAML edits need a process restart",
            "severity": "LOW",
            "description": (
                "Editing enrichment_config.yaml (e.g. provider weights) "
                "does not take effect until the Bot process restarts, "
                "since load_config() caches the parsed result for the "
                "life of the process."
            ),
            "evidence": None,
            "fix_action": "Document in ops runbook, or add a /reload_config command.",
        }
    return {"check_id": "C.1", "severity": "PASS"}


async def check_c2() -> dict:
    """C.2 -- Settings for the bots this project actually runs are non-empty.

    Settings fields default to "" rather than raising at import time
    (Pydantic BaseSettings with string defaults, not required fields),
    so "missing" here means "still at its empty default", checked via
    get_settings() rather than raw os.environ (some values may come
    from a loaded .env file rather than the process environment).
    """
    from ati_evn.config import get_settings

    settings = get_settings()
    required_fields = [
        "telegram_alert_bot_token",
        "telegram_analyst_bot_token",
        "telegram_allowed_user_ids",
        "openai_base_url",
    ]
    missing = [f for f in required_fields if not getattr(settings, f, "")]

    if missing:
        return {
            "check_id": "C.2",
            "title": f"{len(missing)} bot/LLM setting(s) unset",
            "severity": "CRITICAL",
            "description": (
                "Bot 1 (alerts), Bot 2 (analyst), or the LLM provider "
                "cannot function without these settings."
            ),
            "evidence": f"unset_fields={missing}",
            "fix_action": "Set the corresponding env vars in .env before restarting the bots.",
        }
    return {"check_id": "C.2", "severity": "PASS"}


async def check_c3() -> dict:
    """C.3 -- Enrichment provider weights should sum to 1.0 (+/- 0.001)."""
    from ati_evn.enrichment_v2.config import get_weights

    weights = get_weights()
    total = sum(weights.values())
    if abs(total - 1.0) > 0.001:
        return {
            "check_id": "C.3",
            "title": f"Enrichment weights sum = {total:.3f}, not 1.0",
            "severity": "HIGH",
            "description": (
                "The aggregator normalizes by sum(weights) of *responded* "
                "providers, but a base weight config that doesn't sum to "
                "1.0 still skews the intended relative importance of each "
                "provider."
            ),
            "evidence": f"weights={weights}, sum={total}",
            "fix_action": "Fix src/ati_evn/data/enrichment_config.yaml weights.",
        }
    return {"check_id": "C.3", "severity": "PASS"}


async def run_all() -> list[dict]:
    results = []
    for check in [check_c1, check_c2, check_c3]:
        r = await check()
        if r["severity"] != "PASS":
            results.append(r)
    return results
