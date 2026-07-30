"""Load enrichment_config.yaml."""
from __future__ import annotations

import functools
import logging
from importlib import resources

import yaml

logger = logging.getLogger("ati_evn.enrichment_v2.config")


@functools.lru_cache(maxsize=1)
def load_config() -> dict:
    data_pkg = resources.files("ati_evn.data")
    with data_pkg.joinpath("enrichment_config.yaml").open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    cfg = data.get("enrichment") or {}
    logger.info("Enrichment config loaded: %d providers configured", len(cfg.get("weights") or {}))
    return cfg


def reload_config() -> dict:
    """Force a re-read of enrichment_config.yaml, bypassing the cache.

    load_config() is cached for the life of the process (by design --
    it's read on essentially every enrichment call, and re-parsing the
    YAML each time would be wasteful) but that means editing
    enrichment_config.yaml (e.g. tweaking provider weights) previously
    had no effect until the whole Bot process was restarted. Call this
    after an edit (e.g. from a REPL, a maintenance script, or a future
    /reload_config admin command) to pick up changes without a restart.
    """
    load_config.cache_clear()
    return load_config()


def get_provider_config(provider: str) -> dict:
    cfg = load_config()
    return (cfg.get("providers") or {}).get(provider) or {}


def get_weights() -> dict:
    return load_config().get("weights") or {}


def get_ttl_hours(provider: str) -> int:
    ttls = load_config().get("ttl_hours") or {}
    return int(ttls.get(provider, 24))


def get_foreground_providers() -> list[str]:
    return load_config().get("foreground_providers") or []


def get_background_providers() -> list[str]:
    return load_config().get("background_providers") or []


def get_scoring_policy(provider: str) -> dict:
    """Return scoring policy dict for provider."""
    cfg = load_config()
    scoring = cfg.get("scoring") or {}
    return scoring.get(provider) or {}
