"""Deterministic post-filter for agent output.

Fixes command name hallucinations that survive the prompt-level
instruction (e.g. /campaign_detail -> /campaign, /campaign_confirm ->
/confirm_campaign). Applied AFTER agent produces final answer, BEFORE
Telegram send.

Strategy:
  1. Whitelist of all real commands registered in Bot 2's routers.
  2. Regex-find every /token in the answer text.
  3. If token is whitelisted, leave it untouched.
  4. If token is a known hallucination (FIX_MAP), replace with the
     real command.
  5. Otherwise, strip the token (safer than showing the analyst an
     invalid command).
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger("ati_evn.agent.postfilter")

# Curated hallucination -> real command map. Extend as new patterns
# are observed in production; this is a living whitelist.
FIX_MAP: dict[str, str] = {
    # Campaign
    "/campaign_detail": "/campaign",
    "/campaign_info": "/campaign",
    "/campaign_show": "/campaign",
    "/show_campaign": "/campaign",
    "/view_campaign": "/campaign",
    "/campaign_list": "/list_campaigns",
    "/campaigns": "/list_campaigns",
    "/list_campaign": "/list_campaigns",
    "/campaign_confirm": "/confirm_campaign",
    "/confirm": "/confirm_campaign",
    "/campaign_reject": "/reject_campaign",
    "/reject": "/reject_campaign",
    # Finding actions
    "/finding_detail": "/finding",
    "/finding_info": "/finding",
    "/show_finding": "/finding",
    "/close_finding": "/close",
    "/finding_close": "/close",
    "/mark_finding_fp": "/mark_fp",
    "/finding_ack": "/ack",
    # CVE
    "/cve_detail": "/cve",
    "/cve_info": "/cve",
    "/show_cve": "/cve",
    # IOC
    "/ioc_detail": "/ioc",
    "/ioc_info": "/ioc",
    # Playbook / rule
    "/get_playbook": "/playbook",
    "/get_rule": "/rule",
    "/sigma": "/rule",
    # Customer/asset
    "/customer_detail": "/customer",
    "/asset_detail": "/asset",
    "/customer_info": "/customer",
    # Stats
    "/dashboard": "/stats",
    "/status": "/stats",
    # Ingestion
    "/ingestion": "/ingest",
    "/ingest_confirm": "/confirm_ingest",
    "/ingest_reject": "/reject_ingest",
    "/ingest_edit": "/edit_ingest",
    "/list_ingest": "/list_ingests",
    "/ingest_list": "/list_ingests",
    # Censys
    "/censys": "/scan_censys",
    "/censys_scan": "/scan_censys",
    "/scan_external": "/scan_censys",
    # Fetcher
    "/fetch": "/force_fetch",
    "/force_fetcher": "/force_fetch",
    "/refresh_feeds": "/force_fetch",
    # GrayHatWarfare
    "/grayhat": "/scan_ghwarfare",
    "/scan_documents": "/scan_ghwarfare",
    "/scan_bucket": "/scan_ghwarfare",
    # urlscan / brand abuse
    "/urlscan": "/scan_urlscan",
    "/scan_brand": "/scan_urlscan",
    "/brand_abuse": "/scan_urlscan",
    "/scan_brand_abuse": "/scan_urlscan",
    # AbuseIPDB / IP enrichment
    "/enrichment": "/enrich_ip",
    "/check_ip": "/enrich_ip",
    "/lookup_ip": "/enrich_ip",
    "/abuseipdb": "/enrich_ip",
    "/enrich": "/enrich_ip",
    "/lookup": "/enrich_ip",
    "/report": "/generate_report",
    "/gen_report": "/generate_report",
    "/reports": "/list_reports",
    "/download": "/download_report",
}

# All real Bot 2 commands, sourced from the router registry
# (src/ati_evn/telegram/commands/*.py Command(...) decorators).
WHITELIST: frozenset[str] = frozenset({
    "/start", "/help", "/finding", "/cve", "/ioc", "/asset",
    "/customer", "/stats", "/list_open", "/list_alerts",
    "/rule", "/playbook", "/export",
    "/add_customer", "/add_asset", "/add_ioc",
    "/update_customer", "/update_asset", "/update_ioc",
    "/delete_customer", "/delete_asset", "/delete_ioc",
    "/restore_customer", "/restore_asset", "/restore_ioc",
    "/ack", "/close", "/mark_fp", "/reopen", "/silence", "/rescan",
    "/campaign", "/list_campaigns", "/confirm_campaign",
    "/reject_campaign", "/add_test_campaign",
    "/ingest", "/confirm_ingest", "/reject_ingest",
    "/edit_ingest", "/list_ingests",
    "/scan_censys", "/force_fetch", "/scan_ghwarfare", "/scan_urlscan", "/enrich_ip",
    "/generate_report", "/list_reports", "/download_report",
})

# Match /command_name at a word boundary (line start or preceded by
# whitespace/opening punctuation), not inside a URL like https://...
COMMAND_RE = re.compile(r"(?:(?<=^)|(?<=[\s\(\[`]))(/[a-zA-Z_]+)", re.MULTILINE)


def postfilter_answer(text: str) -> tuple[str, dict]:
    """Return (cleaned_text, stats).

    stats: {"replaced": [(bad, good), ...], "stripped": [bad, ...]}
    """
    if not text:
        return text, {"replaced": [], "stripped": []}

    replaced: list[tuple[str, str]] = []
    stripped: list[str] = []

    def _replace(m: re.Match) -> str:
        token = m.group(1)
        token_lower = token.lower()
        if token_lower in WHITELIST:
            return token
        if token_lower in FIX_MAP:
            real = FIX_MAP[token_lower]
            replaced.append((token, real))
            return real
        stripped.append(token)
        logger.warning(
            "Post-filter stripped unknown command %r from agent output", token
        )
        return ""

    cleaned = COMMAND_RE.sub(_replace, text)
    stats = {"replaced": replaced, "stripped": stripped}
    if replaced or stripped:
        logger.info(
            "Post-filter: %d replaced, %d stripped", len(replaced), len(stripped)
        )
    return cleaned, stats
