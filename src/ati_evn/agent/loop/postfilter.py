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
    "/list_indicators", "/search_indicators", "/indicator",
    "/acknowledge_indicator", "/note_indicator", "/export_indicators",
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


# Telegram's legacy Markdown parse_mode has no concept of "#" headings,
# "|---|" tables, "---" horizontal rules, or "**bold**" (only single-star
# *bold* is supported) -- all render as literal punctuation clutter instead
# of formatting. The system prompt tells the LLM not to produce them, but
# this is a behavioral-discipline instruction an LLM won't reliably follow,
# so enforce it here as a deterministic safety net (same rationale as the
# command-hallucination postfilter above).
_HEADING_RE = re.compile(r"^#{1,6}\s*(.+?)\s*$", re.MULTILINE)
_HR_RE = re.compile(r"^\s*-{3,}\s*$", re.MULTILINE)
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_TABLE_SEP_RE = re.compile(r"^\s*\|[\s:|-]*\|\s*$")


def _table_row_cells(line: str) -> list[str]:
    stripped = line.strip().strip("|")
    return [c.strip() for c in stripped.split("|")]


def _convert_tables(text: str) -> str:
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        is_header = "|" in line and i + 1 < len(lines) and _TABLE_SEP_RE.match(lines[i + 1])
        if not is_header:
            out.append(line)
            i += 1
            continue

        headers = _table_row_cells(line)
        i += 2  # skip header + separator row
        while i < len(lines) and "|" in lines[i] and lines[i].strip():
            cells = _table_row_cells(lines[i])
            parts = [
                f"{h}: {c}" for h, c in zip(headers, cells) if c
            ]
            out.append("- " + " — ".join(parts))
            i += 1
    return "\n".join(out)


def sanitize_telegram_markdown(text: str) -> str:
    """Rewrite GitHub-flavored constructs Telegram legacy Markdown can't
    render (headings, tables, horizontal rules, double-star bold) into
    equivalents that actually render in Telegram's legacy Markdown mode."""
    if not text:
        return text
    text = _convert_tables(text)
    text = _HEADING_RE.sub(lambda m: f"*{m.group(1)}*", text)
    text = _BOLD_RE.sub(lambda m: f"*{m.group(1)}*", text)
    text = _HR_RE.sub("", text)
    # collapse the blank-line runs left behind by a removed "---" line
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
