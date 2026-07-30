"""Trigger IP enrichment via agent -- non-destructive (only queries APIs).

Note: get_ip_enrichment (existing read-only tool) reads cached
IpEnrichment rows only. This tool actually calls the providers.
"""
from __future__ import annotations

import logging

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.enrichment_v2.ip_enricher import enrich_ip_foreground, enrich_ip_full

logger = logging.getLogger("ati_evn.agent.tools.enrich_ip")


@register_action_tool(
    name="enrich_ip",
    destructive=False,
    description=(
        "Enrich an IPv4/IPv6 via multi-source providers (live API calls). "
        "Default: foreground (AbuseIPDB + VirusTotal, ~5s). "
        "full=true: all 5 providers (~15-30s). "
        "IMPORTANT: the `ip` param is passed to providers as-is with no "
        "DNS resolution -- you CAN pass a domain string instead of an IP "
        "(e.g. to check a typosquat domain's hosting reputation), but "
        "IP-only providers (e.g. AbuseIPDB) will error and be skipped, "
        "so a domain query returns partial coverage, not a failure. "
        "There is no separate domain-to-IP resolution tool -- if you "
        "need the real resolved IP first, check search_indicators or "
        "search_exposures for an already-known IP tied to that domain."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": (
                    "IPv4/IPv6 address, e.g. '8.8.8.8'. A domain name "
                    "(e.g. 'evn.io.vn') also works but yields partial "
                    "provider coverage -- see tool description."
                ),
            },
            "full": {"type": "boolean", "default": False, "description": "Query all 5 providers"},
            "force": {"type": "boolean", "default": False, "description": "Bypass cache TTL"},
        },
        "required": ["ip"],
    },
)
async def action_enrich_ip(ip: str, full: bool = False, force: bool = False) -> dict:
    try:
        if full:
            results, agg = await enrich_ip_full(ip, force=force)
        else:
            results, agg = await enrich_ip_foreground(ip, force=force)
    except Exception as e:
        logger.warning("enrich_ip failed for %s: %s", ip, e)
        return tool_error(f"Enrichment failed: {str(e)[:200]}")

    return {
        "ip": ip,
        "providers_queried": len(results),
        "per_provider": results,
        "aggregate": (
            {
                "risk_score": agg.aggregate_risk_score,
                "confidence": agg.confidence_score,
                "coverage": agg.coverage_score,
                "positive_count": agg.positive_provider_count,
                "consensus_status": agg.consensus_status,
            }
            if agg else None
        ),
    }
