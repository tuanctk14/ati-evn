"""summarize_customer — LLM-generated Vietnamese narrative summary for a customer."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.config import get_settings
from ati_evn.db.models import AlertQueue, Customer, CustomerAsset, Finding
from ati_evn.db.query_utils import (
    customer_match_order_by,
    customer_name_or_code_match,
    cve_only_filter,
    only_live_asset,
)
from ati_evn.db.session import async_session
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.agent.tools.summarize_customer")

SUMMARIZE_SYSTEM = """You are a CTI analyst writing a short executive summary
for a Vietnamese electric utility SOC about ONE customer's recent security
posture. Given aggregated metrics, write a ~300 word narrative summary in
Vietnamese (keep technical terms like CVE-ID, ATT&CK, CVSS in English).

Output JSON with key: summary (the markdown text).

Do NOT hallucinate any numbers not provided in the input — use exactly the
figures given. Return ONLY the JSON, no markdown fences."""


async def _resolve_customer(session, query_str: str) -> Customer | None:
    if query_str.isdigit():
        return await session.get(Customer, int(query_str))
    result = await session.execute(
        select(Customer).where(customer_name_or_code_match(query_str))
        .order_by(customer_match_order_by(query_str)).limit(1)
    )
    return result.scalar_one_or_none()


@register_tool(
    name="summarize_customer",
    description="Generate a Vietnamese narrative summary of a customer's recent security posture (calls the LLM).",
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Customer name or ID"},
            "since_days": {"type": "integer", "description": "Window size in days", "default": 7},
        },
        "required": ["customer"],
    },
)
async def summarize_customer(customer: str, since_days: int = 7) -> dict:
    async with async_session() as session:
        cust = await _resolve_customer(session, customer)
        if not cust:
            return tool_error(f"Customer '{customer}' not found", hint="Check the name spelling or try /customer.")

        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

        sev_rows = await session.execute(
            select(Finding.severity, func.count()).where(
                cve_only_filter(), Finding.customer_id == cust.id, Finding.first_seen >= cutoff,
            ).group_by(Finding.severity)
        )
        sev_counts = {s.value: c for s, c in sev_rows.all()}

        top_tech_rows = await session.execute(text("""
            SELECT t->>'id' AS tech_id, count(*) AS n
            FROM findings f, jsonb_array_elements((f.metadata::jsonb->'attack_context'->'techniques')) AS t
            WHERE f.customer_id = :customer_id AND f.first_seen >= :cutoff
            GROUP BY t->>'id' ORDER BY n DESC LIMIT 3
        """), {"customer_id": cust.id, "cutoff": cutoff})
        top_techniques = [(r[0], r[1]) for r in top_tech_rows.all()]

        recent_rows = await session.execute(
            select(Finding).where(
                cve_only_filter(),
                Finding.customer_id == cust.id,
                Finding.severity.in_(["CRITICAL", "HIGH"]),
                Finding.first_seen >= cutoff,
            ).order_by(Finding.first_seen.desc()).limit(5)
        )
        recent_findings = [
            {"id": f.id, "severity": f.severity.value, "title": f.title}
            for f in recent_rows.scalars()
        ]

        asset_rows = await session.execute(
            select(CustomerAsset.criticality, func.count()).where(
                CustomerAsset.customer_id == cust.id, only_live_asset(),
            ).group_by(CustomerAsset.criticality)
        )
        asset_breakdown = dict(asset_rows.all())

        dispatch_rows = await session.execute(
            select(AlertQueue.state, func.count()).where(
                AlertQueue.customer_id == cust.id, AlertQueue.created_at >= cutoff,
            ).group_by(AlertQueue.state)
        )
        dispatch_stats = dict(dispatch_rows.all())

        data = {
            "customer": cust.name,
            "since_days": since_days,
            "severity_breakdown": sev_counts,
            "top_techniques": top_techniques,
            "recent_critical_high_findings": recent_findings,
            "asset_breakdown_by_criticality": asset_breakdown,
            "dispatch_stats": dispatch_stats,
        }

    settings = get_settings()
    if not settings.openai_api_key:
        result = tool_error("LLM not configured (OPENAI_API_KEY missing)")
        result["data"] = data
        return result

    client = LLMClient(settings)
    try:
        raw = await client.chat_json(
            system=SUMMARIZE_SYSTEM,
            user=json.dumps(data, ensure_ascii=False, default=str),
            max_tokens=1024, temperature=0.3,
        )
        summary = raw.get("summary", "")
        words = summary.split()
        if len(words) > 500:
            summary = " ".join(words[:500])
        return {"success": True, "summary": summary, "data": data}
    except Exception as e:
        # The raw metrics in `data` are still valid even though the LLM
        # narrative failed -- but this must NOT look like a plain
        # success to the caller (an earlier version returned tool_error()
        # with `data` attached, which let the agent quietly present the
        # raw numbers as if the full summary had succeeded, hiding the
        # LLM failure from the analyst). success=True + narrative_failed
        # is a distinct third state the agent is told (SYSTEM_PROMPT) to
        # always surface before presenting `data`.
        logger.warning("summarize_customer LLM failed: %s", e)
        return {
            "success": True,
            "narrative_failed": True,
            "narrative_error": str(e)[:200],
            "data": data,
        }
