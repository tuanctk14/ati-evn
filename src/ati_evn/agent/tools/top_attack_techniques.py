"""top_attack_techniques — aggregate ATT&CK technique frequency across
Findings, server-side (not a per-finding sample).

Added after a manual test showed the agent guessing "most common
technique" from a handful of sampled Findings and getting it wrong
(no tool existed to compute this aggregate directly) -- see
scripts/audit_14b_backlog.md's "no aggregate tool for ATT&CK technique
frequency" entry. Reuses the same jsonb_array_elements query
telegram/commands/export.py's weekly-report generator already relies
on for its own "Top 5 ATT&CK techniques" section, just exposed as a
directly-callable, customer-filterable tool.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match
from ati_evn.db.session import async_session

HARD_CAP = 20


@register_tool(
    name="top_attack_techniques",
    description=(
        "Return the most frequent MITRE ATT&CK techniques across "
        "Findings, computed as a true aggregate over ALL matching "
        "Findings (not a sample) -- use this for 'most common/phổ biến "
        "nhất technique' questions instead of guessing from a handful "
        "of individually-inspected Findings."
    ),
    parameters={
        "type": "object",
        "properties": {
            "since_days": {"type": "integer", "default": 30, "description": "Window size in days"},
            "customer": {"type": "string", "description": "Customer name/short_code, optional (omit for all EVN)"},
            "limit": {"type": "integer", "default": 5, "description": "Max techniques returned (capped at 20)"},
        },
        "required": [],
    },
)
async def top_attack_techniques(
    since_days: int = 30, customer: str | None = None, limit: int = 5,
) -> dict:
    limit = min(max(limit, 1), HARD_CAP)
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    async with async_session() as session:
        customer_id = None
        if customer:
            cust_row = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer))
                .order_by(customer_match_order_by(customer))
                .limit(1)
            )
            customer_id = cust_row.scalar_one_or_none()
            if customer_id is None:
                return tool_error(f"Customer '{customer}' not found")

        query = """
            SELECT t->>'id' AS tech_id, count(*) AS n
            FROM findings f, jsonb_array_elements((f.metadata::jsonb->'attack_context'->'techniques')) AS t
            WHERE f.first_seen >= :cutoff
        """
        params: dict = {"cutoff": cutoff}
        if customer_id is not None:
            query += " AND f.customer_id = :customer_id"
            params["customer_id"] = customer_id
        query += " GROUP BY t->>'id' ORDER BY n DESC LIMIT :limit"
        params["limit"] = limit

        rows = (await session.execute(text(query), params)).all()

    return {
        "since_days": since_days,
        "customer": customer,
        "techniques": [{"technique_id": r[0], "count": r[1]} for r in rows],
    }
