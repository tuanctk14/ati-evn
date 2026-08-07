"""top_cve_by_finding_count — aggregate Finding count per CVE, server-side
(not a per-finding sample or a full-table pagination).

Added after a manual test showed the agent answering "CVE nao co nhieu
Finding nhat" by paginating search_findings across the ENTIRE dataset
(6 calls, 92,420 tokens, near-total-failure) instead of a cheap
GROUP BY -- same root-cause class as top_attack_techniques.py (no
aggregate tool existed, so the model reconstructed the aggregate by
brute-force reading every row).
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
    name="top_cve_by_finding_count",
    description=(
        "Return the CVEs with the most Findings, computed as a true "
        "aggregate (GROUP BY) over ALL matching Findings -- use this for "
        "'CVE nao co nhieu Finding nhat / most Findings' questions "
        "instead of paginating search_findings across the whole dataset "
        "to count manually, which is far more expensive and can exhaust "
        "the token budget before answering."
    ),
    parameters={
        "type": "object",
        "properties": {
            "since_days": {"type": "integer", "description": "Only findings first_seen within this many days. Omit for no time limit."},
            "customer": {"type": "string", "description": "Customer name/short_code, optional (omit for all EVN)"},
            "limit": {"type": "integer", "default": 5, "description": "Max CVEs returned (capped at 20)"},
        },
        "required": [],
    },
)
async def top_cve_by_finding_count(
    since_days: int | None = None, customer: str | None = None, limit: int = 5,
) -> dict:
    limit = min(max(limit, 1), HARD_CAP)

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

        query = "SELECT ioc_value, count(*) AS n FROM findings WHERE ioc_type = 'cve_id'"
        params: dict = {}
        if since_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
            query += " AND first_seen >= :cutoff"
            params["cutoff"] = cutoff
        if customer_id is not None:
            query += " AND customer_id = :customer_id"
            params["customer_id"] = customer_id
        query += " GROUP BY ioc_value ORDER BY n DESC LIMIT :limit"
        params["limit"] = limit

        rows = (await session.execute(text(query), params)).all()

    return {
        "since_days": since_days,
        "customer": customer,
        "cves": [{"cve_id": r[0], "finding_count": r[1]} for r in rows],
    }
