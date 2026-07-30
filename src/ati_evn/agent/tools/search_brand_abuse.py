"""search_brand_abuse -- search urlscan.io brand abuse sightings."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import BrandAbuseSighting, Customer, ThreatIndicator
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match
from ati_evn.db.session import async_session


@register_tool(
    name="search_brand_abuse",
    description=(
        "Search brand abuse / impersonation sightings from urlscan.io. Filter by "
        "customer, keyword, rule matched, malicious verdict. Each row is a raw "
        "observation; findings are created only if the pipeline confirmed relevance."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string"},
            "keyword": {"type": "string"},
            "rule_matched_only": {"type": "boolean", "default": False},
            "malicious_only": {"type": "boolean", "default": False},
            "since_days": {"type": "integer"},
            "limit": {"type": "integer", "default": 10},
        },
        "required": [],
    },
)
async def search_brand_abuse(
    customer: str | None = None,
    keyword: str | None = None,
    rule_matched_only: bool = False,
    malicious_only: bool = False,
    since_days: int | None = None,
    limit: int = 10,
) -> dict:
    limit = min(max(limit, 1), 20)

    async with async_session() as session:
        stmt = select(BrandAbuseSighting).where(BrandAbuseSighting.status == "active")
        count_stmt = select(func.count(BrandAbuseSighting.id)).where(BrandAbuseSighting.status == "active")

        if customer:
            r = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer))
                .order_by(customer_match_order_by(customer)).limit(1)
            )
            cid = r.scalar_one_or_none()
            if not cid:
                return tool_error(f"Customer '{customer}' not found")
            stmt = stmt.where(BrandAbuseSighting.customer_id == cid)
            count_stmt = count_stmt.where(BrandAbuseSighting.customer_id == cid)
        if keyword:
            stmt = stmt.where(BrandAbuseSighting.keyword_matched.ilike(f"%{keyword}%"))
            count_stmt = count_stmt.where(BrandAbuseSighting.keyword_matched.ilike(f"%{keyword}%"))
        if rule_matched_only:
            stmt = stmt.where(BrandAbuseSighting.rule_matched.is_not(None))
            count_stmt = count_stmt.where(BrandAbuseSighting.rule_matched.is_not(None))
        if malicious_only:
            stmt = stmt.where(BrandAbuseSighting.verdict_malicious.is_(True))
            count_stmt = count_stmt.where(BrandAbuseSighting.verdict_malicious.is_(True))
        if since_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
            stmt = stmt.where(BrandAbuseSighting.first_seen_local >= cutoff)
            count_stmt = count_stmt.where(BrandAbuseSighting.first_seen_local >= cutoff)

        total = (await session.execute(count_stmt)).scalar() or 0
        stmt = stmt.order_by(BrandAbuseSighting.last_seen_local.desc()).limit(limit)
        rows = list((await session.execute(stmt)).scalars())

        customer_names: dict[int, str] = {}
        for r in rows:
            if r.customer_id and r.customer_id not in customer_names:
                c = await session.get(Customer, r.customer_id)
                customer_names[r.customer_id] = c.name if c else f"#{r.customer_id}"

        # Map sighting -> its ThreatIndicator id so callers can point the
        # analyst at /indicator <id> without confusing the two ID spaces
        # (BrandAbuseSighting.id and ThreatIndicator.id are unrelated
        # sequences -- a sighting's own "id" is NOT a valid /indicator arg).
        # A sighting can have more than one TI row across rescans; use the
        # most recently created one.
        sighting_ids = [r.id for r in rows]
        indicator_ids: dict[int, int] = {}
        if sighting_ids:
            ti_rows = await session.execute(
                select(ThreatIndicator.id, ThreatIndicator.source_entity_id).where(
                    ThreatIndicator.source_entity_type == "brand_abuse_sighting",
                    ThreatIndicator.source_entity_id.in_(sighting_ids),
                ).order_by(ThreatIndicator.id.desc())
            )
            for ti_id, sid in ti_rows.all():
                indicator_ids.setdefault(sid, ti_id)

        return {
            "total_count": total,
            "returned_count": len(rows),
            "sightings": [
                {
                    "id": r.id, "url": r.url, "domain": r.domain,
                    "page_title": r.page_title,
                    "keyword_matched": r.keyword_matched,
                    "customer": customer_names.get(r.customer_id),
                    "rule_matched": r.rule_matched,
                    "rule_severity": r.rule_severity,
                    "verdict_malicious": r.verdict_malicious,
                    "engines_malicious_total": r.engines_malicious_total,
                    "typosquat_distance": r.typosquat_distance,
                    "llm_relevant": r.llm_relevant,
                    "llm_reasoning": r.llm_reasoning,
                    "first_seen_local": r.first_seen_local.isoformat() if r.first_seen_local else None,
                    "indicator_id": indicator_ids.get(r.id),
                }
                for r in rows
            ],
        }
