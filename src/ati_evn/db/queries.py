"""Small cross-cutting query helpers that don't warrant their own module."""
from __future__ import annotations

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import CustomerAsset
from ati_evn.db.query_utils import only_live_asset
from ati_evn.db.session import async_session


async def load_evn_vendors_lowercase(session: AsyncSession | None = None) -> set[str]:
    """Distinct lowercase CustomerAsset.vendor values across all customers.
    Used as the LLM-inference relevance filter's vendor allowlist."""
    async def _q(s: AsyncSession) -> set[str]:
        rows = await s.execute(
            select(distinct(func.lower(CustomerAsset.vendor)))
            .where(CustomerAsset.vendor.is_not(None), only_live_asset())
        )
        return {r[0] for r in rows if r[0]}

    if session is not None:
        return await _q(session)
    async with async_session() as s:
        return await _q(s)
