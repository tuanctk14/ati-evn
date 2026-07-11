"""False-positive memory lookup.

Analysts mark IOCs as false positive via the Telegram /mark_fp handler
(slice 5), which inserts into fp_memory. This module only provides the
read-side check — no FpMemory rows are created here.
"""
from __future__ import annotations

import hashlib

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import FpMemory


def compute_fp_hash(ioc_type: str, ioc_value: str) -> str:
    """SHA-256 hex of f'{ioc_type}::{ioc_value.lower().strip()}'."""
    normalized = f"{ioc_type}::{ioc_value.lower().strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


async def is_false_positive(
    session: AsyncSession, customer_id: int, ioc_type: str, ioc_value: str,
    asset_id: int | None = None,
) -> tuple[bool, int | None]:
    """Check FP with per-asset OR customer-wide scope.

    An FpMemory row with asset_id=NULL applies to ALL of this customer's
    assets; a row with a specific asset_id only suppresses that one asset.
    Both scopes are checked so a narrow per-asset FP doesn't accidentally
    miss (and a customer-wide FP still covers assets added later).

    Caller is responsible for bumping hit_count/last_hit_at on the returned
    row and skipping Finding/ProbableExposure creation when is_fp is True.
    """
    value_hash = compute_fp_hash(ioc_type, ioc_value)
    result = await session.execute(
        select(FpMemory.id).where(
            FpMemory.customer_id == customer_id,
            FpMemory.ioc_type == ioc_type,
            FpMemory.ioc_value_hash == value_hash,
            or_(FpMemory.asset_id == asset_id, FpMemory.asset_id.is_(None)),
        )
    )
    row_id = result.scalar_one_or_none()
    return (row_id is not None, row_id)
