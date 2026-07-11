"""False-positive memory lookup.

Analysts mark IOCs as false positive via the Telegram /mark_fp handler
(slice 5), which inserts into fp_memory. This module only provides the
read-side check — no FpMemory rows are created here.
"""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import FpMemory


def compute_fp_hash(ioc_type: str, ioc_value: str) -> str:
    """SHA-256 hex of f'{ioc_type}::{ioc_value.lower().strip()}'."""
    normalized = f"{ioc_type}::{ioc_value.lower().strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


async def is_false_positive(
    session: AsyncSession, customer_id: int, ioc_type: str, ioc_value: str,
) -> tuple[bool, int | None]:
    """Return (is_fp, fp_memory_row_id).

    Caller is responsible for bumping hit_count/last_hit_at on the returned
    row and skipping Finding/ProbableExposure creation when is_fp is True.
    """
    value_hash = compute_fp_hash(ioc_type, ioc_value)
    result = await session.execute(
        select(FpMemory.id).where(
            FpMemory.customer_id == customer_id,
            FpMemory.ioc_type == ioc_type,
            FpMemory.ioc_value_hash == value_hash,
        )
    )
    row_id = result.scalar_one_or_none()
    return (row_id is not None, row_id)
