"""Dedupe key: (customer_id, ioc_value, asset_id) within window.

When a new alert arrives:
  1. Compute key hash
  2. Look up alert_queue for same key within N minutes
     (state IN dispatched, batched)
  3. If found → mark new alert state=deduped, deduped_of_id=old_id
  4. If not → queue as pending
"""
from __future__ import annotations

import hashlib
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import AlertQueue, _utcnow


def compute_dedupe_key(customer_id: int, ioc_value: str, asset_id: int | None) -> str:
    """SHA-256 of (customer_id::ioc_value::asset_id or '')."""
    raw = f"{customer_id}::{(ioc_value or '').lower()}::{asset_id or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


async def find_existing_dispatch(
    session: AsyncSession, dedupe_key: str, window_minutes: int,
) -> int | None:
    """Return alert_queue.id of an existing dispatched/batched entry within
    the window, or None."""
    cutoff = _utcnow() - timedelta(minutes=window_minutes)
    stmt = select(AlertQueue.id).where(
        AlertQueue.dedupe_key == dedupe_key,
        AlertQueue.created_at >= cutoff,
        AlertQueue.state.in_(("dispatched", "batched")),
    ).order_by(AlertQueue.created_at.desc()).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none()
