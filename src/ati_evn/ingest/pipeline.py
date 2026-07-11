"""Ingest pipeline v0 — receive-side API that turns RawIOC into Detection rows.

This module never talks to fetchers directly; it is the sole consumer of
list[RawIOC]. The runner (scripts/run_fetchers.py) does the fetching and
calls ingest_raw_iocs().

Dedup rule: a RawIOC is considered a repeat sighting if a Detection with the
same (source, ioc_type, ioc_value) was created within `dedup_window_hours`.
In that case we bump the existing row's last_seen instead of inserting a new
Detection. Everything else is a fresh insert with status=NEW, customer_id
unset (routing happens in slice 3).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import CveCweMap, CveProductMap, Detection, DetectionStatus, Severity
from ati_evn.fetchers.base import RawIOC

logger = logging.getLogger("ati_evn.ingest.pipeline")

_HASH_LENGTHS = {32, 40, 64}

_SEVERITY_VALUES = {s.value for s in Severity}


@dataclass
class IngestStats:
    inserted: int = 0
    deduped: int = 0
    rejected: int = 0
    by_source: dict[str, int] = field(default_factory=dict)
    by_ioc_type: dict[str, int] = field(default_factory=dict)

    def _bump(self, counter: dict[str, int], key: str) -> None:
        counter[key] = counter.get(key, 0) + 1

    def record_inserted(self, source: str, ioc_type: str) -> None:
        self.inserted += 1
        self._bump(self.by_source, source)
        self._bump(self.by_ioc_type, ioc_type)

    def merge(self, other: "IngestStats") -> None:
        self.inserted += other.inserted
        self.deduped += other.deduped
        self.rejected += other.rejected
        for k, v in other.by_source.items():
            self.by_source[k] = self.by_source.get(k, 0) + v
        for k, v in other.by_ioc_type.items():
            self.by_ioc_type[k] = self.by_ioc_type.get(k, 0) + v


def _normalize_ioc_value(ioc_type: str, raw_value: str) -> str | None:
    value = raw_value.strip()
    if not value:
        return None

    if ioc_type == "url":
        # Preserve path casing; lowercase only the host component.
        match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://)?([^/]+)(/.*)?$", value)
        if match:
            scheme, host, rest = match.groups()
            value = f"{scheme or ''}{host.lower()}{rest or ''}"
        return value

    return value.lower()


def _passes_sanity_check(ioc_type: str, value: str) -> bool:
    if not value:
        return False

    if ioc_type == "domain" or ioc_type == "subdomain":
        return "." in value
    if ioc_type in ("ipv4",):
        return any(ch.isdigit() for ch in value) and "." in value
    if ioc_type == "ipv6":
        return ":" in value
    if ioc_type in ("md5", "sha1", "sha256"):
        return len(value) in _HASH_LENGTHS and all(c in "0123456789abcdef" for c in value)
    if ioc_type == "cve_id":
        return value.upper().startswith("CVE-")
    if ioc_type == "url":
        return "." in value
    # email, keyword, brand_name, etc. — no cheap check, accept as-is.
    return True


def _map_severity(severity_hint: str | None) -> Severity:
    if severity_hint and severity_hint.upper() in _SEVERITY_VALUES:
        return Severity(severity_hint.upper())
    return Severity.MEDIUM


async def _find_recent_detection(
    session: AsyncSession, source: str, ioc_type: str, ioc_value: str, cutoff: datetime,
) -> Detection | None:
    result = await session.execute(
        select(Detection).where(
            and_(
                Detection.source == source,
                Detection.ioc_type == ioc_type,
                Detection.ioc_value == ioc_value,
                Detection.created_at >= cutoff,
            )
        ).order_by(Detection.created_at.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def upsert_cve_product_map(session: AsyncSession, rows: list[dict]) -> int:
    if not rows:
        return 0

    stmt = pg_insert(CveProductMap).values(rows)
    stmt = stmt.on_conflict_do_nothing(constraint="uq_cpm_row")
    result = await session.execute(stmt)
    return result.rowcount or 0


async def upsert_cve_cwe_map(session: AsyncSession, rows: list[dict]) -> int:
    if not rows:
        return 0

    stmt = pg_insert(CveCweMap).values(rows)
    stmt = stmt.on_conflict_do_nothing(constraint="uq_cwe_row")
    result = await session.execute(stmt)
    return result.rowcount or 0


async def ingest_raw_iocs(
    session: AsyncSession,
    raw_iocs: list[RawIOC],
    dedup_window_hours: int = 24,
    cve_product_map_rows: list[dict] | None = None,
) -> IngestStats:
    stats = IngestStats()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=dedup_window_hours)

    for raw in raw_iocs:
        ioc_type = raw.ioc_type
        normalized = _normalize_ioc_value(ioc_type, raw.ioc_value)

        if normalized is None or not _passes_sanity_check(ioc_type, normalized):
            stats.rejected += 1
            continue

        existing = await _find_recent_detection(session, raw.source, ioc_type, normalized, cutoff)
        if existing is not None:
            existing.last_seen = datetime.now(timezone.utc)
            stats.deduped += 1
            continue

        detection = Detection(
            source=raw.source,
            ioc_type=ioc_type,
            ioc_value=normalized,
            raw_text=raw.raw_text,
            severity=_map_severity(raw.severity_hint),
            status=DetectionStatus.NEW,
            confidence=0.5,
            metadata_=raw.metadata or {},
        )
        session.add(detection)
        stats.record_inserted(raw.source, ioc_type)

    await upsert_cve_product_map(session, cve_product_map_rows or [])

    await session.flush()
    logger.info(
        "Ingest: inserted=%d deduped=%d rejected=%d",
        stats.inserted, stats.deduped, stats.rejected,
    )
    return stats


async def ingest_cve_batch(session: AsyncSession, payload: dict) -> IngestStats:
    """Ingest the NVD fetcher's {"raw_iocs", "cpe_rows", "cwe_rows"} shape.
    cpe_rows/cwe_rows mix source='nvd' and source='llm_inferred' rows —
    both are upserted the same way; the ON CONFLICT DO NOTHING unique
    constraints (uq_cpm_row / uq_cwe_row) already key on source, so an LLM
    inference never collides with or overwrites NVD's own authoritative row.
    """
    stats = await ingest_raw_iocs(session, payload["raw_iocs"])
    cpe_inserted = await upsert_cve_product_map(session, payload["cpe_rows"])
    cwe_inserted = await upsert_cve_cwe_map(session, payload["cwe_rows"])
    logger.info(
        "CVE batch: %d detections, %d CPE rows, %d CWE rows",
        stats.inserted, cpe_inserted, cwe_inserted,
    )
    return stats
