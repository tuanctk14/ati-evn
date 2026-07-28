"""Compute expires_at for a ThreatIndicator based on indicator_type.

Per source-type policy:
  brand_abuse       -> 90 days
  exposed_document  -> 60 days
  exposure          -> 30 days
  ipv4/ipv6/domain/url/sha256/sha1/md5 -> 14 days
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

TTL_DAYS = {
    "brand_abuse": 90,
    "exposed_document": 60,
    "exposure": 30,
    "ipv4": 14,
    "ipv6": 14,
    "domain": 14,
    "url": 14,
    "sha256": 14,
    "sha1": 14,
    "md5": 14,
}

DEFAULT_TTL_DAYS = 14


def compute_expires_at(indicator_type: str, first_seen: datetime | None = None) -> datetime:
    """Return expiration timestamp = first_seen + TTL for type."""
    base = first_seen or datetime.now(timezone.utc)
    days = TTL_DAYS.get(indicator_type, DEFAULT_TTL_DAYS)
    return base + timedelta(days=days)


def is_expired(indicator, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return indicator.expires_at < now
