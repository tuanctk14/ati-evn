"""Deterministic, cheap pre-filter for LLM CPE inference candidates.

Running the LLM on every CVE with no CPE data would burn tokens on
hundreds of CVEs that could never match an EVN asset (e.g. an unrelated
npm package). We only send a CVE to the LLM if its description mentions
at least one vendor or product keyword we already know about from
customer_assets — a cheap, deterministic word-boundary substring check.

Shared by scripts/run_cpe_inference.py (the actual batch) and
customer_router.route_detections' end-of-run nudge (which only counts,
never calls the LLM).
"""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import CustomerAsset


async def load_hint_keywords(session: AsyncSession) -> list[str]:
    """Distinct lowercase vendor + product keywords from customer_assets."""
    result = await session.execute(
        select(CustomerAsset.vendor, CustomerAsset.product).where(CustomerAsset.vendor.is_not(None))
    )
    keywords: set[str] = set()
    for vendor, product in result.all():
        if vendor:
            keywords.add(vendor.strip().lower())
        if product:
            # Split multi-word products into individual tokens too (e.g.
            # "simatic s7-1200" -> "simatic", "s7-1200") so a description
            # mentioning just the product line still hits the pre-filter.
            product_norm = product.strip().lower()
            keywords.add(product_norm)
            for token in re.split(r"[\s_-]+", product_norm):
                if len(token) >= 3:
                    keywords.add(token)
    return sorted(keywords)


def text_matches_any_keyword(text: str, keywords: list[str]) -> str | None:
    """Return the first keyword found as a whole word in text (case-insensitive),
    or None if no keyword matches."""
    if not text:
        return None
    lowered = text.lower()
    for keyword in keywords:
        if re.search(r"\b" + re.escape(keyword) + r"\b", lowered):
            return keyword
    return None
