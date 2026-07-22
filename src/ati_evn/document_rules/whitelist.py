"""Stage 1: Bucket URL whitelist filter.

Pass if the bucket URL matches EVN-related patterns.
"""
from __future__ import annotations

import re

WHITELIST_PATTERNS = [
    re.compile(r"evn", re.IGNORECASE),
    re.compile(r"vietnam", re.IGNORECASE),
    re.compile(r"dienluc", re.IGNORECASE),
    re.compile(r"electricity", re.IGNORECASE),
]


def bucket_matches_whitelist(bucket_url: str) -> bool:
    """Return True if the bucket URL likely relates to EVN."""
    if not bucket_url:
        return False
    return any(pat.search(bucket_url) for pat in WHITELIST_PATTERNS)
