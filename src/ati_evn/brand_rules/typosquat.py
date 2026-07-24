"""Levenshtein-distance typosquat detection against EVN's real domains."""
from __future__ import annotations


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                prev[j] + 1,        # deletion
                curr[j - 1] + 1,    # insertion
                prev[j - 1] + cost,  # substitution
            )
        prev = curr
    return prev[-1]


def closest_distance(domain: str, known_domains: list[str]) -> int | None:
    """Smallest edit distance between `domain` and any of `known_domains`.

    Returns None if known_domains is empty or domain equals a known
    domain exactly (not a typosquat -- it's the real thing).
    """
    domain = domain.lower().strip()
    if not domain or not known_domains:
        return None

    best: int | None = None
    for known in known_domains:
        known = known.lower().strip()
        if not known or domain == known:
            return None
        dist = levenshtein(domain, known)
        if best is None or dist < best:
            best = dist
    return best


def is_typosquat(domain: str, known_domains: list[str], max_distance: int) -> tuple[bool, int | None]:
    dist = closest_distance(domain, known_domains)
    if dist is None:
        return False, None
    return dist <= max_distance, dist
