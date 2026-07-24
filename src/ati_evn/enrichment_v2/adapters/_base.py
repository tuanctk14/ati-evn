"""Base adapter interface for IP enrichment providers.

ProviderVerdict is the normalized output -- provider-agnostic.
AggregateService in slice 13B operates only on this dataclass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

Verdict = Literal["benign", "suspicious", "malicious", "unknown"]


@dataclass
class ProviderVerdict:
    """Normalized output from any provider adapter."""
    provider: str
    normalized_score: float          # 0-100
    verdict: Verdict
    confidence: float                # 0-1
    country: Optional[str] = None
    isp: Optional[str] = None
    raw_data: dict = field(default_factory=dict)
    error: Optional[str] = None


class BaseIpAdapter:
    """Base class. Each provider adapter must set provider_name +
    implement fetch()."""
    provider_name: str = "base"

    async def fetch(self, ip: str) -> ProviderVerdict:
        """Fetch data + normalize to ProviderVerdict.

        On error: return ProviderVerdict with error field set,
        verdict='unknown', score=0.
        """
        raise NotImplementedError

    def _mk_error(self, error_msg: str) -> ProviderVerdict:
        """Helper: build error verdict."""
        return ProviderVerdict(
            provider=self.provider_name,
            normalized_score=0.0,
            verdict="unknown",
            confidence=0.0,
            error=error_msg,
        )
