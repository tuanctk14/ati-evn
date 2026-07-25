"""Base adapter interface -- 3-layer architecture (slice 13C).

ProviderSignal: adapter output. Data only, NO scoring.
ProviderVerdict: ScoringEngine output. Verdict + score for consumers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

Verdict = Literal["benign", "suspicious", "malicious", "unknown"]


@dataclass
class ProviderSignal:
    """Adapter output. Raw+normalized data from provider.

    Adapter's ONLY responsibility: fetch + extract fields. No verdict
    determination, no scoring -- those belong to ScoringEngine.
    """
    provider: str
    signals: dict = field(default_factory=dict)
    # Provider-specific normalized signals, e.g.
    #   AbuseIPDB: {abuse_confidence: 20, total_reports: 37}
    #   VirusTotal: {malicious_engines: 4, suspicious_engines: 0,
    #                total_engines: 91, reputation: -10}
    #   OTX: {pulse_count: 50, reputation: 0}
    #   Pulsedive: {risk_level: "critical", threat_count: 3, feed_count: 8}
    #   LeakIX: {services_count: 0, leaks_count: 0,
    #            malicious_event_types_count: 0}
    country: Optional[str] = None
    isp: Optional[str] = None
    raw_data: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class ProviderVerdict:
    """ScoringEngine output. Score + verdict for downstream consumers
    (DB storage, Bot 2 display, agent tools, aggregate service).

    Note: normalized_score comes from ScoringEngine, NOT the adapter.
    """
    provider: str
    verdict: Verdict
    confidence: float
    normalized_score: float          # 0-100, from ScoringEngine
    signals: dict = field(default_factory=dict)
    # Preserved for A/B test + debug (recompute if policy changes)
    country: Optional[str] = None
    isp: Optional[str] = None
    raw_data: dict = field(default_factory=dict)
    error: Optional[str] = None


class BaseIpAdapter:
    """Base class. Provider adapters return ProviderSignal only."""
    provider_name: str = "base"

    async def fetch(self, ip: str) -> ProviderSignal:
        """Fetch + normalize to ProviderSignal. No scoring."""
        raise NotImplementedError

    def _mk_error(self, error_msg: str) -> ProviderSignal:
        return ProviderSignal(
            provider=self.provider_name,
            signals={},
            error=error_msg,
        )
