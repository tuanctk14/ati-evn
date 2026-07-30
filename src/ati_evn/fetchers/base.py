"""Fetcher abstractions.

Every collector — CVE or IOC — subclasses IOCFetcher and returns list[RawIOC].
The ingest pipeline is the sole consumer; fetchers never touch the DB directly.
This makes fetchers unit-testable with plain HTTP mocks and lets us swap
scheduler or transport without rewriting collector code.
"""
from __future__ import annotations

import abc
from datetime import datetime
from typing import Any, Optional

import httpx
from pydantic import BaseModel, Field
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings

_RETRY_TRANSIENT = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)


@_RETRY_TRANSIENT
async def _retried_request(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
    return await client.request(method, url, **kwargs)


class RawIOC(BaseModel):
    """Normalized IOC record emitted by a fetcher. This is the pipeline's input contract."""
    source: str                              # collector name, e.g. "threatfox"
    ioc_type: str                            # canonical: ipv4, ipv6, domain, url, sha256, md5, sha1, cve_id, email
    ioc_value: str                           # normalized lowercase, no whitespace
    raw_text: Optional[str] = None           # context: description, malware name, tag, etc.
    severity_hint: Optional[str] = None      # collector's guess: INFO/LOW/MEDIUM/HIGH/CRITICAL
    first_seen: Optional[datetime] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FetchResult(BaseModel):
    """Summary of a single fetcher run."""
    fetcher: str
    ok: bool
    count: int = 0
    error: Optional[str] = None
    skipped_reason: Optional[str] = None
    duration_ms: float = 0.0


class IOCFetcher(abc.ABC):
    """Abstract base for all fetchers.

    Subclass contract
    -----------------
    - `name` : short identifier used as Detection.source and in logs.
    - `requires_auth` : True if the collector needs an API key to function.
    - `is_configured()` : return False if required credentials are missing;
      the runner will skip cleanly instead of raising.
    - `fetch(since_hours)` : return list[RawIOC]. Should not raise on network
      errors — catch and return empty list with logging.
    """

    name: str = ""
    ioc_type_default: str = ""
    requires_auth: bool = False

    def __init__(self) -> None:
        self.settings = get_settings()

    def is_configured(self) -> bool:
        """Override in subclasses that require an API key."""
        return True

    @abc.abstractmethod
    async def fetch(self, since_hours: int = 24) -> list[RawIOC]:
        """Fetch IOCs. Return [] on error rather than raising."""
        raise NotImplementedError

    # ── HTTP helpers ─────────────────────────────────────────────────────────

    def _http_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"User-Agent": self.settings.user_agent, "Accept": "application/json"}
        if extra:
            headers.update(extra)
        return headers

    async def _http_client(self, extra_headers: dict[str, str] | None = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.settings.http_timeout_seconds,
            headers=self._http_headers(extra_headers),
            follow_redirects=True,
        )

    async def _get(self, client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
        """GET through `client`, retrying transient network errors (not HTTP status errors)."""
        return await _retried_request(client, "GET", url, **kwargs)

    async def _post(self, client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
        """POST through `client`, retrying transient network errors (not HTTP status errors)."""
        return await _retried_request(client, "POST", url, **kwargs)
