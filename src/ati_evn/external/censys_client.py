"""Thin wrapper around the Censys Platform API (v3).

The project's CENSYS_API_KEY is a single bearer token for Censys's newer
Platform API (https://api.platform.censys.io), not the legacy Search API
v2 api_id/api_secret pair the `censys` PyPI SDK expects. This account
tier also does NOT have search/query access (POST /v3/global/search/query
returns 403 "requires an organization ID — free users only access through
the Platform UI") — confirmed against the real key during development.

What IS available and verified working: per-host lookup,
GET /v3/global/asset/host/{ip}, which returns the full service list for
a single IP. So this client only supports single-IP lookups; ASN-wide
search is not offered (see search_asn below), and CIDR scanning is done
by expanding the range into individual IPs and looking each one up.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings

logger = logging.getLogger("ati_evn.external.censys")

PLATFORM_BASE_URL = "https://api.platform.censys.io/v3"
REQUEST_TIMEOUT = 30.0


class CensysConfigError(Exception):
    pass


class CensysQuotaExceeded(Exception):
    pass


class CensysNotAvailable(Exception):
    """Raised for operations this account tier can't perform (e.g. ASN-wide
    search, which needs an organization-scoped key)."""


def _auth_headers() -> dict:
    settings = get_settings()
    if not settings.censys_api_key:
        raise CensysConfigError("CENSYS_API_KEY must be set in .env")
    return {"Authorization": f"Bearer {settings.censys_api_key}"}


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=10),
    retry=retry_if_exception_type(httpx.TransportError),
    reraise=True,
)
def _get_host(ip: str) -> dict:
    """Sync call — GET /v3/global/asset/host/{ip}. Wrapped in
    asyncio.to_thread by the async callers below."""
    headers = _auth_headers()
    url = f"{PLATFORM_BASE_URL}/global/asset/host/{ip}"
    resp = httpx.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

    if resp.status_code == 401:
        raise CensysConfigError(f"Censys API key rejected (401): {resp.text[:200]}")
    if resp.status_code == 429:
        raise CensysQuotaExceeded(f"Censys rate limit / quota exceeded (429): {resp.text[:200]}")
    if resp.status_code == 422:
        # Invalid IP format — not a transport error, don't retry
        raise ValueError(f"Invalid IP for Censys lookup: {ip} ({resp.text[:200]})")
    resp.raise_for_status()
    return resp.json()


def _normalize_host(raw_resource: dict) -> list[dict]:
    """Flatten one Censys host resource into a list of exposure dicts,
    one per service. See module docstring for the real Platform API v3
    response shape (verified against live API responses)."""
    out = []
    ip = raw_resource.get("ip") or ""
    as_info = raw_resource.get("autonomous_system") or {}
    asn = str(as_info.get("asn") or "") or None
    asn_org = as_info.get("name") or as_info.get("description")
    country = (raw_resource.get("location") or {}).get("country")

    for svc in raw_resource.get("services") or []:
        port = svc.get("port")
        svc_name = (svc.get("protocol") or "").lower() or None
        transport = (svc.get("transport_protocol") or "").lower() or None
        scan_time = svc.get("scan_time")

        product = version = vendor = None
        sw_list = svc.get("software") or []
        if sw_list:
            sw = sw_list[0]
            product = sw.get("product")
            version = sw.get("version")
            vendor = sw.get("vendor")

        banner = ""
        for ep in svc.get("endpoints") or []:
            http = ep.get("http") or {}
            server_hdr = (http.get("headers") or {}).get("Server", {}).get("headers") or []
            if server_hdr:
                banner = server_hdr[0]
                break
        if len(banner) > 2000:
            banner = banner[:2000]

        tls = svc.get("tls") or {}
        tls_enabled = bool(tls)
        tls_version = tls.get("version_selected") or tls.get("version")
        tls_self_signed = False
        tls_expired = False
        chain = tls.get("presented_chain") or []
        if chain:
            leaf = chain[0]
            iss = leaf.get("issuer_dn") or ""
            subj = leaf.get("subject_dn") or ""
            tls_self_signed = bool(iss and subj and iss == subj)

        caps: dict = {}
        auth_required = None
        for ep in svc.get("endpoints") or []:
            http = ep.get("http") or {}
            status = http.get("status_code")
            if status is not None:
                caps["http.status_code"] = status
        if svc.get("labels"):
            caps["labels"] = [lab.get("value") for lab in svc["labels"] if lab.get("value")]

        out.append({
            "ip": ip,
            "port": port,
            "service_name": svc_name,
            "transport": transport,
            "product": product,
            "version": version,
            "vendor": vendor,
            "banner": banner,
            "tls_enabled": tls_enabled,
            "tls_version": tls_version,
            "tls_expired": tls_expired,
            "tls_self_signed": tls_self_signed,
            "auth_required": auth_required,
            "capabilities": caps,
            "asn": asn,
            "asn_organization": asn_org,
            "country": country,
            "last_seen_censys": scan_time,
            "raw_service": svc,
        })
    return out


async def search_ip(ip: str) -> list[dict]:
    """Look up a single host by IP. Returns a flat list of exposure dicts
    (one per open service), or [] if the host has no observed services."""
    data = await asyncio.to_thread(_get_host, ip)
    resource = (data.get("result") or {}).get("resource") or {}
    return _normalize_host(resource)


async def search_cidr(cidr: str, max_hosts: int | None = None) -> list[dict]:
    """Expand a CIDR into individual IPs and look each one up.

    There is no bulk/CIDR search endpoint available on this account tier
    (see module docstring), so this issues one host lookup per address,
    capped at `max_hosts` (defaults to settings.censys_max_hosts_per_scan).
    """
    settings = get_settings()
    cap = max_hosts or settings.censys_max_hosts_per_scan
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR: {cidr}") from e

    hosts = list(net.hosts()) or list(net)  # net.hosts() is empty for /31, /32
    hosts = hosts[:cap]

    all_exposures: list[dict] = []
    for host in hosts:
        try:
            data = await asyncio.to_thread(_get_host, str(host))
        except ValueError:
            continue
        resource = (data.get("result") or {}).get("resource") or {}
        all_exposures.extend(_normalize_host(resource))

    logger.info(
        "Censys CIDR scan %s: %d IPs queried, %d exposures normalized",
        cidr, len(hosts), len(all_exposures),
    )
    return all_exposures


async def search_asn(asn: str, max_pages: int = 2) -> list[dict]:
    """Not available on this account tier.

    Bulk ASN search requires POST /v3/global/search/query, which this
    key cannot access (403: "requires an organization ID — free users
    only access through the Platform UI" — verified against the real
    key during development). Raises CensysNotAvailable so callers can
    show a clear message instead of silently returning nothing.
    """
    raise CensysNotAvailable(
        "Quét theo ASN cần quyền search/query (organization-scoped key), "
        "không khả dụng với free tier hiện tại. Dùng --ip=<IP cụ thể> "
        "hoặc --cidr=<range nhỏ> thay thế."
    )
