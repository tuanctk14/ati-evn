"""Helpers for filtering test-scenario data out of production queries."""
import ipaddress
import logging

logger = logging.getLogger("ati_evn.db.query_utils_test")

# RFC 5737 documentation ranges -- never real
TEST_NET_RANGES = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]


def is_test_scenario(metadata: dict | None) -> bool:
    """True if finding/detection has test_scenario flag set."""
    return bool((metadata or {}).get("test_scenario"))


def is_test_ip(ip: str | None) -> bool:
    """True if IP is in RFC 5737 documentation range."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in TEST_NET_RANGES)


def is_test_finding(finding) -> bool:
    """Broader detection: is this Finding a test artifact?

    Checks multiple signals, since not every legacy test finding was
    created with the metadata_.test_scenario flag (that flag only
    exists on findings from /add_test_campaign, slice 6.2A+). Earlier
    test findings (e.g. slice 6.1 S-series attribution verification)
    predate that convention and must be caught by title/IOC pattern
    instead:
      a. metadata_.test_scenario = True (from /add_test_campaign)
      b. title starts with "Test finding" or contains "(slice 6.N)"
      c. IOC value is TEST-NET-1/2/3 IP or a test-*/*.tld/*.example
         placeholder domain

    Accepts a Finding ORM object (reads .metadata_, .title, .ioc_value).
    """
    if is_test_scenario(finding.metadata_):
        return True

    title = (finding.title or "").lower()
    if title.startswith("test finding"):
        return True
    if "(slice 6." in title:
        return True

    ioc = (finding.ioc_value or "").lower()
    if is_test_ip(ioc):
        return True
    if ioc.startswith("test-"):
        if any(ioc.endswith(sfx) for sfx in (".tld", ".example", ".local", ".test")):
            return True
    # non-"test-" prefixed placeholder domains (e.g. "emotet-c2.tld")
    if any(ioc.endswith(sfx) for sfx in (".tld", ".example")):
        return True

    return False
