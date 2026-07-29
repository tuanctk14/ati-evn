"""Small helpers for filter-common expressions."""
from sqlalchemy import or_

from ati_evn.db.models import Customer, CustomerAsset, Detection, Finding, ThreatIndicator


def only_live_customer():
    return Customer.deleted_at.is_(None)


def customer_name_or_code_match(query: str):
    """Return SQLAlchemy expression matching Customer.name OR
    Customer.short_code with case-insensitive substring.

    Analysts and the agent frequently use abbreviations ("EVN NPC")
    that aren't substrings of the full legal name ("EVN Northern Power
    Corporation") but ARE substrings of short_code ("EVNNPC") — matching
    both avoids the agent burning tool calls guessing name variants.
    """
    pattern = f"%{query.strip()}%"
    return or_(
        Customer.name.ilike(pattern),
        Customer.short_code.ilike(pattern),
    )


def only_live_asset():
    return CustomerAsset.deleted_at.is_(None)


def only_live_detection():
    return Detection.deleted_at.is_(None)


def cve_only_filter():
    """Standard filter for "current findings" queries (slice 15B).

    After the Finding/ThreatIndicator split, Finding rows are either:
      1. CVE findings (ioc_type='cve_id') -- active, full lifecycle
      2. Legacy non-CVE findings (ioc_type!='cve_id') -- migrated to
         ThreatIndicator, kept only for historical trace via
         metadata['migrated_to_ti_id']; still tagged ioc_type for
         that reason, but should never surface in "what's open" views.

    Apply this to every Finding query that represents "current
    findings the analyst should look at" -- NOT to the migration
    script itself (which needs to see non-CVE rows) or anything that
    intentionally wants the historical/legacy view.
    """
    return Finding.ioc_type == "cve_id"


def ti_default_status_filter():
    """Default ThreatIndicator status filter (slice 15C).

    Excludes stale (past TTL, auto-marked by ti_ttl_worker.enforce_ttl)
    and archived (stale > 30d) -- those are only surfaced when the
    caller explicitly asks for that status. Active + acknowledged are
    what "what's currently relevant" queries should show by default.
    """
    return ThreatIndicator.status.in_(["active", "acknowledged"])
