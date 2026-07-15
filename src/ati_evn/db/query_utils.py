"""Small helpers for filter-common expressions."""
from sqlalchemy import or_

from ati_evn.db.models import Customer, CustomerAsset, Detection


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
