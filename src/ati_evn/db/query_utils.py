"""Small helpers for filter-common expressions."""
from ati_evn.db.models import Customer, CustomerAsset, Detection


def only_live_customer():
    return Customer.deleted_at.is_(None)


def only_live_asset():
    return CustomerAsset.deleted_at.is_(None)


def only_live_detection():
    return Detection.deleted_at.is_(None)
