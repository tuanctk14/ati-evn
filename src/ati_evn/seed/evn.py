"""Seed EVN corporate + 11 subsidiaries + a mixed IT/ICS asset inventory.

Structure mirrors the real Vietnam Electricity (EVN) group:
- EVN (parent, corporate holding)
- 3 regional power corporations: NPC, CPC, SPC
- 2 city power companies: EVN HANOI, EVN HCMC
- 3 generation corporations: GENCO1, GENCO2, GENCO3
- EVNNPT (National Power Transmission)
- NPCC (National Power Control Center / dispatch, aka "A0")
- EVNEPS (Electrical Power Services / EPS — engineering & construction arm)

Idempotent: looked up by Customer.name before insert, so rerunning is a no-op.
"""
from __future__ import annotations

import logging
from collections import Counter

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import AssetType, Customer, CustomerAsset, DeviceType, NetworkSegment

logger = logging.getLogger("ati_evn.seed.evn")


# ── Customers ────────────────────────────────────────────────────────────────

SUBSIDIARIES = [
    {
        "name": "EVN Northern Power Corporation",
        "short_code": "EVNNPC",
        "primary_domain": "npc.evn.com.vn",
    },
    {
        "name": "EVN Central Power Corporation",
        "short_code": "EVNCPC",
        "primary_domain": "cpc.evn.vn",
    },
    {
        "name": "EVN Southern Power Corporation",
        "short_code": "EVNSPC",
        "primary_domain": "evnspc.vn",
    },
    {
        "name": "EVN Hanoi Power Corporation",
        "short_code": "EVNHANOI",
        "primary_domain": "evnhanoi.vn",
    },
    {
        "name": "EVN Ho Chi Minh City Power Corporation",
        "short_code": "EVNHCMC",
        "primary_domain": "evnhcmc.vn",
    },
    {
        "name": "EVN Generation Corporation 1",
        "short_code": "EVNGENCO1",
        "primary_domain": None,
    },
    {
        "name": "EVN Generation Corporation 2",
        "short_code": "EVNGENCO2",
        "primary_domain": None,
    },
    {
        "name": "EVN Generation Corporation 3",
        "short_code": "EVNGENCO3",
        "primary_domain": "genco3.vn",
    },
    {
        "name": "EVN National Power Transmission Corporation",
        "short_code": "EVNNPT",
        "primary_domain": "npt.com.vn",
    },
    {
        "name": "National Power Control Center",
        "short_code": "NPCC",
        "primary_domain": None,
    },
    {
        "name": "EVN Electrical Power Services Corporation",
        "short_code": "EVNEPS",
        "primary_domain": None,
    },
]


# ── Assets per subsidiary (short_code -> list of asset dicts) ────────────────
# Each dict maps directly onto CustomerAsset columns.

def _match_asset(asset_type: AssetType, value: str, criticality: str = "medium",
                  is_internet_facing: bool = False) -> dict:
    return {
        "asset_type": asset_type,
        "asset_value": value,
        "criticality": criticality,
        "is_internet_facing": is_internet_facing,
        "discovery_source": "seed",
        "confidence": 1.0,
    }


def _device_asset(
    value: str, device_type: DeviceType, vendor: str, product: str, version: str,
    is_ics: bool, network_segment: NetworkSegment, criticality: str,
    is_internet_facing: bool = False,
) -> dict:
    return {
        "asset_type": AssetType.DEVICE,
        "asset_value": value,
        "criticality": criticality,
        "device_type": device_type,
        "vendor": vendor,
        "product": product,
        "version": version,
        "is_ics": is_ics,
        "is_internet_facing": is_internet_facing,
        "network_segment": network_segment,
        "discovery_source": "seed",
        "confidence": 1.0,
    }


ASSETS_BY_CODE: dict[str, list[dict]] = {
    "EVN": [
        _match_asset(AssetType.DOMAIN, "evn.com.vn", "high", True),
        _match_asset(AssetType.BRAND_NAME, "Vietnam Electricity", "medium"),
        _match_asset(AssetType.KEYWORD, "EVN", "low"),
        _device_asset(
            "evn-web-dmz-01", DeviceType.SERVER, "vmware", "esxi", "7.0",
            False, NetworkSegment.DMZ, "high", True,
        ),
    ],
    "EVNNPC": [
        _match_asset(AssetType.DOMAIN, "npc.evn.com.vn", "high", True),
        _match_asset(AssetType.IP, "14.161.10.20", "medium", True),
        _device_asset(
            "npc-fw-edge-01", DeviceType.FIREWALL, "fortinet", "fortios", "7.2.4",
            False, NetworkSegment.DMZ, "high", True,
        ),
        _device_asset(
            "npc-scada-hmi-01", DeviceType.HMI, "siemens", "simatic s7-1200", "4.5.2",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "EVNCPC": [
        _match_asset(AssetType.DOMAIN, "cpc.evn.vn", "high", True),
        _match_asset(AssetType.CIDR, "203.113.128.0/24", "medium"),
        _device_asset(
            "cpc-adc-plc-01", DeviceType.PLC, "schneider", "modicon m340", "2.9",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
    ],
    "EVNSPC": [
        _match_asset(AssetType.DOMAIN, "evnspc.vn", "high", True),
        _match_asset(AssetType.SUBDOMAIN, "portal.evnspc.vn", "medium", True),
        _device_asset(
            "spc-core-sw-01", DeviceType.NETWORK_SWITCH, "cisco", "ios", "15.9",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        _device_asset(
            "spc-rtu-district-04", DeviceType.RTU, "abb", "rtu560", "12.0",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
    ],
    "EVNHANOI": [
        _match_asset(AssetType.DOMAIN, "evnhanoi.vn", "high", True),
        _match_asset(AssetType.EMAIL_DOMAIN, "evnhanoi.vn", "medium"),
        _device_asset(
            "hnoi-win-dc-01", DeviceType.SERVER, "microsoft", "windows server", "2019",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
    ],
    "EVNHCMC": [
        _match_asset(AssetType.DOMAIN, "evnhcmc.vn", "high", True),
        _match_asset(AssetType.IP, "115.78.9.40", "medium", True),
        _device_asset(
            "hcmc-scada-srv-01", DeviceType.SCADA_SERVER, "ge", "cimplicity", "11.1",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "EVNGENCO1": [
        _match_asset(AssetType.KEYWORD, "GENCO1", "low"),
        _match_asset(AssetType.BRAND_NAME, "EVNGENCO1", "medium"),
        _device_asset(
            "genco1-eng-ws-01", DeviceType.ENGINEERING_WORKSTATION,
            "rockwell", "controllogix 1756", "33.0",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "EVNGENCO2": [
        _match_asset(AssetType.KEYWORD, "GENCO2", "low"),
        _match_asset(AssetType.ORG_NAME, "EVN Generation Corporation 2", "medium"),
        _device_asset(
            "genco2-historian-01", DeviceType.HISTORIAN, "osisoft", "pi server", "2018",
            True, NetworkSegment.OT_CORPORATE, "high",
        ),
    ],
    "EVNGENCO3": [
        _match_asset(AssetType.DOMAIN, "genco3.vn", "high", True),
        _match_asset(AssetType.IP, "125.235.20.5", "medium", True),
        _device_asset(
            "genco3-plc-turbine-02", DeviceType.PLC, "siemens", "simatic s7-1200", "4.4.0",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
    ],
    "EVNNPT": [
        _match_asset(AssetType.DOMAIN, "npt.com.vn", "high", True),
        _match_asset(AssetType.CIDR, "203.162.21.0/24", "medium"),
        _device_asset(
            "npt-fw-edge-01", DeviceType.FIREWALL, "fortinet", "fortios", "7.2.4",
            False, NetworkSegment.DMZ, "high", True,
        ),
        _device_asset(
            "npt-substation-rtu-11", DeviceType.RTU, "abb", "rtu560", "12.0",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
    ],
    "NPCC": [
        _match_asset(AssetType.KEYWORD, "A0 dispatch center", "low"),
        _match_asset(AssetType.ORG_NAME, "National Power Control Center", "high"),
        _device_asset(
            "npcc-scada-srv-a0", DeviceType.SCADA_SERVER, "ge", "cimplicity", "11.1",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "EVNEPS": [
        _match_asset(AssetType.DOMAIN, "evneps.vn", "medium", True),
        _match_asset(AssetType.BRAND_NAME, "EVNEPS", "low"),
        _device_asset(
            "eps-win-srv-01", DeviceType.SERVER, "microsoft", "windows server", "2019",
            False, NetworkSegment.INTERNAL_IT, "medium",
        ),
    ],
}


async def _get_or_none(session: AsyncSession, name: str) -> Customer | None:
    result = await session.execute(select(Customer).where(Customer.name == name))
    return result.scalar_one_or_none()


async def seed_evn(session: AsyncSession) -> None:
    """Idempotent seed: EVN + 11 subsidiaries + mixed IT/ICS asset inventory."""
    created_customers = 0
    created_assets = 0

    evn = await _get_or_none(session, "Vietnam Electricity (EVN)")
    if evn is None:
        evn = Customer(
            name="Vietnam Electricity (EVN)",
            short_code="EVN",
            parent_id=None,
            industry="electric_utility",
            tier="critical",
            primary_domain="evn.com.vn",
            onboarding_state="monitoring",
        )
        session.add(evn)
        await session.flush()
        created_customers += 1
        logger.info("Created customer: %s", evn.name)
    else:
        logger.info("Customer already exists: %s", evn.name)

    for row in SUBSIDIARIES:
        existing = await _get_or_none(session, row["name"])
        if existing is not None:
            logger.info("Customer already exists: %s", row["name"])
            continue
        sub = Customer(
            name=row["name"],
            short_code=row["short_code"],
            parent_id=evn.id,
            industry="electric_utility",
            tier="critical",
            primary_domain=row["primary_domain"],
            onboarding_state="monitoring",
        )
        session.add(sub)
        created_customers += 1
        logger.info("Created customer: %s", row["name"])

    await session.flush()

    # Re-fetch full customer set so we have IDs for both EVN and subsidiaries.
    all_customers_result = await session.execute(select(Customer))
    customers_by_code = {c.short_code: c for c in all_customers_result.scalars().all() if c.short_code}

    for short_code, asset_rows in ASSETS_BY_CODE.items():
        customer = customers_by_code.get(short_code)
        if customer is None:
            logger.warning("No customer found for short_code=%s — skipping its assets", short_code)
            continue

        existing_result = await session.execute(
            select(CustomerAsset.asset_value).where(CustomerAsset.customer_id == customer.id)
        )
        existing_values = {v for (v,) in existing_result.all()}

        for asset_row in asset_rows:
            if asset_row["asset_value"] in existing_values:
                continue
            asset = CustomerAsset(customer_id=customer.id, **asset_row)
            session.add(asset)
            created_assets += 1

    await session.flush()

    # ── Summary ──────────────────────────────────────────────────────────────
    total_customers_result = await session.execute(select(Customer))
    total_customers = len(total_customers_result.scalars().all())

    total_assets_result = await session.execute(select(CustomerAsset))
    all_assets = total_assets_result.scalars().all()
    total_assets = len(all_assets)

    by_type = Counter(a.asset_type.value for a in all_assets)
    ics_count = sum(1 for a in all_assets if a.is_ics)

    if created_customers == 0 and created_assets == 0:
        print("no changes (seed already applied)")
    print(f"{total_customers} customers, {total_assets} assets")
    print(f"By asset_type : {dict(by_type)}")
    print(f"is_ics=True   : {ics_count}")
