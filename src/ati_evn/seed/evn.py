"""Seed EVN corporate + 11 subsidiaries + a mixed IT/ICS asset inventory.

Structure mirrors the real Vietnam Electricity (EVN) group:
- EVN (parent, corporate holding)
- 3 regional power corporations: NPC, CPC, SPC
- 2 city power companies: EVN HANOI, EVN HCMC
- 3 generation corporations: GENCO1, GENCO2, GENCO3
- EVNNPT (National Power Transmission)
- NPCC (National Power Control Center / dispatch, aka "A0")
- EVNEPS (Electrical Power Services / EPS — engineering & construction arm)

Every device row carries its own ip_address (in addition to vendor/product/
version/device_type/network_segment/is_ics) so the asset inventory reads
like a real CMDB rather than a bag of loose IP/domain match strings. IT and
OT devices are both represented per subsidiary, on IP ranges that reflect
their Purdue level (DMZ/internal_it on the office LAN, ot_control/ot_process
on a separate private range) — this is deliberately simplified (real EVN
segmentation would use many more VLANs) but keeps the seed readable.

Some device products/versions are chosen to line up with real CVEs already
present in cve_product_map (fetched live from NVD) — e.g. an asset running
"pan-os" 10.2.3 sits inside a real PAN-OS CVE's vulnerable version_range —
so the slice-3 matcher has genuine data to exercise instead of 0 findings.
This is documented inline per row where it applies; nothing here is
fabricated CVE data — the CVE rows themselves come only from the NVD fetcher.

Idempotent: looked up by Customer.name / CustomerAsset.asset_value before
insert, so rerunning is a no-op.
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


# ── Asset row builders ────────────────────────────────────────────────────────

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
    hostname: str, ip_address: str, device_type: DeviceType, vendor: str, product: str, version: str,
    is_ics: bool, network_segment: NetworkSegment, criticality: str,
    is_internet_facing: bool = False,
) -> dict:
    return {
        "asset_type": AssetType.DEVICE,
        "asset_value": hostname,
        "ip_address": ip_address,
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


# ── Assets per subsidiary (short_code -> list of asset dicts) ────────────────
# Each subsidiary gets: match-surface rows (domain/keyword/brand/CIDR) plus a
# realistic IT + OT device set. Product strings for devices chosen to overlap
# real cve_product_map rows use the raw CPE-style token (e.g. "sql_server_2019",
# "pan-os") because match_cve_product() does plain substring containment with
# no snake_case normalization — human-readable names would silently not match.

ASSETS_BY_CODE: dict[str, list[dict]] = {
    "EVN": [
        _match_asset(AssetType.DOMAIN, "evn.com.vn", "high", True),
        _match_asset(AssetType.BRAND_NAME, "Vietnam Electricity", "medium"),
        _match_asset(AssetType.KEYWORD, "EVN", "low"),
        # IT — corporate HQ, DMZ + internal LAN
        _device_asset(
            "evn-web-dmz-01", "203.113.100.10", DeviceType.SERVER, "vmware", "esxi", "7.0",
            False, NetworkSegment.DMZ, "high", True,
        ),
        # SQL Server 2019 vulnerable range: >=15.0.2000.5, <15.0.2160.4 (real NVD CVE)
        _device_asset(
            "evn-sql-corp-01", "10.10.1.11", DeviceType.SERVER, "microsoft", "sql_server_2019", "15.0.2100.0",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        # windows: matching CVEs carry no version_range in NVD -> ProbableExposure, not Finding.
        _device_asset(
            "evn-win-corp-01", "10.10.1.12", DeviceType.SERVER, "microsoft", "windows", "server_2019",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        _device_asset(
            "evn-ws-hr-01", "10.10.2.21", DeviceType.WORKSTATION, "microsoft", "windows", "11",
            False, NetworkSegment.INTERNAL_IT, "low",
        ),
    ],
    "EVNNPC": [
        _match_asset(AssetType.DOMAIN, "npc.evn.com.vn", "high", True),
        _match_asset(AssetType.IP, "14.161.10.20", "medium", True),
        # IT
        _device_asset(
            "npc-fw-edge-01", "14.161.10.1", DeviceType.FIREWALL, "fortinet", "fortios", "7.2.4",
            False, NetworkSegment.DMZ, "high", True,
        ),
        # pan-os vulnerable range: >=10.2.0, <10.2.7 (real NVD CVE) — DMZ secondary firewall.
        _device_asset(
            "npc-fw-pa-01", "14.161.10.2", DeviceType.FIREWALL, "paloaltonetworks", "pan-os", "10.2.3",
            False, NetworkSegment.DMZ, "critical", True,
        ),
        # openssh vulnerable range: <10.4 (real NVD CVE) — jump host into OT network.
        _device_asset(
            "npc-jump-openssh-01", "10.20.1.5", DeviceType.SERVER, "openbsd", "openssh", "9.6",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        # OT — distribution SCADA
        _device_asset(
            "npc-scada-hmi-01", "10.20.2.10", DeviceType.HMI, "siemens", "simatic s7-1200", "4.5.2",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
        _device_asset(
            "npc-rtu-substation-07", "10.20.3.7", DeviceType.RTU, "abb", "rtu560", "12.0",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
    ],
    "EVNCPC": [
        _match_asset(AssetType.DOMAIN, "cpc.evn.vn", "high", True),
        _match_asset(AssetType.CIDR, "203.113.128.0/24", "medium"),
        # IT
        # mariadb vulnerable range: >=10.6.1, <10.6.26 (real NVD CVE)
        _device_asset(
            "cpc-db-maria-01", "10.11.1.15", DeviceType.SERVER, "mariadb", "mariadb", "10.6.20",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        # apache cxf vulnerable range: <3.6.11 (real NVD CVE)
        _device_asset(
            "cpc-app-cxf-01", "10.11.1.16", DeviceType.SERVER, "apache", "cxf", "3.6.5",
            False, NetworkSegment.INTERNAL_IT, "medium",
        ),
        # OT — distribution
        _device_asset(
            "cpc-adc-plc-01", "10.21.2.4", DeviceType.PLC, "schneider", "modicon m340", "2.9",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
        _device_asset(
            "cpc-scada-hmi-01", "10.21.1.9", DeviceType.HMI, "siemens", "simatic s7-1200", "4.5.2",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "EVNSPC": [
        _match_asset(AssetType.DOMAIN, "evnspc.vn", "high", True),
        _match_asset(AssetType.SUBDOMAIN, "portal.evnspc.vn", "medium", True),
        # IT
        _device_asset(
            "spc-core-sw-01", "10.12.1.2", DeviceType.NETWORK_SWITCH, "cisco", "ios", "15.9",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        # apache tomcat vulnerable range: <9.0.119 (real NVD CVE) — customer portal, DMZ-facing.
        _device_asset(
            "spc-app-tomcat-01", "203.113.129.20", DeviceType.SERVER, "apache", "tomcat", "9.0.90",
            False, NetworkSegment.DMZ, "high", True,
        ),
        # Patched instance — NOT vulnerable (past the fixed version <9.0.119) — exercises exclusion path.
        _device_asset(
            "spc-app-tomcat-02", "10.12.1.20", DeviceType.SERVER, "apache", "tomcat", "9.0.120",
            False, NetworkSegment.INTERNAL_IT, "medium",
        ),
        # OT — distribution
        _device_asset(
            "spc-rtu-district-04", "10.22.3.4", DeviceType.RTU, "abb", "rtu560", "12.0",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
    ],
    "EVNHANOI": [
        _match_asset(AssetType.DOMAIN, "evnhanoi.vn", "high", True),
        _match_asset(AssetType.EMAIL_DOMAIN, "evnhanoi.vn", "medium"),
        # IT
        _device_asset(
            "hnoi-win-dc-01", "10.13.1.10", DeviceType.SERVER, "microsoft", "windows server", "2019",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        # mozilla firefox — several real NVD CVEs with ranges like "<115.37.0", this version is inside.
        _device_asset(
            "hnoi-ws-firefox-01", "10.13.2.31", DeviceType.WORKSTATION, "mozilla", "firefox", "115.20.0",
            False, NetworkSegment.INTERNAL_IT, "medium",
        ),
        # OT — city distribution SCADA
        _device_asset(
            "hnoi-scada-hmi-01", "10.23.1.6", DeviceType.HMI, "ge", "cimplicity", "11.1",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "EVNHCMC": [
        _match_asset(AssetType.DOMAIN, "evnhcmc.vn", "high", True),
        _match_asset(AssetType.IP, "115.78.9.40", "medium", True),
        # IT
        # wireshark vulnerable range: >=4.4.0, <4.4.17 (real NVD CVE) — used by NOC engineers.
        _device_asset(
            "hcmc-eng-wireshark-01", "10.14.2.40", DeviceType.ENGINEERING_WORKSTATION,
            "wireshark", "wireshark", "4.4.10",
            False, NetworkSegment.INTERNAL_IT, "medium",
        ),
        # OT — city distribution SCADA
        _device_asset(
            "hcmc-scada-srv-01", "10.24.1.8", DeviceType.SCADA_SERVER, "ge", "cimplicity", "11.1",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "EVNGENCO1": [
        _match_asset(AssetType.KEYWORD, "GENCO1", "low"),
        _match_asset(AssetType.BRAND_NAME, "EVNGENCO1", "medium"),
        # OT — generation plant control
        _device_asset(
            "genco1-eng-ws-01", "10.25.2.12", DeviceType.ENGINEERING_WORKSTATION,
            "rockwell", "controllogix 1756", "33.0",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
        # nozominetworks guardian — ICS/OT network security monitoring appliance,
        # plausible at a generation plant. Vulnerable range: <26.2.0 (real NVD CVE).
        _device_asset(
            "genco1-ot-guardian-01", "10.25.1.5", DeviceType.OTHER, "nozominetworks", "guardian", "25.4.0",
            True, NetworkSegment.OT_CORPORATE, "critical",
        ),
        # IT — plant office network
        _device_asset(
            "genco1-fw-edge-01", "203.113.150.1", DeviceType.FIREWALL, "fortinet", "fortios", "7.0.12",
            False, NetworkSegment.DMZ, "high", True,
        ),
    ],
    "EVNGENCO2": [
        _match_asset(AssetType.KEYWORD, "GENCO2", "low"),
        _match_asset(AssetType.ORG_NAME, "EVN Generation Corporation 2", "medium"),
        # OT — generation plant
        _device_asset(
            "genco2-historian-01", "10.26.1.14", DeviceType.HISTORIAN, "osisoft", "pi server", "2018",
            True, NetworkSegment.OT_CORPORATE, "high",
        ),
        # nozominetworks cmc (Central Management Console) — same product family as GENCO1's
        # Guardian sensor. Vulnerable range: <26.2.0 (real NVD CVE).
        _device_asset(
            "genco2-ot-cmc-01", "10.26.1.6", DeviceType.OTHER, "nozominetworks", "cmc", "25.0.0",
            True, NetworkSegment.OT_CORPORATE, "critical",
        ),
    ],
    "EVNGENCO3": [
        _match_asset(AssetType.DOMAIN, "genco3.vn", "high", True),
        _match_asset(AssetType.IP, "125.235.20.5", "medium", True),
        # OT — turbine control
        _device_asset(
            "genco3-plc-turbine-02", "10.27.2.9", DeviceType.PLC, "siemens", "simatic s7-1200", "4.4.0",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
        # gridtime_3000_firmware — Microchip grid-timing appliance (GPS/PTP time sync for
        # substations), directly relevant to an electric utility. Vulnerable range:
        # >=1.0r0.03, <1.2r0.0 (real NVD CVE). NVD's "r0.0" build suffix isn't PEP440-
        # parseable, so this intentionally exercises 'unparseable' / ProbableExposure
        # rather than a confirmed Finding — documented here rather than miscounted as a bug.
        _device_asset(
            "genco3-gridtime-01", "10.27.1.3", DeviceType.OTHER, "microchip", "gridtime_3000_firmware",
            "1.1r0.05", True, NetworkSegment.OT_PROCESS, "critical",
        ),
    ],
    "EVNNPT": [
        _match_asset(AssetType.DOMAIN, "npt.com.vn", "high", True),
        _match_asset(AssetType.CIDR, "203.162.21.0/24", "medium"),
        # IT
        _device_asset(
            "npt-fw-edge-01", "203.162.21.1", DeviceType.FIREWALL, "fortinet", "fortios", "7.2.4",
            False, NetworkSegment.DMZ, "high", True,
        ),
        # cisco secure_endpoint vulnerable range: <1.27.2 (real NVD CVE) — EDR agent on
        # the transmission SOC management server.
        _device_asset(
            "npt-edr-secure-endpoint-01", "10.15.1.9", DeviceType.SERVER, "cisco", "secure_endpoint", "1.25.0",
            False, NetworkSegment.INTERNAL_IT, "high",
        ),
        # OT — transmission substations
        _device_asset(
            "npt-substation-rtu-11", "10.28.3.11", DeviceType.RTU, "abb", "rtu560", "12.0",
            True, NetworkSegment.OT_PROCESS, "critical",
        ),
        _device_asset(
            "npt-substation-hmi-11", "10.28.2.11", DeviceType.HMI, "ge", "cimplicity", "11.1",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
    ],
    "NPCC": [
        _match_asset(AssetType.KEYWORD, "A0 dispatch center", "low"),
        _match_asset(AssetType.ORG_NAME, "National Power Control Center", "high"),
        # OT — national dispatch center
        _device_asset(
            "npcc-scada-srv-a0", "10.29.1.2", DeviceType.SCADA_SERVER, "ge", "cimplicity", "11.1",
            True, NetworkSegment.OT_CONTROL, "critical",
        ),
        # grafana — dispatch center monitoring dashboards, plausible at A0.
        # Vulnerable range: <=11.6.14 (real NVD CVE).
        _device_asset(
            "npcc-monitor-grafana-01", "10.29.1.20", DeviceType.SERVER, "grafana", "grafana", "11.6.10",
            False, NetworkSegment.OT_CORPORATE, "high",
        ),
    ],
    "EVNEPS": [
        _match_asset(AssetType.DOMAIN, "evneps.vn", "medium", True),
        _match_asset(AssetType.BRAND_NAME, "EVNEPS", "low"),
        # IT — engineering & construction arm
        _device_asset(
            "eps-win-srv-01", "10.16.1.10", DeviceType.SERVER, "microsoft", "windows server", "2019",
            False, NetworkSegment.INTERNAL_IT, "medium",
        ),
        # gitlab — internal source control. Vulnerable range (widest): >=9.1.0, <18.11.7
        # (real NVD CVE).
        _device_asset(
            "eps-devops-gitlab-01", "10.16.1.30", DeviceType.SERVER, "gitlab", "gitlab", "17.5.0",
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
    by_vendor = Counter((a.vendor or "").lower() for a in all_assets if a.vendor)
    ics_count = sum(1 for a in all_assets if a.is_ics)
    device_with_ip = sum(1 for a in all_assets if a.asset_type == AssetType.DEVICE and a.ip_address)

    if created_customers == 0 and created_assets == 0:
        print("no changes (seed already applied)")
    print(f"{total_customers} customers, {total_assets} assets")
    print(f"By asset_type : {dict(by_type)}")
    print(f"By vendor     : {dict(by_vendor)}")
    print(f"is_ics=True   : {ics_count}")
    print(f"devices with ip_address: {device_with_ip}")
