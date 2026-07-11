"""Add a new CustomerAsset and trigger a rescan (blocking, for CLI use).

Usage:
    python scripts/add_asset.py --customer "EVN NPT" --type device \\
        --vendor Siemens --product "SIMATIC S7-1500" \\
        --version 4.5.2 --device-type plc --network-segment ot_control \\
        --criticality critical --is-ics
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from sqlalchemy import select

from ati_evn.db.models import AssetType, Customer, CustomerAsset, DeviceType, NetworkSegment
from ati_evn.db.session import async_session
from ati_evn.rescan import run_rescan_sync


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--customer", required=True, help="Customer name (exact or substring match).")
    parser.add_argument("--type", dest="asset_type", required=True,
                         choices=[e.value for e in AssetType], help="AssetType value.")
    parser.add_argument("--value", default=None,
                         help="asset_value (hostname/IP/domain/etc). Defaults to vendor+product for devices.")
    parser.add_argument("--vendor", default=None)
    parser.add_argument("--product", default=None)
    parser.add_argument("--version", default=None)
    parser.add_argument("--ip-address", default=None)
    parser.add_argument("--device-type", default=None, choices=[e.value for e in DeviceType])
    parser.add_argument("--network-segment", default=None, choices=[e.value for e in NetworkSegment])
    parser.add_argument("--criticality", default="medium", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--is-ics", action="store_true")
    parser.add_argument("--is-internet-facing", action="store_true")
    parser.add_argument("--no-rescan", action="store_true", help="Skip the auto-rescan after adding.")
    return parser.parse_args()


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    args = parse_args()

    asset_value = args.value or f"{args.vendor or ''} {args.product or ''}".strip() or "unnamed-asset"

    async with async_session() as session:
        result = await session.execute(
            select(Customer).where(Customer.name.ilike(f"%{args.customer}%"))
        )
        customer = result.scalars().first()
        if customer is None:
            print(f"ERROR: no customer matching {args.customer!r} found.")
            return 2

        asset = CustomerAsset(
            customer_id=customer.id,
            asset_type=AssetType(args.asset_type),
            asset_value=asset_value,
            criticality=args.criticality,
            device_type=DeviceType(args.device_type) if args.device_type else None,
            vendor=args.vendor.lower() if args.vendor else None,
            product=args.product.lower() if args.product else None,
            version=args.version,
            ip_address=args.ip_address,
            is_ics=args.is_ics,
            is_internet_facing=args.is_internet_facing,
            network_segment=NetworkSegment(args.network_segment) if args.network_segment else None,
            discovery_source="manual",
            confidence=1.0,
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        print(f"Asset added: id={asset.id} customer={customer.name!r} value={asset_value!r}")

        if args.no_rescan:
            return 0

        focus_vendor = args.vendor.lower() if args.vendor else None
        print(f"Starting rescan (focus vendor: {focus_vendor})...")

    stats = await run_rescan_sync(reason="asset_added", focus_vendor=focus_vendor)

    print("\n=== RescanStats ===")
    print(f"candidate_cves_for_llm : {stats.candidate_cves_for_llm}")
    print(f"llm_calls              : {stats.llm_calls}")
    print(f"llm_extracted          : {stats.llm_extracted}")
    print(f"elapsed_seconds        : {stats.elapsed_seconds:.1f}")
    print(f"matcher.findings_created            : {stats.matcher.findings_created}")
    print(f"matcher.findings_merged             : {stats.matcher.findings_merged}")
    print(f"matcher.probable_exposures_created  : {stats.matcher.probable_exposures_created}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
