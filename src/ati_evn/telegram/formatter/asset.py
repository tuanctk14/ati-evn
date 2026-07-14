"""Format CustomerAsset detail -> Bot 2 /asset response."""
from __future__ import annotations


def format_asset_detail(asset, customer, finding_count) -> str:
    customer_name = customer.name if customer else f"Customer#{asset.customer_id}"

    lines = [
        f"🖥️ Asset #{asset.id} — {asset.asset_value}",
        "",
        f"Customer: {customer_name}",
        f"Type: {asset.asset_type.value}",
    ]

    if asset.vendor or asset.product:
        vp = " / ".join(x for x in (asset.vendor, asset.product) if x)
        version = f" v{asset.version}" if asset.version else ""
        lines.append(f"Vendor/Product: {vp}{version}")

    lines += [
        f"Criticality: {asset.criticality}",
        f"Device type: {asset.device_type.value if asset.device_type else '-'}",
        f"Network segment: {asset.network_segment.value if asset.network_segment else '-'}",
        f"is_ics: {asset.is_ics}",
        f"is_internet_facing: {asset.is_internet_facing}",
        f"IP address: {asset.ip_address or '-'}",
        f"Discovery source: {asset.discovery_source or '-'}",
        "",
        f"Open findings on this asset: {finding_count}",
    ]

    return "\n".join(lines)
