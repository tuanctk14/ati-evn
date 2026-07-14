"""/update_asset <id> [--vendor=X] [--product=Y] [--version=Z] [--value=V]
                [--device-type=DT] [--network-segment=NS] [--criticality=X]
                [--is-ics=true|false] [--is-internet-facing=true|false]
                [--notes=X]

Match-affecting fields (vendor/product/version/is_internet_facing) trigger
an auto-rescan (fire-and-forget) after commit.
"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import Customer, CustomerAsset, DeviceType, NetworkSegment
from ati_evn.db.session import async_session
from ati_evn.rescan import trigger_rescan_background
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()

MATCH_AFFECTING = {"vendor", "product", "version", "is_internet_facing"}


@router.message(Command("update_asset"))
@log_command("update_asset")
async def cmd_update_asset(message: Message):
    args = parse_args(message.text or "", "update_asset")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer(
            "Cú pháp: /update_asset <id> [--vendor=X] [--product=Y] "
            "[--version=Z] [--value=V] [--device-type=DT] "
            "[--network-segment=NS] [--criticality=X] [--is-ics=true|false] "
            "[--is-internet-facing=true|false] [--notes=X]"
        )
        return
    try:
        asset_id = int(pos[0])
    except ValueError:
        await message.answer(f"asset_id không hợp lệ: {pos[0]}")
        return

    async with async_session() as session:
        asset = await session.get(CustomerAsset, asset_id)
        if not asset:
            await message.answer(f"Không tìm thấy Asset #{asset_id}")
            return
        if asset.deleted_at:
            await message.answer(f"Asset #{asset_id} đang bị soft-delete. Restore trước khi update.")
            return
        customer = await session.get(Customer, asset.customer_id)
        if customer and customer.deleted_at:
            await message.answer(
                f"Customer của asset #{asset_id} đang bị soft-delete. "
                f"Restore customer trước."
            )
            return

        changes: dict[str, tuple] = {}

        new_vendor = args.get("vendor")
        if new_vendor and new_vendor != asset.vendor:
            changes["vendor"] = (asset.vendor, new_vendor)
            asset.vendor = new_vendor

        new_product = args.get("product")
        if new_product and new_product != asset.product:
            changes["product"] = (asset.product, new_product)
            asset.product = new_product

        new_version = args.get("version")
        if new_version and new_version != asset.version:
            changes["version"] = (asset.version, new_version)
            asset.version = new_version

        new_value = args.get("value")
        if new_value and new_value != asset.asset_value:
            changes["asset_value"] = (asset.asset_value, new_value)
            asset.asset_value = new_value

        new_device_type = args.get("device-type")
        if new_device_type:
            try:
                dt = DeviceType(new_device_type.lower())
            except ValueError:
                await message.answer(f"device_type không hợp lệ: {new_device_type}")
                return
            if dt != asset.device_type:
                changes["device_type"] = (
                    asset.device_type.value if asset.device_type else None, dt.value,
                )
                asset.device_type = dt

        new_network_segment = args.get("network-segment")
        if new_network_segment:
            try:
                ns = NetworkSegment(new_network_segment.lower())
            except ValueError:
                await message.answer(f"network_segment không hợp lệ: {new_network_segment}")
                return
            if ns != asset.network_segment:
                changes["network_segment"] = (
                    asset.network_segment.value if asset.network_segment else None, ns.value,
                )
                asset.network_segment = ns

        new_criticality = args.get("criticality")
        if new_criticality and new_criticality.lower() != asset.criticality:
            changes["criticality"] = (asset.criticality, new_criticality.lower())
            asset.criticality = new_criticality.lower()

        new_is_ics = args.get("is-ics")
        if new_is_ics is not None:
            ics_bool = str(new_is_ics).lower() in ("true", "1", "yes")
            if ics_bool != asset.is_ics:
                changes["is_ics"] = (asset.is_ics, ics_bool)
                asset.is_ics = ics_bool

        new_internet_facing = args.get("is-internet-facing")
        if new_internet_facing is not None:
            facing_bool = str(new_internet_facing).lower() in ("true", "1", "yes")
            if facing_bool != asset.is_internet_facing:
                changes["is_internet_facing"] = (asset.is_internet_facing, facing_bool)
                asset.is_internet_facing = facing_bool

        new_notes = args.get("notes")
        if new_notes is not None and new_notes != asset.notes:
            changes["notes"] = (asset.notes, new_notes)
            asset.notes = new_notes

        if not changes:
            await message.answer("Không có thay đổi.")
            return

        await session.commit()
        asset_id_final = asset.id
        vendor_for_rescan = (asset.vendor or "").lower() if asset.vendor else None

    changes_str = "\n".join(f"  {k}: {v[0]} → {v[1]}" for k, v in changes.items())
    reply = f"✅ Asset #{asset_id_final} updated:\n{changes_str}"

    if changes.keys() & MATCH_AFFECTING:
        trigger_rescan_background(
            reason=f"/update_asset #{asset_id_final} — {sorted(changes.keys() & MATCH_AFFECTING)}",
            focus_vendor=vendor_for_rescan,
            bot=message.bot,
            chat_id=message.chat.id,
        )
        reply += "\n\n🔍 Rescan đã queue (do vendor/product/version thay đổi)."

    await message.answer(reply)
