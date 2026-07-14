"""/add_asset --customer=X --type=T [--vendor=V] [--product=P]
              [--version=Ver] [--device-type=DT] [--network-segment=NS]
              [--criticality=X] [--is-ics] [--is-internet-facing]
              [--value=V]  (for ip/domain/keyword types)

After insert: fire-and-forget rescan (asyncio.create_task).
Bot 1 will dispatch alerts for newly-matched findings.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import AssetType, Customer, CustomerAsset, DeviceType, NetworkSegment
from ati_evn.db.session import async_session
from ati_evn.rescan import trigger_rescan_background
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.add_asset")
router = Router()


@router.message(Command("add_asset"))
@log_command("add_asset")
async def cmd_add_asset(message: Message):
    args = parse_args(message.text or "", "add_asset")
    customer_name = args.get("customer")
    asset_type_str = args.get("type")
    if not customer_name or not asset_type_str:
        await message.answer(
            "Cú pháp: /add_asset --customer=X --type=T [--vendor=V] "
            "[--product=P] [--version=Ver] [--device-type=DT] "
            "[--network-segment=NS] [--criticality=X] [--is-ics] "
            "[--is-internet-facing] [--value=V]"
        )
        return

    try:
        asset_type = AssetType(asset_type_str.lower())
    except ValueError:
        await message.answer(
            f"asset_type không hợp lệ: {asset_type_str}\n"
            f"Valid: {[t.value for t in AssetType]}"
        )
        return

    device_type = None
    if args.get("device-type"):
        try:
            device_type = DeviceType(args["device-type"].lower())
        except ValueError:
            await message.answer(f"device_type không hợp lệ: {args['device-type']}")
            return

    network_segment = None
    if args.get("network-segment"):
        try:
            network_segment = NetworkSegment(args["network-segment"].lower())
        except ValueError:
            await message.answer(f"network_segment không hợp lệ: {args['network-segment']}")
            return

    vendor = args.get("vendor")
    product = args.get("product")
    version = args.get("version")
    asset_value = args.get("value")
    if not asset_value:
        if asset_type == AssetType.DEVICE and vendor and product:
            asset_value = f"{vendor.lower()} {product.lower()}"
        else:
            await message.answer(
                "Cần --value= cho asset_type=ip/cidr/domain/keyword/... "
                "hoặc --vendor+--product cho type=device"
            )
            return

    async with async_session() as session:
        cr = await session.execute(
            select(Customer).where(Customer.name == customer_name)
        )
        customer = cr.scalar_one_or_none()
        if not customer:
            await message.answer(f"Customer '{customer_name}' không tồn tại.")
            return
        if customer.deleted_at:
            await message.answer(
                f"Customer '{customer.name}' đang bị soft-delete. "
                f"Restore trước khi add asset."
            )
            return
        cust_id, cust_name = customer.id, customer.name

        asset = CustomerAsset(
            customer_id=cust_id,
            asset_type=asset_type,
            asset_value=asset_value,
            vendor=vendor,
            product=product,
            version=version,
            device_type=device_type,
            network_segment=network_segment,
            criticality=(args.get("criticality") or "medium").lower(),
            is_ics=bool(args.get("is-ics")),
            is_internet_facing=bool(args.get("is-internet-facing")),
            discovery_source="manual_telegram",
        )
        session.add(asset)
        await session.commit()

        reply = (
            f"✅ Asset #{asset.id} đã tạo cho {cust_name}:\n"
            f"  Type: {asset_type.value}\n"
            f"  Value: {asset_value}\n"
        )
        if vendor and product:
            reply += f"  Vendor/Product: {vendor} / {product}\n"
        if version:
            reply += f"  Version: {version}\n"

    focus_vendor = vendor.lower() if vendor else None
    trigger_rescan_background(
        reason=f"add_asset via Telegram — asset#{asset.id}",
        focus_vendor=focus_vendor,
        bot=message.bot,
        chat_id=message.chat.id,
    )

    reply += (
        f"\n🔍 Rescan đã queue (focus_vendor={focus_vendor}). "
        f"Sẽ báo kết quả ở đây khi quét xong (kể cả khi không có match mới)."
    )
    await message.answer(reply)
