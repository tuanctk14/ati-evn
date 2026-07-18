"""/scan_censys command — on-demand external exposure scan.

Usage:
  /scan_censys --ip=203.113.128.5
  /scan_censys --cidr=203.113.128.0/28   # small chunk, capped hosts
  /scan_censys --asn=149069              # NOT available on this tier —
                                          # returns a clear message instead
                                          # of silently doing nothing.

Optional:
  --auto-discover=<customer_id_or_name>
    If an IP isn't in inventory, create an asset for this customer with
    discovery_source='censys'.

Note: bulk ASN search requires an organization-scoped Censys key (see
external/censys_client.py docstring) — this account's key only supports
per-host lookups, so --asn is not implemented as a real scan and
--cidr works by looking up each address in the range individually.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.external.censys_client import (
    CensysConfigError,
    CensysNotAvailable,
    CensysQuotaExceeded,
    search_asn,
    search_cidr,
    search_ip,
)
from ati_evn.external.exposure_ingest import upsert_exposures
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.scan_censys")
router = Router()


@router.message(Command("scan_censys"))
@log_command("scan_censys")
async def cmd_scan_censys(message: Message):
    args = parse_args(message.text or "", "scan_censys")
    settings = get_settings()

    asn = args.get("asn")
    ip = args.get("ip")
    cidr = args.get("cidr")
    auto_discover = args.get("auto-discover")

    if not asn and not ip and not cidr:
        await message.answer(
            "Cú pháp: /scan_censys --ip=X | --cidr=X | --asn=X\n"
            "[--auto-discover=<customer_id_or_name>]\n\n"
            "Lưu ý: --asn hiện KHÔNG khả dụng (free tier key không có "
            "quyền search/query). Dùng --ip hoặc --cidr (range nhỏ)."
        )
        return

    auto_discover_customer_id: int | None = None
    if auto_discover:
        async with async_session() as session:
            try:
                cust_id = int(auto_discover)
                cust = await session.get(Customer, cust_id)
                if cust and not cust.deleted_at:
                    auto_discover_customer_id = cust_id
            except ValueError:
                row = await session.execute(
                    select(Customer.id)
                    .where(customer_name_or_code_match(auto_discover))
                    .limit(1)
                )
                r = row.scalar_one_or_none()
                if r:
                    auto_discover_customer_id = r
        if not auto_discover_customer_id:
            await message.answer(f"⚠️ --auto-discover='{auto_discover}' không match customer nào.")
            return

    scope_desc = f"ASN {asn}" if asn else f"IP {ip}" if ip else f"CIDR {cidr}"
    thinking = await message.answer(
        f"🔎 Đang scan Censys — scope: {scope_desc}\n"
        f"Max: {settings.censys_max_hosts_per_scan} hosts\n"
        f"⏳ Có thể mất 5-60s..."
    )
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    try:
        if asn:
            exposures = await search_asn(asn)
        elif ip:
            exposures = await search_ip(ip)
        else:
            exposures = await search_cidr(cidr, max_hosts=settings.censys_max_hosts_per_scan)
    except CensysConfigError as e:
        await thinking.delete()
        await message.answer(
            f"⚠️ Censys config lỗi: {e}\nKiểm tra CENSYS_API_KEY trong .env."
        )
        return
    except CensysQuotaExceeded as e:
        await thinking.delete()
        await message.answer(f"⚠️ Censys quota vượt limit: {str(e)[:200]}")
        return
    except CensysNotAvailable as e:
        await thinking.delete()
        await message.answer(f"ℹ️ {e}")
        return
    except ValueError as e:
        await thinking.delete()
        await message.answer(f"⚠️ {e}")
        return
    except Exception as e:
        await thinking.delete()
        logger.exception("Censys scan error: %s", e)
        await message.answer(f"⚠️ Scan lỗi: {str(e)[:200]}")
        return

    await thinking.delete()

    if not exposures:
        await message.answer(
            f"📭 Không có service internet-facing nào cho {scope_desc}.\n"
            f"Có thể IP/range không có service mở, hoặc chưa được Censys quét."
        )
        return

    stats = await upsert_exposures(exposures, auto_discover_customer_id=auto_discover_customer_id)

    lines = [
        f"✅ Scan Censys hoàn tất — scope: {scope_desc}",
        "",
        f"Exposures found: {len(exposures)}",
        f"  New: {stats['new']}",
        f"  Updated: {stats['updated']}",
        "Attribution:",
        f"  Matched to asset: {stats['attributed']}",
        f"  Orphan (no asset match): {stats['orphan']}",
    ]
    lines.append("")
    lines.append("Rule engine + Finding creation: slice 9B (chưa implement).")
    lines.append("Xem raw exposures qua SQL:")
    lines.append(
        "  SELECT ip, port, service_name, product, version, "
        "customer_id FROM exposures ORDER BY id DESC LIMIT 20;"
    )

    await message.answer("\n".join(lines))
