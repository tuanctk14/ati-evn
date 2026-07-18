"""Bot 1 campaign alert dispatch — direct send (bypasses alert_queue).

Sends via TELEGRAM_ALERT_BOT_TOKEN when campaign confidence >= 0.75.
"""
import logging

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError

from ati_evn.config import get_settings
from ati_evn.db.models import Campaign, Customer
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.campaigns.notify")

CONFIDENCE_THRESHOLD = 0.75

# Kill chain phase display order (MITRE Enterprise order)
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _sort_tactics(tactics: list[str]) -> list[str]:
    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    return sorted(tactics, key=lambda t: order.get(t, 999))


def format_campaign_alert(campaign: Campaign, customer: Customer) -> str:
    tactics_sorted = _sort_tactics(campaign.tactic_ids or [])
    tactics_arrow = " → ".join(tactics_sorted) if tactics_sorted else "-"
    sev_str = " · ".join(
        f"{v} {k}" for k, v in
        sorted((campaign.severities or {}).items(),
               key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                              "LOW": 3}.get(x[0], 9))
    )
    span_hours = (
        (campaign.window_end - campaign.window_start).total_seconds() / 3600
    )
    return (
        f"🎯 Campaign Candidate #{campaign.id} — {customer.name}\n"
        f"{campaign.finding_count} findings ({sev_str}) trong "
        f"{span_hours:.1f}h window\n"
        f"Kill chain: {tactics_arrow}\n"
        f"Techniques: {', '.join((campaign.technique_ids or [])[:6])}"
        f"{'…' if len(campaign.technique_ids or []) > 6 else ''}\n"
        f"Assets: {campaign.asset_count} · "
        f"Sources: {', '.join(campaign.source_ids or [])}\n"
        f"Confidence: {campaign.confidence:.2f}\n"
        f"Reason: {campaign.detection_reason}\n\n"
        f"Xem chi tiết trong @ATIEVNBOT:\n"
        f"  /campaign {campaign.id}\n"
        f"  /confirm_campaign {campaign.id} --notes=X\n"
        f"  /reject_campaign {campaign.id} --reason=X"
    )


async def dispatch_campaign_alerts_if_high(campaign_ids: list[int]) -> int:
    """Send Telegram alert for each campaign in campaign_ids where
    confidence >= threshold. Return count dispatched."""
    if not campaign_ids:
        return 0

    settings = get_settings()
    if not settings.telegram_alert_bot_token or not settings.telegram_alert_chat_id:
        logger.warning("Alert bot token/chat_id missing — skip campaign dispatch")
        return 0

    dispatched = 0
    bot = Bot(token=settings.telegram_alert_bot_token)
    try:
        async with async_session() as session:
            for cid in campaign_ids:
                campaign = await session.get(Campaign, cid)
                if not campaign:
                    continue
                if campaign.confidence < CONFIDENCE_THRESHOLD:
                    continue
                customer = await session.get(Customer, campaign.customer_id)
                if not customer:
                    continue
                text = format_campaign_alert(campaign, customer)
                try:
                    await bot.send_message(
                        settings.telegram_alert_chat_id, text,
                        disable_web_page_preview=True,
                    )
                    dispatched += 1
                    logger.info("Campaign #%d alert dispatched", cid)
                except TelegramAPIError as e:
                    logger.error("Campaign #%d alert failed: %s", cid, e)
    finally:
        await bot.session.close()

    return dispatched
