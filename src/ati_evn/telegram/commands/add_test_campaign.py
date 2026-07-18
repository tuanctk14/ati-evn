"""/add_test_campaign --customer=X --techniques=T1190,T1059,T1105
                      [--count=4] [--source-mix]

Creates N test IOCs for the same customer spread across N minutes,
each linked to a Detection with different source (nvd, threatfox,
internal) if --source-mix. All get attack_context with the specified
techniques.

Use case: verify Campaign detection algorithm (slice 6.2A) without
waiting for real attack data. Filter A (bulk-ingest) will NOT trigger
because findings are spread over minutes, not created bulk.

Test-only command — deliberately kept out of the Telegram command menu
(setMyCommands in bot_analyst.py). Analyst discovers it via /help.
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import (
    Customer,
    Detection,
    DetectionStatus,
    Finding,
    FindingStatus,
    Severity,
)
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.enrichment.attack_catalog import (
    get_mitigation_name,
    get_mitigations_for_technique,
    get_tactics_for_technique,
    get_technique_name,
)
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.add_test_campaign")
router = Router()


@router.message(Command("add_test_campaign"))
@log_command("add_test_campaign")
async def cmd_add_test_campaign(message: Message):
    args = parse_args(message.text or "", "add_test_campaign")
    customer_name = args.get("customer")
    techniques_str = args.get("techniques")
    count = int(args.get("count") or 4)
    source_mix = bool(args.get("source-mix"))

    if not customer_name or not techniques_str:
        await message.answer(
            "Cú pháp: /add_test_campaign --customer=X "
            "--techniques=T1190,T1059,T1105 [--count=4] [--source-mix]\n\n"
            "Tạo N test IOC + Finding cho customer với ATT&CK techniques "
            "chỉ định. Findings spread qua N phút để không trigger "
            "bulk-ingest filter."
        )
        return

    technique_ids = [t.strip().upper() for t in techniques_str.split(",") if t.strip()]
    if not technique_ids:
        await message.answer("--techniques rỗng.")
        return

    async with async_session() as session:
        cust_row = await session.execute(
            select(Customer).where(customer_name_or_code_match(customer_name)).limit(1)
        )
        customer = cust_row.scalar_one_or_none()
        if not customer:
            await message.answer(f"Customer '{customer_name}' không tìm thấy.")
            return

        who = message.from_user.username or str(message.from_user.id)
        source_pool = ["internal", "threatfox", "malwarebazaar", "urlhaus"] \
            if source_mix else ["internal"]

        # Build attack_context
        tactics = set()
        for tid in technique_ids:
            tactics.update(get_tactics_for_technique(tid))
        mitigation_ids = set()
        for tid in technique_ids:
            mitigation_ids.update(get_mitigations_for_technique(tid))
        ac = {
            "techniques": [
                {"id": tid, "name": get_technique_name(tid),
                 "confidence": 0.8, "source": "test_scenario"}
                for tid in technique_ids
            ],
            "cwe_ids": [],
            "kill_chain_phases": sorted(tactics),
            "mitigations": [
                {"id": mid, "name": get_mitigation_name(mid)}
                for mid in sorted(mitigation_ids)
            ],
            "smet_used": False,
            "chain_used": False,
            "test_scenario_used": True,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

        created_finding_ids = []
        base_time = datetime.now(timezone.utc)
        # Randomize the IP block so repeated invocations against the same
        # customer don't collide with Finding's (customer_id, ioc_type,
        # ioc_value) unique constraint from a prior test run.
        ip_base = random.randint(0, 250 - count)
        for i in range(count):
            # Spread findings a few minutes apart so filter A3 (bulk-ingest,
            # >=80% of a cluster created within +-60s of each other) never
            # fires on a deliberately-spread test scenario.
            offset_min = (count - i) * 3
            ts = base_time - timedelta(minutes=offset_min)
            src = source_pool[i % len(source_pool)]

            det = Detection(
                source=src,
                ioc_type="ipv4",
                ioc_value=f"192.0.2.{ip_base + i}",
                raw_text=f"Test campaign IOC #{i+1} for {customer.name}",
                severity=Severity.HIGH,
                status=DetectionStatus.ROUTED,
                metadata_={
                    "added_by": who,
                    "test_scenario": True,
                    **({"malware_printable": "Cobalt Strike"} if source_mix else {}),
                },
                created_at=ts,
            )
            session.add(det)
            await session.flush()

            fnd = Finding(
                customer_id=customer.id,
                ioc_type="ipv4",
                ioc_value=det.ioc_value,
                title=f"Test campaign finding for {customer.name}",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                matched_asset=f"test_asset_{i+1}",
                detection_reason="Test scenario for campaign detection",
                sources=[src],
                source_count=1,
                first_seen=ts,
                last_seen=ts,
                metadata_={"attack_context": ac, "test_scenario": True},
            )
            session.add(fnd)
            await session.flush()

            det.finding_id = fnd.id
            created_finding_ids.append(fnd.id)

        await session.commit()

    await message.answer(
        f"✅ Đã tạo {count} test finding cho {customer.name}\n"
        f"Finding IDs: {created_finding_ids}\n"
        f"Techniques: {technique_ids}\n"
        f"Sources: {'mixed' if source_mix else 'internal only'}\n"
        f"Spread: ~3-{count * 3} phút trước\n\n"
        f"Chạy detection: python scripts/run_campaign_detection.py"
    )
