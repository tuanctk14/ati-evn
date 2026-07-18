from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command, CommandStart
from aiogram.types import Message

from ati_evn.telegram.audit import log_command

router = Router()

WELCOME = """👋 Chào analyst!

Đây là ATI-EVN Analyst Command Bot.

Nhóm lệnh chính:
  /finding <id>       Chi tiết Finding
  /cve <CVE-ID>       Chi tiết CVE + ATT&CK context
  /rule <CVE-ID>      Sigma rule cho CVE
  /playbook <id>      Response playbook
  /stats              Dashboard tổng quan
  /list_open          Danh sách Finding open

Gõ /help <lệnh> để xem cú pháp chi tiết.
Gõ /help all để xem toàn bộ lệnh.
"""

HELP_ALL = """📖 Toàn bộ lệnh:

QUERY (chỉ đọc):
  /start /help /finding /cve /ioc /asset /customer
  /stats /list_open /list_alerts

RULES + CONTENT:
  /rule <CVE-ID> [--regen] [--aql]
  /playbook <CVE-ID | finding_id>
  /export <type> [flags]

CREATE:
  /add_customer --name=X [--parent=Y] [--domain=Z] [--tier=X]
  /add_asset --customer=X --type=T [--vendor=V] [--product=P] ...
  /add_ioc --type=T --value=V [--severity=X] [--expire=Nd] [--note=X] [--malware=X]

UPDATE:
  /update_customer <id|name> [--name=X] [--parent=Y] [--domain=Z] ...
  /update_asset <id> [--vendor=X] [--product=Y] [--version=Z] ...
  /update_ioc <detection_id> [--severity=X] [--expire=Nd] [--note=X]

DELETE (soft) + RESTORE:
  /delete_customer <id|name> --confirm="<full_name>"
  /delete_asset <id> --confirm
  /delete_ioc <detection_id> --confirm
  /restore_customer <id|name> [--with-assets]
  /restore_asset <id>
  /restore_ioc <detection_id>

ACTIONS:
  /ack <alert_id> [--note=X]
  /close <finding_id> --reason=X
  /mark_fp <finding_id> [--all-assets] [--reason=X]
  /reopen <finding_id> --reason=X
  /silence <finding_id> --hours=N
  /rescan [--customer=X] [--asset=id]

Free-text query (slice 5B.3):
  Gõ câu hỏi tự nhiên → agent xử lý.
  Action bắt buộc dùng command.
"""

HELP_DETAIL = {
    "finding": "/finding <id>\n\nXem chi tiết Finding: customer, asset, severity, match reason, sources, ATT&CK context, mitigations.\n\nVí dụ: /finding 12847",
    "cve": "/cve <CVE-ID>\n\nXem chi tiết CVE: description, CVSS, CWE, ATT&CK techniques, mitigations, product mapping.\n\nVí dụ: /cve CVE-2024-12345",
    "ioc": "/ioc <value>\n\nXem chi tiết IOC (IP/domain/hash): feed sources, first/last seen, related Findings.\n\nVí dụ: /ioc 1.2.3.4\n       /ioc example.com",
    "asset": "/asset <id>\n\nXem chi tiết CustomerAsset.\n\nVí dụ: /asset 42",
    "customer": "/customer <name|id>\n\nXem chi tiết customer.\n\nVí dụ: /customer NPC\n       /customer 3",
    "stats": "/stats\n\nDashboard tổng quan: finding counts, alert stats, top ATT&CK, top vendors.",
    "list_open": "/list_open [flags]\n\nDanh sách Finding open.\nFlags:\n  --severity=HIGH|MEDIUM|LOW|CRITICAL\n  --customer=<name>\n  --limit=<N> (default 10)\n  --page=<N> (default 1)\n\nVí dụ: /list_open --severity=HIGH --limit=5",
    "list_alerts": "/list_alerts [flags]\n\nDanh sách alert đã dispatch.\nFlags:\n  --recent=24h|1h|7d\n  --customer=<name>\n  --state=dispatched|failed|deduped",
    "rule": "/rule <CVE-ID> [--regen] [--aql]\n\nTìm Sigma rule cho CVE (community trực tiếp → community theo ATT&CK → AI generate). --regen ép AI tạo mới. --aql xuất kèm QRadar AQL nếu có.\n\nVí dụ: /rule CVE-2024-12345\n       /rule CVE-2024-12345 --regen --aql",
    "playbook": "/playbook <CVE-ID | finding_id>\n\nSinh NIST 800-61 playbook (Identification/Containment/Eradication/Recovery/Lessons Learned). Cache theo (cve_id, network_segment).\n\nVí dụ: /playbook CVE-2024-12345\n       /playbook 12847",
    "export": "/export <type> [flags]\n\nTypes: findings | alerts | assets | ioc_summary | weekly_report\nFlags:\n  --customer=<name>\n  --since=7d|24h\n  --format=csv|json|md|pdf\n  --limit=<N> (findings/alerts)\n\nVí dụ: /export findings --limit=20 --format=csv\n       /export weekly_report --format=pdf",
    "add_customer": "/add_customer --name=X [--parent=Y] [--domain=Z] [--short-code=X] [--tier=critical|high|medium]\n\nVí dụ: /add_customer --name=\"EVN TEST\" --tier=high",
    "add_asset": "/add_asset --customer=X --type=T [--vendor=V] [--product=P] [--version=Ver] [--device-type=DT] [--network-segment=NS] [--criticality=X] [--is-ics] [--is-internet-facing] [--value=V]\n\nTự động trigger rescan sau khi thêm.\n\nVí dụ: /add_asset --customer=\"EVN NPC\" --type=device --vendor=Fortinet --product=FortiOS --version=7.2.4",
    "add_ioc": "/add_ioc --type=T --value=V [--severity=X] [--note=N] [--expire=Nd] [--malware=X]\n\nThêm IOC nội bộ (source=internal), chạy matcher ngay. --malware gắn tên họ malware (VD: Emotet, Cobalt Strike) để enrichment tra ATT&CK technique thật từ MITRE S-series thay vì heuristic chung.\n\nVí dụ: /add_ioc --type=ipv4 --value=192.0.2.1 --severity=HIGH --expire=30d\n       /add_ioc --type=domain --value=evil.tld --malware=\"Cobalt Strike\"",
    "ack": "/ack <alert_id> [--note=X]\n\nAcknowledge một alert.\n\nVí dụ: /ack 42",
    "close": "/close <finding_id> --reason=X\n\nĐóng Finding với lý do.\n\nVí dụ: /close 12847 --reason=\"Patched\"",
    "mark_fp": "/mark_fp <finding_id> [--all-assets] [--reason=X]\n\nMark Finding là false positive. Mặc định chỉ scope 1 asset; --all-assets áp dụng cho toàn bộ asset của customer.\n\nVí dụ: /mark_fp 12847 --reason=\"Known benign\"",
    "reopen": "/reopen <finding_id> --reason=X\n\nMở lại Finding đã đóng.\n\nVí dụ: /reopen 12847 --reason=\"Recurred\"",
    "rescan": "/rescan [--customer=X] [--asset=id]\n\nTrigger rescan bất đồng bộ toàn hệ thống (hoặc scope hẹp hơn).\n\nVí dụ: /rescan",
    "silence": "/silence <finding_id> --hours=N\n\nTạm ngưng alert dispatch cho Finding trong N giờ (1-720).\n\nVí dụ: /silence 12847 --hours=24",
    "update_customer": "/update_customer <id|name> [--name=X] [--parent=Y] [--domain=Z] [--tier=X] [--short-code=X] [--active=true|false]\n\nCập nhật thông tin customer. Chỉ hiển thị field nào thực sự thay đổi.\n\nVí dụ: /update_customer \"EVN NPC\" --tier=critical",
    "update_asset": "/update_asset <id> [--vendor=X] [--product=Y] [--version=Z] [--value=V] [--device-type=DT] [--network-segment=NS] [--criticality=X] [--is-ics=true|false] [--is-internet-facing=true|false] [--notes=X]\n\nCập nhật asset. Nếu vendor/product/version/is-internet-facing thay đổi, tự động trigger rescan.\n\nVí dụ: /update_asset 42 --version=7.2.5 --criticality=critical",
    "update_ioc": "/update_ioc <detection_id> [--severity=X] [--expire=Nd|clear] [--note=X]\n\nChỉ update được IOC source=internal. Nếu đổi severity, Finding liên quan (chưa đóng/FP/expired) cũng được cập nhật theo.\n\nVí dụ: /update_ioc 501 --severity=CRITICAL",
    "delete_customer": "/delete_customer <id|name> --confirm=\"<full_name>\"\n\nSoft-delete customer + cascade toàn bộ asset còn active của customer đó. --confirm phải khớp CHÍNH XÁC tên hiện tại (case-sensitive).\n\nVí dụ: /delete_customer \"TEST_CORP\" --confirm=\"TEST_CORP\"",
    "delete_asset": "/delete_asset <id> --confirm\n\nSoft-delete asset. Finding liên quan vẫn giữ nguyên.\n\nVí dụ: /delete_asset 42 --confirm",
    "delete_ioc": "/delete_ioc <detection_id> --confirm [--acknowledge-findings]\n\nSoft-delete IOC nội bộ (chỉ source=internal). Nếu có Finding liên quan, cần thêm --acknowledge-findings.\n\nVí dụ: /delete_ioc 501 --confirm --acknowledge-findings",
    "restore_customer": "/restore_customer <id|name> [--with-assets]\n\nKhôi phục customer đã soft-delete. Mặc định KHÔNG khôi phục asset kèm theo — dùng --with-assets để khôi phục luôn asset bị cascade-delete.\n\nVí dụ: /restore_customer \"TEST_CORP\" --with-assets",
    "restore_asset": "/restore_asset <id>\n\nKhôi phục asset đã soft-delete (customer phải đang active). Tự động trigger rescan.\n\nVí dụ: /restore_asset 42",
    "restore_ioc": "/restore_ioc <detection_id>\n\nKhôi phục IOC nội bộ đã soft-delete, reset status=NEW và chạy lại matcher cho riêng IOC đó.\n\nVí dụ: /restore_ioc 501",
}


@router.message(CommandStart())
@log_command("start")
async def cmd_start(message: Message):
    await message.answer(WELCOME)


@router.message(Command("help"))
@log_command("help")
async def cmd_help(message: Message):
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(WELCOME)
        return
    topic = parts[1].strip().lower()
    if topic in ("all", "tất cả"):
        await message.answer(HELP_ALL)
        return
    if topic in HELP_DETAIL:
        await message.answer(HELP_DETAIL[topic])
        return
    await message.answer(f"Không có help cho `{topic}`. Gõ /help all để xem list.")
