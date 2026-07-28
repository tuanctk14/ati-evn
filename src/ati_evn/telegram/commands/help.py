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

CAMPAIGN:
  /campaign <id>
  /list_campaigns [--status=candidate|confirmed|rejected|expired] [--customer=X] [--limit=N] [--page=N]
  /confirm_campaign <id> [--notes=X]
  /reject_campaign <id> --reason=X
  /add_test_campaign --customer=X --techniques=T1,T2 [--count=N] [--source-mix]

INGESTION:
  /ingest <URL | text | PDF attachment>
  /list_ingests [--status=pending|confirmed|rejected|expired] [--limit=N] [--page=N]
  /confirm_ingest <session_id>
  /reject_ingest <session_id> [--reason=X]
  /edit_ingest <session_id> [--drop=1,3,5] [--drop-cves=2,4]

EXTERNAL MONITORING:
  /scan_censys --ip=X | --cidr=X [--auto-discover=customer]
                Quét external internet exposure qua Censys.
                --asn hiện chưa khả dụng (free tier).
  /scan_ghwarfare --keyword=X [--max=50]
                Kiểm tra lộ lọt tài liệu (public bucket) qua GrayHatWarfare.
  /scan_urlscan --keyword=X [--domain=Y] [--max=50]
                Kiểm tra brand abuse/impersonation qua urlscan.io.
  Truy vấn exposure/finding phát hiện qua rule engine — dùng free-text agent
  (VD: "Có exposure SSH nào không?"), không có command riêng.

ENRICHMENT (background, auto):
  /enrich_ip <ip> [--force] [--full]
                Fast: AbuseIPDB + VirusTotal. --full: + OTX/Pulsedive/LeakIX.
                Trả về aggregate_risk_score + confidence + coverage.

  Auto-backfill: every 15 min, 10 IPs x 5 providers per tick.
  Cache TTL: per-provider (24h hoặc 12h, xem enrichment_config.yaml).

REPORT:
  /generate_report [--window=7d] [--from=YYYY-MM-DD --to=YYYY-MM-DD]
                   [--format=html|pdf|both] [--customer=X]
  /list_reports [--limit=15] [--type=global|customer] [--customer=X]
  /download_report <id> [--format=html|pdf|both]

  Weekly global report auto-scheduled: Monday 06:00 UTC.

FETCHER (auto-scheduled):
  /force_fetch [--feed=nvd|threatfox|malwarebazaar|urlhaus|feodo|all]

Free-text query:
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
    "add_test_campaign": "/add_test_campaign --customer=X --techniques=T1190,T1059 [--count=4] [--source-mix]\n\nTạo test scenario để verify campaign detection algorithm. Chỉ dùng khi test — không dùng trong production.\n\nVí dụ: /add_test_campaign --customer=NPC --techniques=T1190,T1059,T1105 --count=4",
    "campaign": "/campaign <id>\n\nXem chi tiết Campaign — findings, kill chain, techniques, confidence breakdown.\n\nVí dụ: /campaign 12",
    "list_campaigns": "/list_campaigns [flags]\n\nFlags:\n  --status=candidate|confirmed|rejected|expired\n  --customer=<name|short_code>\n  --limit=<N> (default 10)\n  --page=<N> (default 1)",
    "confirm_campaign": "/confirm_campaign <id> [--notes=X]\n\nXác nhận Campaign candidate là attack thật.\nNotes tùy chọn — analyst có thể thêm context.",
    "reject_campaign": "/reject_campaign <id> --reason=X\n\nTừ chối Campaign candidate là false positive.\nReason bắt buộc.",
    "update_customer": "/update_customer <id|name> [--name=X] [--parent=Y] [--domain=Z] [--tier=X] [--short-code=X] [--active=true|false]\n\nCập nhật thông tin customer. Chỉ hiển thị field nào thực sự thay đổi.\n\nVí dụ: /update_customer \"EVN NPC\" --tier=critical",
    "update_asset": "/update_asset <id> [--vendor=X] [--product=Y] [--version=Z] [--value=V] [--device-type=DT] [--network-segment=NS] [--criticality=X] [--is-ics=true|false] [--is-internet-facing=true|false] [--notes=X]\n\nCập nhật asset. Nếu vendor/product/version/is-internet-facing thay đổi, tự động trigger rescan.\n\nVí dụ: /update_asset 42 --version=7.2.5 --criticality=critical",
    "update_ioc": "/update_ioc <detection_id> [--severity=X] [--expire=Nd|clear] [--note=X]\n\nChỉ update được IOC source=internal. Nếu đổi severity, Finding liên quan (chưa đóng/FP/expired) cũng được cập nhật theo.\n\nVí dụ: /update_ioc 501 --severity=CRITICAL",
    "delete_customer": "/delete_customer <id|name> --confirm=\"<full_name>\"\n\nSoft-delete customer + cascade toàn bộ asset còn active của customer đó. --confirm phải khớp CHÍNH XÁC tên hiện tại (case-sensitive).\n\nVí dụ: /delete_customer \"TEST_CORP\" --confirm=\"TEST_CORP\"",
    "delete_asset": "/delete_asset <id> --confirm\n\nSoft-delete asset. Finding liên quan vẫn giữ nguyên.\n\nVí dụ: /delete_asset 42 --confirm",
    "delete_ioc": "/delete_ioc <detection_id> --confirm [--acknowledge-findings]\n\nSoft-delete IOC nội bộ (chỉ source=internal). Nếu có Finding liên quan, cần thêm --acknowledge-findings.\n\nVí dụ: /delete_ioc 501 --confirm --acknowledge-findings",
    "restore_customer": "/restore_customer <id|name> [--with-assets]\n\nKhôi phục customer đã soft-delete. Mặc định KHÔNG khôi phục asset kèm theo — dùng --with-assets để khôi phục luôn asset bị cascade-delete.\n\nVí dụ: /restore_customer \"TEST_CORP\" --with-assets",
    "restore_asset": "/restore_asset <id>\n\nKhôi phục asset đã soft-delete (customer phải đang active). Tự động trigger rescan.\n\nVí dụ: /restore_asset 42",
    "restore_ioc": "/restore_ioc <detection_id>\n\nKhôi phục IOC nội bộ đã soft-delete, reset status=NEW và chạy lại matcher cho riêng IOC đó.\n\nVí dụ: /restore_ioc 501",
    "ingest": "/ingest <URL | text | PDF attachment>\n\nNhập bài báo/report để LLM trích xuất IOC/CVE/malware/ATT&CK. Trả về preview kèm session ID.\n\nVí dụ: /ingest https://example.com/article\n       /ingest <paste văn bản>\n       Attach PDF với caption /ingest",
    "list_ingests": "/list_ingests [flags]\n\nFlags:\n  --status=pending|confirmed|rejected|expired\n  --limit=<N> (default 10)\n  --page=<N> (default 1)",
    "confirm_ingest": "/confirm_ingest <session_id>\n\nXác nhận ingestion session: tạo Detection cho IOC/CVE, auto-fetch CVE thiếu từ NVD, chạy matcher scoped.\n\nVí dụ: /confirm_ingest 3",
    "reject_ingest": "/reject_ingest <session_id> [--reason=X]\n\nTừ chối ingestion session — không tạo Detection nào.\n\nVí dụ: /reject_ingest 3 --reason=\"Not relevant\"",
    "edit_ingest": "/edit_ingest <session_id> [--drop=1,3,5] [--drop-cves=2,4]\n\nXóa IOC/CVE khỏi extraction trước khi confirm. Index 1-based, theo preview hiện tại (reshuffled sau mỗi edit).\n\nVí dụ: /edit_ingest 3 --drop=1,3\n       /edit_ingest 3 --drop-cves=2",
    "scan_censys": "/scan_censys --ip=X | --cidr=X [--auto-discover=customer]\n\nQuét external exposure (service/port đang mở) qua Censys cho 1 IP hoặc 1 CIDR range (mỗi IP trong range được tra riêng, giới hạn số host/scan). --auto-discover tạo asset mới nếu IP chưa có trong inventory. --asn hiện chưa khả dụng — cần key có quyền search/query (organization-scoped), free tier chỉ tra được từng IP.\n\nVí dụ: /scan_censys --ip=203.113.128.5\n       /scan_censys --cidr=203.113.128.0/28 --auto-discover=NPT",
    "force_fetch": "/force_fetch [--feed=nvd|threatfox|malwarebazaar|urlhaus|feodo|all]\n\nManual trigger fetcher — bỏ qua schedule interval. Dùng khi cần cập nhật data ngay (debug hoặc trước /export report).\n\nDefault: all feeds.\n\nVí dụ: /force_fetch --feed=nvd\n       /force_fetch",
    "scan_ghwarfare": "/scan_ghwarfare --keyword=X [--max=50]\n\nKiểm tra lộ lọt tài liệu (file công khai trên S3/DO Spaces/GCP...) qua GrayHatWarfare. Pipeline 3 bước: bucket whitelist → rule engine (YAML) → LLM classifier (chỉ chạy khi rule không chắc chắn). Free tier chỉ tìm được ~15% index, không sort, không full-path search.\n\nVí dụ: /scan_ghwarfare --keyword=EVN\n       /scan_ghwarfare --keyword=GENCO1 --max=100",
    "scan_urlscan": "/scan_urlscan --keyword=X [--domain=Y] [--max=50]\n\nKiểm tra brand abuse/impersonation qua urlscan.io. Pipeline 3 bước: typosquat check (Levenshtein vs domain EVN thật) → rule engine (YAML: malicious verdict, nhiều engine flag, brand impersonation) → LLM classifier (chỉ chạy khi không match rule HIGH/CRITICAL). Mỗi kết quả tìm kiếm được enrich thêm verdict thật qua Result API.\n\nVí dụ: /scan_urlscan --keyword=\"Vietnam Electricity\"\n       /scan_urlscan --keyword=EVN --domain=evn.com.vn --max=100",
    "enrich_ip": "/enrich_ip <ip> [--force] [--full]\n\n"
        "Fast (2 provider): AbuseIPDB + VirusTotal — ~5s\n"
        "Full (5 provider): + OTX + Pulsedive + LeakIX — ~15-30s\n\n"
        "Background scheduler tự động enrich full 5 provider mỗi 15 phút.\n"
        "Kết quả có aggregate_risk_score + confidence + coverage. Không tạo Finding mới — đây là lớp enrichment/metadata, không phải discovery layer.\n\n"
        "Ví dụ: /enrich_ip 45.146.164.110\n       /enrich_ip 45.146.164.110 --full\n       /enrich_ip 45.146.164.110 --force",
    "generate_report": "/generate_report [--window=7d] [--from=YYYY-MM-DD --to=YYYY-MM-DD] [--format=html|pdf|both] [--customer=X]\n\n"
        "Tạo báo cáo CTI (CyRadar-style): findings theo severity/source/customer, "
        "CVE, campaign, exposure (Censys), document leak (GrayHatWarfare), brand abuse (urlscan), malicious IP "
        "(multi-provider aggregate), asset coverage — kèm Executive Summary 3 đoạn do LLM viết. "
        "--customer=X thu hẹp scope về 1 customer cụ thể (narrative + số liệu riêng, tên file customer_{short_code}.html); "
        "không có --customer thì tạo report toàn cảnh (global). Output HTML (canonical) "
        "+ PDF (wkhtmltopdf), lưu tại reports/YYYY-MM-DD/, metadata lưu vào bảng reports, gửi kèm file qua Telegram. "
        "Weekly global report tự động chạy Monday 06:00 UTC. Default: 7 ngày, cả 2 format.\n\n"
        "Ví dụ: /generate_report\n       /generate_report --window=30d --format=html\n       "
        "/generate_report --customer=NPC --window=30d",
    "list_reports": "/list_reports [--limit=15] [--type=global|customer] [--customer=X]\n\n"
        "Danh sách report đã tạo (global + customer), sắp xếp mới nhất trước. Filter theo type hoặc customer.\n\n"
        "Ví dụ: /list_reports\n       /list_reports --type=customer --limit=5\n       /list_reports --customer=NPC",
    "download_report": "/download_report <id> [--format=html|pdf|both]\n\n"
        "Tải lại file HTML/PDF của 1 report đã tạo trước đó, theo report ID (xem qua /list_reports).\n\n"
        "Ví dụ: /download_report 3\n       /download_report 3 --format=pdf",
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
