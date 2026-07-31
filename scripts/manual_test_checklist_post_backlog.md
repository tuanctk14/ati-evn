# Manual Test Checklist — Post backlog fixes (E.1/E.3 + Telegram Markdown sanitize)

Mục đích: verify không có regression sau khi sửa 76→0 bare-except (E.1),
thêm @retry cho 12 client (E.3), và thêm sanitize_telegram_markdown().
Chạy qua Bot 2 Telegram thật. Đánh dấu [x] khi user paste kết quả và xác nhận OK,
[FAIL] kèm ghi chú nếu phát hiện lỗi.

Ưu tiên cao nhất: các tool đã sửa trực tiếp trong E.1/E.3 —
action_enrich_ip, add_ioc, force_fetch_feed, ingest_article, rescan_finding,
scan_brand_abuse, scan_censys, scan_document_leak, download_report,
generate_report, và toàn bộ enrichment adapter (abuseipdb/leakix/otx/pulsedive/virustotal).

---

## Phase 1 — Slash-command (30 lệnh)

### Query / tra cứu (không đổi, kỳ vọng không regression)
- [ ] `/stats`
- [ ] `/finding <id>` (dùng 1 finding có thật)
- [ ] `/cve <cve_id>`
- [ ] `/ioc <ioc_value>`
- [ ] `/asset <asset_name>`
- [ ] `/customer EVN`
- [ ] `/list_open`
- [ ] `/list_alerts`
- [ ] `/indicator <id>`
- [ ] `/list_indicators`
- [ ] `/search_indicators <keyword>`
- [ ] `/campaign <id>`
- [ ] `/list_campaigns`
- [ ] `/rule <cve_id>`
- [ ] `/playbook <cve_id>`
- [ ] `/list_reports`

### Action — vùng bị sửa trực tiếp (ưu tiên cao)
- [ ] `/enrich_ip 8.8.8.8` — full=false (foreground, verify AbuseIPDB+VT vẫn chạy, không exception lộ ra)
- [ ] `/enrich_ip <ip> --full` — kiểm tra cả 5 provider (abuseipdb/virustotal/otx/pulsedive/leakix) chạy qua retry wrapper mới, không crash
- [ ] `/add_ioc <type> <value>` — verify matcher pass chạy xong, không lỗi log thừa
- [ ] `/force_fetch --feed=threatfox` (hoặc feed khác) — verify @retry mới không làm chậm bất thường
- [ ] `/scan_censys <ip>`
- [ ] `/scan_ghwarfare <keyword>` (scan_document_leak)
- [ ] `/scan_urlscan <keyword>` (scan_brand_abuse — verify background+notify vẫn hoạt động)
- [ ] `/ingest <url>` rồi `/confirm_ingest <id>`
- [ ] `/rescan <finding_id>`
- [ ] `/generate_report` — verify HTML/PDF upload vẫn gửi được (logger.warning mới thêm không chặn luồng)
- [ ] `/download_report <report_id>`
- [ ] `/close <finding_id>` / `/mark_fp <finding_id>` / `/reopen <finding_id>`
- [ ] `/acknowledge_indicator <id>`
- [ ] `/export_indicators`

---

## Phase 2 — Free-text agent (15 kịch bản)

Ưu tiên các câu có khả năng LLM trả lời bằng heading/bảng/bold để verify
sanitize_telegram_markdown() hoạt động đúng trên Bot 2 thật (không chỉ unit test):

1. [ ] "Tóm tắt tình hình bảo mật cho EVN" (khả năng cao ra heading/bullet nhiều mục)
2. [ ] "Liệt kê các finding HIGH đang mở, so sánh theo từng công ty con" (khả năng ra bảng)
3. [ ] "Chỉ báo nào cần điều tra gấp nhất cho EVN?" (đúng kịch bản đã lộ bug heading/bold/--- trước đó)
4. [ ] "Asset evn-web-01 có finding gì không?" (đúng kịch bản đã lộ bug bảng trước đó)
5. [ ] "Kiểm tra IP 8.8.8.8" (route qua enrich_ip đã sửa)
6. [ ] "Thêm IOC domain example-evil.com severity HIGH" (route qua add_ioc đã sửa)
7. [ ] "Scan brand abuse cho EVN" (route qua scan_brand_abuse — verify background/notify)
8. [ ] "Scan tài liệu rò rỉ từ khóa EVN" (scan_document_leak)
9. [ ] "Fetch lại feed ThreatFox" (force_fetch_feed)
10. [ ] "Rescan finding #<id>" (rescan_finding)
11. [ ] "Ingest bài báo <url>" (ingest_article)
12. [ ] "CVE mới ingest có match asset không?" (test lại command_log/anaphora resolution, đảm bảo không regress slice 16A)
13. [ ] "/list_indicators xong hỏi tiếp free-text follow-up" (test lại Retest Item 3 — scope-bleed)
14. [ ] Câu hỏi rỗng / message không hợp lệ (test lại empty-message crash fix)
15. [ ] Câu hỏi ngoài phạm vi bot (ví dụ hỏi thời tiết) — verify graceful fallback

---

## Phase 3 — End-to-end scenario (5 kịch bản)

1. [ ] scan_brand_abuse → sighting query → enrich chain (Test A gốc từ Retest Item 3)
2. [ ] /list_indicators → free-text follow-up (Test B gốc từ Retest Item 3)
3. [ ] /ingest → /confirm_ingest → hỏi free-text "CVE mới ingest" (slice 16A regression)
4. [ ] Trigger 1 finding mới qua add_ioc/matcher → verify Bot 1 alert dispatch vẫn hoạt động
5. [ ] /generate_report → /download_report full cycle (verify upload logging mới không phá luồng)

---

## Ghi chú lỗi phát hiện (điền khi test)

(để trống, điền khi phát hiện bug)
