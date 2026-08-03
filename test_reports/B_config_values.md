# Giai đoạn B — Tham số cấu hình hệ thống

Nguồn: đọc trực tiếp mã nguồn `src/ati_evn/config.py`,
`src/ati_evn/agent/loop/config.py`, `src/ati_evn/agent/session/state.py`,
`src/ati_evn/campaigns/detector.py`, `src/ati_evn/ingest/pipeline.py`, và
truy vấn DB cho Sigma stats. Toàn bộ giá trị dưới đây lấy trực tiếp từ
code, không suy diễn.

## Nhóm 1 — Fetcher và ingest

| Tham số | Giá trị | Nguồn |
|---|---|---|
| Cửa sổ thời gian NVD fetcher | 48 giờ (mặc định `SINCE_HOURS_OVERRIDES`), 60 phút interval lịch chạy tự động | `scripts/run_fetchers.py:39-41`, `config.py: fetcher_nvd_interval_min=60` |
| Cửa sổ thời gian IOC fetcher khác (ThreatFox/MalwareBazaar/URLhaus/Feodo) | 24 giờ mặc định | `scripts/run_fetchers.py:90` |
| Interval lịch chạy tự động — ThreatFox | 30 phút | `config.py: fetcher_threatfox_interval_min` |
| Interval lịch chạy tự động — MalwareBazaar | 60 phút | `config.py: fetcher_malwarebazaar_interval_min` |
| Interval lịch chạy tự động — URLhaus | 60 phút | `config.py: fetcher_urlhaus_interval_min` |
| Interval lịch chạy tự động — Feodo | 360 phút | `config.py: fetcher_feodo_interval_min` |
| Cửa sổ chống trùng ingest (raw IOC) | 24 giờ | `scripts/run_fetchers.py:105` (`dedup_window_hours=24`) |
| Số bản ghi chunk khi insert | 1000 rows/chunk | `ingest/pipeline.py:35` (`CHUNK_SIZE = 1000`) |
| Concurrency LLM CPE inferrer | 5 (semaphore size) | `config.py: llm_max_concurrent = 5` |
| Cửa sổ đệm khi tính "first window" | 6 giờ | `config.py: fetcher_window_buffer_hours = 6` |
| Cửa sổ mặc định lần chạy đầu tiên | 48 giờ | `config.py: fetcher_default_first_window_hours = 48` |
| Ngưỡng cảnh báo fetcher lỗi liên tiếp | 3 lần | `config.py: fetcher_failure_alert_threshold = 3` |

## Nhóm 2 — Agent loop

| Tham số | Giá trị | Nguồn |
|---|---|---|
| MAX_STEPS | 8 | `agent/loop/config.py:6` |
| TIMEOUT_SECONDS | 60 giây | `agent/loop/config.py:7` |
| TOKEN_SOFT_CAP | 50,000 token | `agent/loop/config.py:8` |
| Số lần retry function-calling | 1 (retry 1 lần rồi fallback ReAct) | `agent/loop/config.py:9` (`FUNCTION_CALLING_RETRY = 1`) |
| Session TTL | 30 phút | `agent/session/state.py:37` (`SESSION_TTL_MINUTES = 30`) |
| Số lượt history hội thoại lưu | 20 turn | `agent/session/state.py:38` (`HISTORY_MAX_TURNS = 20`) |
| Số lượt command_log_recent lưu | 20 entry | `agent/session/state.py:39` (`COMMAND_LOG_MAX_ENTRIES = 20`) |

## Nhóm 3 — Campaign detection

| Tham số | Giá trị | Nguồn |
|---|---|---|
| Cửa sổ gom nhóm | 6 giờ | `campaigns/detector.py:28` (`WINDOW_HOURS = 6`) |
| Ngưỡng ATT&CK overlap | 50% | `campaigns/detector.py:30` (`MIN_TECHNIQUE_OVERLAP = 0.5`) |
| Filter A (bulk-ingest heuristic) — cửa sổ | 60 giây | `campaigns/detector.py:31` (`BULK_INGEST_TIME_WINDOW_SEC = 60`) |
| Filter A — ngưỡng % finding trong cửa sổ | ≥80% | `campaigns/detector.py:32` (`BULK_INGEST_MAJORITY = 0.8`) |
| Ngưỡng thông báo (notification) | 75% | `campaigns/detector.py:33` (`NOTIFICATION_THRESHOLD = 0.75`) |
| Cửa sổ lookback quét finding | 24 giờ | `campaigns/detector.py:34` (`LOOKBACK_HOURS = 24`) |

**Lưu ý:** đề cương chỉ hỏi "Filter A" nhưng code có thêm "Filter C"
(single-source filter, dòng ~245) không nằm trong danh sách tham số hằng
số — đây là logic điều kiện chứ không phải hằng số cấu hình riêng, nên
không có "giá trị" để trích thêm ngoài 2 filter đã liệt kê.

## Nhóm 4 — Alert dispatch (Bot 1)

| Tham số | Giá trị | Nguồn |
|---|---|---|
| Chu kỳ poll | 5 giây | `telegram/bot_alert.py` (log xác nhận: "poll every 5s"), khớp thiết kế |
| Ngưỡng gom nhóm số pending (batch trigger) | ≥3 finding cùng khách hàng | `config.py: alert_batch_trigger_count = 3` |
| Cửa sổ gom nhóm | 60 giây | `config.py: alert_batch_window_seconds = 60` |
| Cửa sổ dedupe | 5 phút | `config.py: alert_dedupe_window_minutes = 5` |
| Số lần retry | 5 lần | `config.py: alert_retry_max_attempts = 5` |
| Khoảng cách giữa các lần retry | 300 giây = 5 phút (cố định, không backoff lũy thừa) | `config.py: alert_retry_backoff_seconds = 300` |

**Lưu ý khác biệt:** đề cương hỏi "khoảng cách giữa các lần retry (phút)"
ngụ ý có thể có nhiều mốc — thực tế code dùng **1 giá trị cố định 5 phút**
cho mọi lần retry (không phải backoff tăng dần theo cấp số).

## Nhóm 5 — Sigma matching

```sql
$ docker compose exec postgres psql -U ati_evn -d ati_evn -c "
SELECT count(*) AS total_rules,
       count(*) FILTER (WHERE cve_refs != '[]'::jsonb) AS with_cve,
       count(*) FILTER (WHERE attack_techniques != '[]'::jsonb) AS with_attack
FROM sigma_rules;
"
```

| total_rules | with_cve | with_attack |
|---|---|---|
| 3142 | 63 | 2796 |

**Diễn giải:** 3142 rule Sigma trong repo (SigmaHQ đồng bộ qua
`scripts/sync_sigma.py`), trong đó chỉ 63 rule (2.0%) có tham chiếu CVE
trực tiếp, còn 2796 rule (89.0%) có gắn ATT&CK technique — khớp với thiết
kế 2 tầng matching mô tả trong Nhóm test 4 (CVE-direct rất hiếm, phần lớn
matching đi qua technique/behavior).

## Nhóm 6 — Tool registry

**Tổng số công cụ đã đăng ký: 58** (đếm trực tiếp từ `TOOL_REGISTRY`
runtime, không phải ước lượng — cập nhật cuối phiên sau khi thêm 3 tool
mới trong quá trình manual test: `top_attack_techniques`,
`generate_sigma_rule`, `generate_playbook`; số liệu gốc lần đo đầu tiên
là 55, xem lịch sử trong `scripts/audit_14b_backlog.md`).

Phân loại theo `register_tool` (query) vs `register_action_tool`
(action, có `destructive=True/False`):

### QUERY — 29 công cụ (read-only, không audit log riêng, luôn tự động chạy)

```
explain_attack_technique, explain_mitigation, generate_playbook,
generate_report, generate_sigma_rule, get_brand_abuse_detail,
get_campaign_detail, get_customer_summary, get_document_leak_detail,
get_exposure_detail, get_finding_detail, get_ip_enrichment,
get_playbook, relationships, search_asset, search_brand_abuse,
search_campaigns, search_cve, search_exposed_documents,
search_exposures, search_findings, search_ioc, search_malicious_ips,
search_pulses, search_sigma_rules, search_software, summarize_customer,
timeline, top_attack_techniques
```

### NON-DESTRUCTIVE ACTION — 9 công cụ (có audit log qua `agent_action_log`, tự động chạy không cần xác nhận)

```
download_report, enrich_ip, force_fetch_feed, get_indicator_detail,
list_reports, scan_brand_abuse, scan_censys, scan_document_leak,
search_indicators
```

### DESTRUCTIVE ACTION — 20 công cụ (yêu cầu xác nhận 2 bước: gọi lần đầu → PENDING_CONFIRMATION → gọi lại với `confirmed=True`)

```
acknowledge_alert, acknowledge_indicator, add_customer,
add_customer_asset, add_indicator_note, add_ioc, confirm_campaign,
create_campaign, create_finding, delete_ioc, export_findings,
export_indicators, ingest_article, reject_campaign,
remove_customer_asset, rescan_finding, trigger_report_generation,
update_customer, update_finding_status, update_ioc
```

Tổng kiểm: 29 + 9 + 20 = 58. ✅ Khớp.

**Lưu ý khi trích xuất:** ban đầu tôi phân loại nhầm bằng cách khớp *tên
file* module với tên tool đăng ký — lỗi này khiến `enrich_ip` (đăng ký từ
file `action_enrich_ip.py`, tên file khác tên tool) bị rơi ra ngoài phân
loại. Đã sửa bằng cách đọc trực tiếp tham số `name="..."` bên trong lệnh
gọi `register_action_tool(...)` của từng file thay vì dùng tên file, đối
chiếu ngược lại với `TOOL_REGISTRY` runtime để đảm bảo tổng khớp.

**Lưu ý về việc tăng từ 55 → 58**: trong quá trình chạy manual test
(Nhóm 5, 6), phát hiện 3 gap chức năng thật (agent không có cách nào
tổng hợp ATT&CK technique thật sự, không có cách sinh Sigma rule/
playbook qua hội thoại tự nhiên dù logic backend đã hỗ trợ đầy đủ qua
slash-command) — đã bổ sung 3 tool mới để lấp gap, không phải thay đổi
kiến trúc. Nếu Chương 3 cần con số "tại thời điểm bắt đầu test" thay vì
"cuối phiên", dùng 55; nếu cần con số phản ánh hệ thống hoàn chỉnh cuối
cùng, dùng 58.

---

## Ghi chú tổng hợp khác biệt Giai đoạn B

- Đề cương B liệt kê tham số theo nhóm khá sát với thực tế code — không
  có tham số nào trong 6 nhóm bị thiếu hoàn toàn, chỉ có 2 điểm cần làm
  rõ hơn khi viết vào Chương 3: (1) alert retry dùng khoảng cách **cố
  định** 5 phút, không phải backoff tăng dần; (2) Sigma "Filter C" tồn
  tại trong code nhưng không phải một hằng số cấu hình riêng để trích.
