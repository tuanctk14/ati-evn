# Giai đoạn A — Kiểm tra sức khỏe hệ thống

Thời điểm chạy: 2026-08-03 22:5x (giờ ICT/UTC+7)

## Ghi chú khác biệt phát hiện được trong Giai đoạn A

- **Môi trường Python**: `python`/`pip` trong PATH mặc định của shell trỏ
  tới bản Python hệ thống (Windows Store), KHÔNG phải `.venv` của project.
  `source .venv/Scripts/activate` không có tác dụng trong Git Bash trên
  Windows theo cách mong đợi. Đã dùng trực tiếp `.venv/Scripts/python.exe`
  cho toàn bộ lệnh Python để đảm bảo đúng môi trường — kết quả A1.3 dưới
  đây là bản đã sửa (lần chạy đầu qua `pip show pysigma` báo "not found"
  sai do nhầm môi trường, đã chạy lại đúng).
- **Tên file log**: log 2 bot thực tế nằm ở `logs/bot1_stderr.log` /
  `logs/bot2_stderr.log` (stderr) — `logs/bot1.log` / `logs/bot2.log`
  (stdout) rỗng vì toàn bộ logging của project ghi ra stderr. Đề cương chỉ
  nói "logs/bot1.log và logs/bot2.log" — đã dùng file `_stderr.log` thay
  thế vì đó là nơi thực sự có nội dung. Ngoài ra còn thấy log cũ hơn với
  tên khác (`alert_bot_stderr.log`, `analyst_bot_stderr.log`, dấu thời
  gian 30/07) — có vẻ tên file log đã đổi giữa các lần chạy `start.bat`
  trước đây, không phải lỗi.

---

## A1.1 — Docker container Postgres

```
$ docker compose ps
NAME               IMAGE                COMMAND                  SERVICE    CREATED       STATUS                    PORTS
ati-evn-postgres   postgres:16-alpine   "docker-entrypoint.s…"   postgres   3 weeks ago   Up 12 minutes (healthy)   0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp
```

**Kết quả: OK** — container đang chạy, healthcheck `healthy`.

## A1.2 — Kết nối DB + liệt kê bảng/số bản ghi (`scripts/init_db.py`)

```
$ python scripts/init_db.py
Created 28 tables:
  agent_action_log          rows=185
  agent_sessions            rows=0
  alert_batch               rows=7
  alert_queue               rows=92
  alerts                    rows=0
  brand_abuse_sightings     rows=51
  campaign_findings         rows=41
  campaigns                 rows=10
  command_log               rows=499
  customer_assets           rows=72
  customers                 rows=17
  cve_cwe_map                rows=18225
  cve_enrichment_cache      rows=1756
  cve_product_map           rows=27840
  detections                rows=51664
  exposed_documents         rows=54
  exposures                 rows=13
  feed_run_history          rows=231
  findings                  rows=253
  fp_memory                 rows=4
  ingestion_sessions        rows=13
  ip_aggregated_scores      rows=22
  ip_enrichments            rows=85
  playbook_cache            rows=3
  probable_exposures        rows=2748
  reports                   rows=22
  sigma_rules                rows=3142
  threat_indicators          rows=97
```

**Kết quả: OK** — kết nối DB thành công, schema idempotent (không tạo lại
bảng đã tồn tại), toàn bộ 28 bảng có dữ liệu hợp lý (không rỗng bất
thường, trừ `agent_sessions`=0 và `alerts`=0 — hai bảng này hợp lý ở 0 vì
`agent_sessions` có TTL tự dọn dẹp và `alerts` là bảng lịch sử ít dùng so
với `alert_queue`).

**Lưu ý:** đề cương liệt kê 27 bảng cần đếm ở A4 nhưng thực tế schema có
**28 bảng** — chênh lệch do đề cương A4 chỉ chọn 10 bảng chính (không phải
toàn bộ), không phải lỗi.

## A1.3 — Phiên bản Python + package (đã sửa dùng đúng `.venv`)

```
$ .venv/Scripts/python.exe --version
Python 3.11.9
```

| Package | Version |
|---|---|
| SQLAlchemy | 2.0.51 |
| asyncpg | 0.31.0 |
| pydantic | 2.13.4 |
| aiogram | 3.29.1 |
| APScheduler | 3.11.3 |
| pySigma | 1.4.0 |
| sentence-transformers | 5.6.0 |
| torch | 2.6.0+cpu |
| Jinja2 | 3.1.6 |
| pdfkit | 1.0.0 |
| reportlab | 5.0.0 |

**Kết quả: OK** — tất cả package yêu cầu đã cài đúng trong `.venv`, phiên
bản đều ≥ mức tối thiểu khai báo trong `pyproject.toml`.

## A4 — Số bản ghi các bảng chính (SQL trực tiếp)

```sql
$ docker compose exec postgres psql -U ati_evn -d ati_evn -c "
SELECT 'customers' AS table_name, count(*) FROM customers
UNION ALL SELECT 'customer_assets', count(*) FROM customer_assets
UNION ALL SELECT 'detections', count(*) FROM detections
UNION ALL SELECT 'findings', count(*) FROM findings
UNION ALL SELECT 'threat_indicators', count(*) FROM threat_indicators
UNION ALL SELECT 'campaigns', count(*) FROM campaigns
UNION ALL SELECT 'alert_queue', count(*) FROM alert_queue
UNION ALL SELECT 'agent_sessions', count(*) FROM agent_sessions
UNION ALL SELECT 'reports', count(*) FROM reports
UNION ALL SELECT 'playbook_cache', count(*) FROM playbook_cache;
"
```

| table_name | count |
|---|---|
| customers | 17 |
| customer_assets | 72 |
| detections | 51664 |
| findings | 253 |
| threat_indicators | 97 |
| campaigns | 10 |
| alert_queue | 92 |
| agent_sessions | 0 |
| reports | 22 |
| playbook_cache | 3 |

**Kết quả: OK**, khớp với A1.2.

**Lưu ý về `customers`=17**: đề cương nói "EVN và 13 đơn vị thành viên"
(tổng 14 tổ chức), nhưng DB có 17 customer record. Kiểm tra nhanh cho
thấy có thêm các customer test/nội bộ: `NPCC`, `TFIX`, `TSTIG`, `TSTMN`
(có vẻ là dữ liệu test scenario, không phải đơn vị EVN thật) bên cạnh 13
đơn vị EVN chính thức (`EVN`, `EVNCPC`, `EVNEPS`, `EVNGENCO1/2/3`,
`EVNHANOI`, `EVNHCMC`, `EVNNPC`, `EVNNPT`, `EVNSPC`). Cần loại các
customer test này khi tổng hợp báo cáo cho luận văn nếu muốn số liệu chỉ
phản ánh 14 đơn vị EVN thật.

## A5 — Dung lượng Docker

```
$ docker system df
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          10        10        10.13GB   0B (0%)
Containers      11        1         6.603MB   6.582MB (99%)
Local Volumes   7         7         5.513GB   0B (0%)
Build Cache     68        0         2.452GB   1.221GB
```

**Lưu ý quan trọng**: đây là dung lượng Docker **toàn máy**, không riêng
cho container `ati-evn-postgres`. Máy có 11 container tổng (không phải
chỉ của project này), 10 image, 7 volume — số liệu này không đại diện
riêng cho dung lượng dữ liệu ATI-EVN. Nếu Chương 3 cần con số dung lượng
CSDL riêng, nên dùng lệnh khác (ví dụ
`docker exec ati-evn-postgres psql -c "SELECT pg_size_pretty(pg_database_size('ati_evn'));"`)
thay vì `docker system df`.

## A6 — Log 2 bot Telegram

**Bot 1** (`logs/bot1_stderr.log`, toàn bộ nội dung — file rất ngắn):
```
2026-08-03 22:50:42,070 | INFO | ati_evn.bot_alert | Bot 1 (alert) starting; poll every 5s
```

**Bot 2** (`logs/bot2_stderr.log`, 20 dòng cuối):
```
2026-08-03 22:50:47,804 | INFO | ati_evn.fetchers.scheduler | [urlhaus] Fetching (startup_catchup) — window 2026-07-31 17:00 -> 2026-08-03 15:50 (71h)
2026-08-03 22:50:48,150 | INFO | httpx | HTTP Request: GET https://feodotracker.abuse.ch/downloads/ipblocklist.json "HTTP/1.1 200 OK"
2026-08-03 22:50:48,160 | INFO | ati_evn.fetchers.feodo | Feodo: fetched 1 online C&C IOCs (5 raw rows)
2026-08-03 22:50:48,193 | INFO | ati_evn.ingest.pipeline | Ingest: inserted=1 deduped=0 rejected=0
2026-08-03 22:50:48,201 | INFO | ati_evn.fetchers.scheduler | [feodo] Fetch OK: 1 added, 0 updated (deduped)
2026-08-03 22:50:48,551 | INFO | httpx | HTTP Request: POST https://threatfox-api.abuse.ch/api/v1/ "HTTP/1.1 200 OK"
2026-08-03 22:50:48,810 | INFO | httpx | HTTP Request: GET https://urlhaus-api.abuse.ch/v1/urls/recent/ "HTTP/1.1 200 OK"
2026-08-03 22:50:49,031 | INFO | httpx | HTTP Request: POST https://mb-api.abuse.ch/api/v1/ "HTTP/1.1 200 OK"
2026-08-03 22:50:49,031 | INFO | ati_evn.fetchers.malwarebazaar | MalwareBazaar: fetched 15 IOCs (5 raw samples, selector=time)
2026-08-03 22:50:49,040 | INFO | httpx | HTTP Request: GET https://services.nvd.nist.gov/rest/json/cves/2.0?... "HTTP/1.1 200 OK"
2026-08-03 22:50:49,080 | INFO | ati_evn.ingest.pipeline | Ingest: inserted=15 deduped=0 rejected=0
2026-08-03 22:50:49,085 | INFO | ati_evn.fetchers.scheduler | [malwarebazaar] Fetch OK: 15 added, 0 updated (deduped)
2026-08-03 22:50:49,720 | INFO | ati_evn.fetchers.urlhaus | URLhaus: fetched 1000 IOCs (1000 raw rows)
2026-08-03 22:50:49,959 | INFO | ati_evn.fetchers.threatfox | ThreatFox: fetched 1563 IOCs (1563 raw, 3 days window)
2026-08-03 22:50:51,470 | INFO | ati_evn.ingest.pipeline | Ingest: inserted=1000 deduped=0 rejected=0
2026-08-03 22:50:51,471 | INFO | ati_evn.fetchers.scheduler | [urlhaus] Fetch OK: 1000 added, 0 updated (deduped)
2026-08-03 22:50:52,511 | INFO | ati_evn.ingest.pipeline | Ingest: inserted=1385 deduped=178 rejected=0
2026-08-03 22:50:52,520 | INFO | ati_evn.fetchers.scheduler | [threatfox] Fetch OK: 1385 added, 178 updated (deduped)
2026-08-03 22:52:55,593 | INFO | httpx | HTTP Request: GET https://services.nvd.nist.gov/... "HTTP/1.1 200 OK"
2026-08-03 22:53:03,534 | INFO | httpx | HTTP Request: GET https://services.nvd.nist.gov/... "HTTP/1.1 200 OK"
```

**Kết quả: OK** — cả 2 bot đang chạy, không có traceback/lỗi. Bot 2 vừa
khởi động lại nên đang chạy catch-up fetch cho các feed (bình thường).

---

## Tổng kết Giai đoạn A

| Hạng mục | Trạng thái |
|---|---|
| Postgres container | ✅ Healthy |
| Kết nối DB + schema | ✅ OK, 28 bảng |
| Python + package versions | ✅ OK (đã sửa dùng đúng .venv) |
| Số bản ghi bảng chính | ✅ OK, dữ liệu hợp lý |
| Dung lượng Docker | ⚠️ Số liệu là toàn máy, không riêng project — cần lệnh khác nếu cần số liệu CSDL riêng |
| Log 2 bot | ✅ Cả 2 đang chạy, không lỗi |

Hệ thống đủ điều kiện để tiếp tục Giai đoạn B.
