# Giai đoạn C — Nhóm test 1 & 2 (script-only, đã tự chạy)

## Nhóm test 1 — Thu thập, chuẩn hóa và chống trùng (mục 3.3.1)

### Khác biệt so với đề cương

- **`scripts/run_fetchers.py` không có flag `--source`.** Script chạy
  tuần tự **cả 5 fetcher trong 1 lần gọi**, không thể chọn chạy riêng
  từng nguồn (`--source nvd` sẽ báo lỗi "unrecognized arguments"). Đã
  chạy `python scripts/run_fetchers.py` (không tham số) một lần duy nhất,
  lấy đủ số liệu cho cả 5 nguồn từ output của lần chạy đó, thay vì 5 lần
  `time python ... --source X` riêng biệt như đề cương.
- Vì vậy "thời gian chạy từng fetcher" không đo bằng `time` riêng lẻ mà
  lấy từ cột `ms` (mili-giây) script tự in ra cho mỗi nguồn trong cùng 1
  lần chạy tuần tự.

### Kết quả chạy (`python scripts/run_fetchers.py`, 2026-08-03 23:09-23:12)

```
fetcher          fetched inserted  deduped rejected       ms  note
------------------------------------------------------------------
threatfox            396        2      394        0   2284.5
malwarebazaar         15        3       12        0   1335.7
feodo                  1        0        1        0    407.0
urlhaus             1000        3      997        0   2401.8
nvd                  606       12      594        0 128369.6  +644 cve_product_map rows, +657 cve_cwe_map rows

Grand totals: inserted=20 deduped=1998 rejected=0
By source   : {'threatfox': 2, 'malwarebazaar': 3, 'urlhaus': 3, 'nvd': 12}
By ioc_type : {'domain': 1, 'ipv4': 1, 'sha256': 1, 'sha1': 1, 'md5': 1, 'url': 3, 'cve_id': 12}

DB detections total      : 52823
DB detections by source  : {'nvd': 23245, 'threatfox': 18848, 'urlhaus': 8239, 'malwarebazaar': 2417, 'analyst_ingested': 34, 'internal': 30, 'feodo': 10}
DB cve_product_map total : 28183
DB cve_product_map by src: {'nvd': 26704, 'llm_inferred': 1479}
DB cve_cwe_map total     : 18581
DB cve_cwe_map by src    : {'nvd': 17443, 'llm_inferred': 1138}

real  2m19.321s (tổng thời gian toàn bộ tiến trình, đo bằng `time`)
```

**Thời gian từng fetcher (bảng riêng cho Chương 3):**

| Fetcher | Thời gian (ms) | Fetched | Inserted | Deduped |
|---|---|---|---|---|
| ThreatFox | 2,284.5 | 396 | 2 | 394 |
| MalwareBazaar | 1,335.7 | 15 | 3 | 12 |
| Feodo | 407.0 | 1 | 0 | 1 |
| URLhaus | 2,401.8 | 1,000 | 3 | 997 |
| NVD | 128,369.6 (~128.4s) | 606 | 12 | 594 |

**Nhận xét:** NVD chiếm >98% tổng thời gian chạy vì phải gọi LLM để suy
luận CPE cho các CVE thiếu metadata (10 CVE cần LLM trong lần chạy này) —
trong quá trình chạy có gặp `HTTP 429 Too Many Requests` từ provider LLM
(free tier rate limit), nhưng hệ thống tự phục hồi và hoàn thành đầy đủ,
không rớt dữ liệu.

### Số Detection theo nguồn (1 giờ qua)

```sql
$ docker compose exec postgres psql -U ati_evn -d ati_evn -c "
SELECT source, count(*) AS n_detection
FROM detections
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY source
ORDER BY n_detection DESC;
"
```

| source | n_detection |
|---|---|
| threatfox | 1387 |
| nvd | 1151 |
| urlhaus | 1003 |
| malwarebazaar | 18 |
| feodo | 1 |

**⚠️ Lưu ý quan trọng:** con số này **lớn hơn nhiều** so với "inserted"
của lần chạy `run_fetchers.py` thủ công ở trên (2/12/3/3/0), vì **Bot 2
đang chạy song song** và tự động fetch theo lịch APScheduler trong cùng
khung 1 giờ qua (xác nhận qua log `bot2_stderr.log`, xem
`A_health_check.md`). Số liệu 1-giờ ở đây là **tổng của cả 2 nguồn fetch**
(chạy thủ công của bài test + tự động của Bot 2 đang chạy nền), không chỉ
riêng lần chạy thủ công vừa thực hiện. Nếu Chương 3 cần con số "chỉ do
lệnh test tạo ra", nên dùng trực tiếp bảng "inserted" ở lần chạy thủ công
phía trên, không dùng query theo cửa sổ thời gian này.

---

## Nhóm test 2 — Đối chiếu tài sản EVN (mục 3.3.2)

### Khác biệt so với đề cương

- **Không dùng `--all`.** `run_matcher.py --all` sẽ reprocess TOÀN BỘ
  52,823 detection kể cả những cái đã match từ trước — rủi ro chạy rất
  lâu và tạo nhiễu dữ liệu test. Theo xác nhận của người dùng, đã đổi
  sang `--since-hours=24` (chỉ match detection mới trong 24h qua, gồm cả
  batch vừa fetch ở Nhóm test 1) — vẫn minh họa đúng pipeline matching,
  chạy trong 2 giây thay vì có thể mất nhiều phút/giờ.
- **Cột `customer_code` trong câu SQL đề cương không tồn tại** — tên cột
  thật trong bảng `customers` là `short_code`. Đã sửa câu query.
- **Câu SQL "Probable Exposure" trong đề cương sai cả cột lẫn cách tiếp
  cận**: `findings.metadata_->>'confidence' = 'probable'` — cột thật của
  bảng `findings` là `metadata` (không có dấu gạch dưới cuối), và
  "Probable Exposure" thực chất là **một bảng riêng** (`probable_exposures`),
  không phải giá trị field trong `findings.metadata`. Đã dùng
  `SELECT count(*) FROM probable_exposures` thay thế.

### Kết quả chạy (`python scripts/run_matcher.py --since-hours=24`)

```
=== RouteStats ===
detections_processed        : 3560
detections_matched          : 26
detections_unmatched        : 3534
findings_created            : 14
findings_merged             : 0
findings_auto_fp             : 0
probable_exposures_created  : 32
per_strategy                : {'cve_probable': 32, 'cve_product': 14}

=== Top 5 highest-severity Findings ===
  [CRITICAL] EVN Northern Power Corporation — ipv4:14.161.10.20 (exact_ip)
      reason: IOC IP 14.161.10.20 exactly matches customer asset 14.161.10.20
  [CRITICAL] Vietnam Electricity (EVN) — brand_abuse:https://malicious-evn-phish.example/ (None)
      reason: Brand abuse -- url=..., rule=malicious_verdict, typosquat_dist=21, LLM relevant=True
  [HIGH] EVN Central Power Corporation — cve_id:cve-2026-48163 (cve_product)
      reason: cve-2026-48163 affects mariadb/mariadb (match_range) on asset cpc-db-maria-01 v10.6.20
  [HIGH] Vietnam Electricity (EVN) — domain:test-plugx.example (None)
  [HIGH] Vietnam Electricity (EVN) — domain:test-emotet-c2.tld (None)
```

### Phân bố Finding theo chiến lược matching (toàn bộ 257 finding hiện có, không chỉ 24h qua)

```sql
SELECT correlation_type, count(*) AS n FROM findings GROUP BY correlation_type ORDER BY n DESC;
```

| correlation_type | n | % |
|---|---|---|
| `cve_product` | 198 | 77.0% |
| *(NULL)* | 58 | 22.6% |
| `exact_ip` | 1 | 0.4% |

**⚠️ Về "5 chiến lược matching" đề cương kỳ vọng:** mã nguồn
(`match/strategies.py`) định nghĩa nhiều chiến lược hơn 2:
`exact_ip`, `cidr`, `exact_domain`/`subdomain` (qua hàm `domain_matches`),
`cve_product`, `cve_probable`, và các `kind` động từ keyword-pattern
matching. Tuy nhiên **dữ liệu Finding hiện có trong DB chỉ thể hiện 2
giá trị non-null** (`cve_product`, `exact_ip`) — các chiến lược còn lại
(`cidr`, `exact_domain`, `cve_probable`, keyword-pattern) chưa từng tạo
ra Finding nào còn tồn tại trong dữ liệu hiện tại (có thể do đã bị
đóng/xoá, hoặc do dữ liệu test chưa bao phủ đủ kịch bản). **58 Finding
`correlation_type = NULL`** đều là các dòng "legacy" thuộc `ioc_type`
phi-CVE cũ (brand_abuse, exposed_document, exposure, domain, ipv4) từ
trước khi slice 15A tách `ThreatIndicator` ra khỏi `Finding` — không
phải lỗi matcher hiện tại, mà là dữ liệu lịch sử chưa có trường này.

### Phân bố Finding theo đơn vị (12 đơn vị có Finding, trên tổng 17 customer trong DB)

```sql
SELECT short_code, count(*) AS n_finding FROM findings f JOIN customers c ON f.customer_id=c.id GROUP BY short_code ORDER BY n_finding DESC;
```

| Đơn vị | Số Finding |
|---|---|
| EVNHANOI | 106 |
| EVN (công ty mẹ) | 44 |
| EVNNPC | 23 |
| EVNCPC | 23 |
| EVNEPS | 20 |
| EVNNPT | 13 |
| EVNHCMC | 10 |
| EVNGENCO1 | 6 |
| EVNGENCO2 | 5 |
| EVNSPC | 4 |
| NPCC (customer test, không phải đơn vị EVN thật) | 2 |
| *(NULL — finding không gắn đúng customer)* | 1 |

**Lưu ý:** đề cương nói "phân bố theo 11 đơn vị" — thực tế có Finding trên
**12 nhóm** (11 đơn vị EVN thật + 1 customer test `NPCC`), và
`EVNGENCO3`, `TFIX`, `TSTIG`, `TSTMN` không có Finding nào (0 dòng, không
xuất hiện trong kết quả GROUP BY).

### Số Probable Exposure (bảng riêng, không phải field trong Finding)

```sql
SELECT count(*) FROM probable_exposures;
```

**Kết quả: 2778** (tổng tích lũy, không chỉ của lần chạy 24h vừa rồi — lần
chạy vừa rồi tạo thêm 32 dòng mới, khớp với `probable_exposures_created: 32`
trong RouteStats ở trên).
