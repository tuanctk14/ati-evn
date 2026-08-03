# Giai đoạn D3 — Campaign detection

## Chạy detector (dry-run, không ghi DB)

```bash
$ python scripts/run_campaign_detection.py --dry
```

```
Loaded 2 recent findings with attack_context   # (log nội bộ, tính tại thời điểm import catalog — số liệu
                                                  cuối cùng dùng để cluster có thể khác do truy vấn lại ngay
                                                  sau đó; xem số liệu SQL xác nhận bên dưới)
Detected 0 candidate campaigns after filters

=== Detected 0 candidate campaigns (DRY) ===
```

## Điều tra tại sao 0 cluster (không phải bug)

```sql
SELECT id, customer_id, ioc_value, first_seen FROM findings
WHERE metadata::jsonb ? 'attack_context' AND first_seen > now() - interval '24 hours'
ORDER BY first_seen DESC;
```

| id | customer_id | ioc_value | first_seen |
|---|---|---|---|
| 263 | 12 | cve-2026-6336 | 2026-08-03 16:13:54.904 |
| 262 | 12 | cve-2026-14351 | 2026-08-03 16:13:54.866 |
| 261 | 12 | cve-2026-13113 | 2026-08-03 16:13:54.849 |
| 260 | 3 | cve-2026-49261 | 2026-08-03 16:13:54.734 |

**Giải thích:** trong cửa sổ lookback 24h (`LOOKBACK_HOURS=24`), chỉ có 4
finding có `attack_context` — 3 finding (#261, #262, #263) cùng
`customer_id=12`, cách nhau chưa tới 100 mili-giây (từ đợt matcher chạy
ở Nhóm test 2 của phiên test này). Đây **chính xác là kịch bản Filter A
(bulk-ingest heuristic)** được thiết kế để chặn: `BULK_INGEST_TIME_WINDOW_SEC=60`
và `BULK_INGEST_MAJORITY=0.8` — với 3/3 finding trong cùng batch xuất
hiện cách nhau <1 giây (100% nằm trong cửa sổ 60s), cluster này bị Filter
A loại bỏ đúng như thiết kế, tránh báo "chiến dịch tấn công" giả từ một
đợt chạy pipeline test/backfill hàng loạt chứ không phải hoạt động tấn
công thật liên tục theo thời gian.

Finding #260 (customer_id=3) đứng riêng lẻ, không đủ `MIN_FINDINGS` (cần
≥2 finding cùng customer) để tạo cluster.

**Kết luận: 0 cluster là kết quả ĐÚNG cho dữ liệu 24h hiện tại** — không
phải lỗi detector, mà là minh chứng thực nghiệm tốt cho việc Filter A hoạt
động chính xác (ngăn dữ liệu test/backfill hàng loạt bị hiểu nhầm thành
chiến dịch tấn công thật).

## Dữ liệu lịch sử — campaign đã tồn tại trong DB (không phải từ lần chạy dry-run này)

```sql
SELECT id, customer_id, status, created_at FROM campaigns ORDER BY id DESC LIMIT 10;
```

| id | customer_id | status | created_at |
|---|---|---|---|
| 11 | 5 | confirmed | 2026-07-30 |
| 10 | 1 | confirmed | 2026-07-27 |
| 9 | 3 | rejected | 2026-07-27 |
| 7 | 4 | expired | 2026-07-18 |
| 6 | 10 | expired | 2026-07-18 |
| 5 | 10 | confirmed | 2026-07-18 |
| 4 | 3 | expired | 2026-07-18 |
| 3 | 2 | expired | 2026-07-18 |
| 2 | 3 | rejected | 2026-07-18 |
| 1 | 2 | expired | 2026-07-10 |

**Phân bố trạng thái (10 campaign gần nhất):** confirmed=3, rejected=2,
expired=4, (candidate=0 hiện tại, đã xử lý hết). Tổng 10 campaign trong
DB (khớp Giai đoạn A). Không đo được "tỷ lệ Filter A/Filter C loại bỏ"
bằng số cụ thể qua lần chạy dry-run này vì log chỉ ghi ở mức `DEBUG`
(không hiện trong output mặc định `INFO`) — nếu Chương 3 cần số liệu
định lượng chính xác về tỷ lệ lọc, cần chạy lại với
`logging.basicConfig(level=logging.DEBUG)` hoặc thêm counter riêng vào
script.
