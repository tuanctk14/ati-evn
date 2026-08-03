# Giai đoạn D2 — External monitoring (urlscan.io + GrayHatWarfare)

## Khác biệt so với đề cương

- Chạy trực tiếp qua `TOOL_REGISTRY[...].handler()` (không có
  `_bot`/`_chat_id` context) nên cả 2 tool tự động fallback về chế độ
  **đồng bộ** thay vì background — đây là hành vi thiết kế đúng (xem
  `scripts/audit_14b_backlog.md`'s ghi chú về `scan_brand_abuse`/
  `scan_document_leak`'s background pattern), không phải bug.
- `max_results=30`/`max_files=50` như đề cương gốc gây **timeout khi chạy
  qua CLI trong 2 phút** (vì chạy đồng bộ, không có bot để nhận thông báo
  nền) — đã giảm xuống `10` cho cả 2 lệnh để hoàn thành trong thời gian
  hợp lý khi test qua CLI. Muốn số liệu ở đúng 30/50 kết quả như đề
  cương, nên chạy qua Bot 2 Telegram thật (khi đó sẽ tự chuyển sang chế
  độ nền, không bị giới hạn timeout CLI).

## ⚠️ Phát hiện quan trọng: bug JSON-truncation xuất hiện thêm ở 2 vị trí mới

Cả 2 lệnh scan đều gặp `LLM relevance check failed: Could not extract
valid JSON from text: ''` (1-2 lần mỗi lệnh) — đây là **cùng bug đã ghi
nhận trước đó** ở `/playbook` (`scripts/audit_14b_backlog.md`) và
`generate_report` (`test_reports/C9_report_generation.md`), nay xác nhận
thêm xuất hiện ở **`brand_rules`** (scan_brand_abuse's LLM classifier) và
**`document_rules`** (scan_document_leak's LLM classifier). Tổng cộng đã
quan sát bug này ở **4 vị trí độc lập** trong phiên test này, đều gọi
chung `LLMClient.chat_json()` — củng cố giả thuyết đây là vấn đề ở tầng
LLM client/provider dùng chung (JSON mode bị cắt cụt trả về content rỗng
khi hết token budget), không phải lỗi riêng lẻ từng chỗ gọi. Cả 4 vị trí
đều **tự phục hồi graceful** (không crash, chỉ bỏ qua 1 item hoặc hiện
thông báo lỗi thay thế) — mức độ ảnh hưởng thấp nhưng đáng để xem xét
sửa tận gốc (ví dụ retry với max_tokens cao hơn khi gặp response rỗng ở
JSON mode) nếu có thời gian, vì đã lặp lại đủ nhiều lần để không còn là
sự cố ngẫu nhiên.

## `/scan_urlscan --keyword=EVN` (giảm max_results 30→10)

```bash
$ python scripts/test_tool.py scan_brand_abuse --args='{"keyword":"EVN","primary_domain":"evn.com.vn","max_results":10}'
```

- Thời gian: **77.9 giây**
- Kết quả:

| Chỉ số | Giá trị |
|---|---|
| Sightings found | 10 |
| Sightings mới | 1 |
| Sightings cập nhật | 9 |
| Typosquat matched | 0 |
| Rule engine matched | 6 (60%) |
| LLM classifier calls | 10 (100% — 4 còn lại sau rule engine + 6 double-check) |
| Indicators created | 0 |
| Queued for alert | 0 |

## `/scan_ghwarfare --keyword=EVN` (giảm max_files 50→10)

```bash
$ python scripts/test_tool.py scan_document_leak --args='{"keyword":"EVN","max_files":10}'
```

- Thời gian: **49.4 giây**
- Kết quả:

| Chỉ số | Giá trị |
|---|---|
| Files found | 10 |
| Documents mới | 10 |
| Documents cập nhật | 0 |
| Bucket whitelist loại | 0 |
| Rule engine matched | 7 (70%) |
| LLM classifier calls | 10 |
| LLM relevant | 4 (40% trong số 10 gọi LLM) |
| Indicators created | 4 |
| Queued for alert | 0 |

## Tổng hợp pipeline 3 giai đoạn

| Giai đoạn | Brand abuse (10 sighting) | Document leak (10 file) |
|---|---|---|
| Rule engine loại/giữ | 6/10 matched trực tiếp bằng rule | 7/10 matched trực tiếp bằng rule |
| Qua LLM classifier | 10/10 (kể cả những cái rule đã match, để double-check) | 10/10 |
| LLM xác nhận liên quan | 0 indicator mới (không có sighting nào đủ tin cậy tạo indicator mới) | 4/10 (40%) tạo indicator mới |

**Nhận xét:** document leak scan có tỷ lệ tạo indicator cao hơn brand
abuse scan trong batch này (40% vs 0%) — phù hợp với đặc điểm dữ liệu:
tài liệu công khai chứa từ khóa "EVN" trên bucket lưu trữ dễ xác nhận
liên quan hơn là các trang web ngẫu nhiên chứa từ "EVN" trong tiêu đề
(nhiều false-positive tiềm năng hơn ở brand abuse).
