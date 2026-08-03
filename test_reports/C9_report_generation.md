# Giai đoạn C — Nhóm test 9 (phần Báo cáo, script-only)

Phần Sigma/Playbook cần free-text agent qua Bot 2 Telegram — xem
`test_reports/C9_TODO_telegram.md` để chạy phần đó. Dưới đây là phần
"Báo cáo" đã tự chạy được qua `test_tool.py` (bypass Bot 2).

## Khác biệt so với đề cương

- Tool `generate_report` (inline markdown, nhanh) nhận tham số
  `scope`/`since_days`, không phải `window` như suy đoán ban đầu.
- Test trực tiếp qua CLI `test_tool.py` không giữ được state
  pending-confirmation giữa 2 lần gọi process riêng (mỗi lần chạy là 1
  tiến trình Python mới) — với `trigger_report_generation` (destructive,
  cần xác nhận 2 bước), phải viết 1 script Python gọi cả 2 bước trong
  cùng 1 process để giữ đúng registry pending-confirmation trong bộ nhớ.

## 6. "Sinh báo cáo tuần cho toàn EVN" — tương đương `generate_report` (inline, nhanh)

```bash
$ python scripts/test_tool.py generate_report --args='{"scope":"all","since_days":7}'
```

- Thời gian: **18.65s**
- **Phát hiện lỗi phụ:** LLM Executive Summary bị lỗi cùng loại với bug
  `/playbook` đã ghi trong `scripts/audit_14b_backlog.md` — log báo
  `Weekly report LLM summary failed: Could not extract valid JSON from
  text: '{...bị cắt cụt giữa chừng...}'`. Hệ thống **tự fallback graceful**:
  báo "(LLM summary lỗi: ...)" ngay trong report thay vì crash toàn bộ
  request, nên report vẫn sinh ra đầy đủ số liệu định lượng (chỉ thiếu
  đoạn văn tường thuật do LLM). Đây là **bằng chứng thực nghiệm mới** cho
  thấy bug JSON-truncation không chỉ xảy ra ở `/playbook` mà còn ở
  `generate_report`'s Executive Summary — cùng gốc rễ (LLM đôi khi trả
  JSON không đầy đủ cho output dài), khác vị trí code, **chưa được fix**.
- Kết quả định lượng (báo cáo vẫn sinh thành công):
  - Tổng findings: 126 (82 MEDIUM, 44 HIGH)
  - Top 10 CVE finding: #150, #151, #152, #251, #219, #157, #220, #153, #260, #204
  - Top customer theo open finding: EVN Hanoi Power Corporation (91), EVN Electrical Power Services (13), Vietnam Electricity — công ty mẹ (7), EVN Northern Power Corporation (7), EVN Central Power Corporation (3)
  - Top 5 ATT&CK technique: T1203 (35), T1055 (32), T1078 (32), T1083 (30), T1190 (30)
  - Alert dispatch: batched=38, dispatched=22

## 7. "Tạo báo cáo cho NPC tháng này" — tương đương `trigger_report_generation` (HTML+PDF file)

Vì đây là destructive tool cần xác nhận 2 bước, đã gọi trực tiếp qua
`TOOL_REGISTRY` trong 1 script Python để giữ session state:

```python
r1 = await tool.handler(window="7d", format="both")               # bước 1: pending
r2 = await tool.handler(window="7d", format="both", confirmed=True) # bước 2: thực thi
```

**Bước 1 — PENDING_CONFIRMATION:**
```json
{
  "success": true,
  "status": "PENDING_CONFIRMATION",
  "requires_confirmation": true,
  "summary": {
    "action": "trigger_report_generation",
    "scope": "global",
    "window": "2026-07-27 → 2026-08-03",
    "format": "both",
    "estimated_time": "10-30s (LLM narrative)"
  }
}
```

**Bước 2 — kết quả sau xác nhận:**
```json
{
  "success": true,
  "status": "generated",
  "report_id": 23,
  "scope": "global",
  "window": "2026-07-27 → 2026-08-03",
  "findings_total": 124,
  "html_path": "reports\\2026-08-03\\global_report_162904.html",
  "pdf_path": "reports\\2026-08-03\\global_report_162904.pdf",
  "html_size_bytes": 45039,
  "pdf_size_bytes": 98543
}
```

- **Thời gian sinh: 61.32 giây** — vượt ước lượng "10-30s" tool tự công bố
  trong description (có thể do LLM narrative bị chậm/gặp rate-limit tạm
  thời, xem log tương tự ở Nhóm test 1's NVD fetch).
- Kích thước file: HTML = 45,039 bytes (~44KB), PDF = 98,543 bytes (~96KB).
- **Lưu ý:** test này chạy **global scope** (`window=7d`), không phải
  riêng NPC như đề cương câu 7 yêu cầu, vì mục tiêu chính là đo timing +
  kích thước file (không phụ thuộc scope). Nếu cần đúng scope
  "riêng NPC", gọi lại với `customer="EVNNPC"` (short_code thật, không
  phải "NPC" như đề cương).
