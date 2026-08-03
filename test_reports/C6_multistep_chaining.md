# Giai đoạn C — Nhóm test 6: Chuỗi function calling nhiều bước + entity memory (10 câu)

Chạy qua Bot 2 Telegram thật, dữ liệu thật. Sau câu 1 (nêu rõ CVE), câu
6-10 cố tình KHÔNG nhắc lại mã CVE/Finding để kiểm tra khả năng phân
giải tham chiếu ngầm ("nó", "EVN", "3 đơn vị", "toàn bộ điều tra") của
agent qua session context.

## Câu 1-5: chuỗi function-calling nhiều bước

| # | Câu hỏi | Đúng/Sai | Ghi chú |
|---|---|---|---|
| 1 | Tìm Finding mới nhất liên quan Fortinet và cho tôi biết ATT&CK technique liên quan | Đúng | Chuỗi nhiều tool call đúng thứ tự |
| 2 | Cho tôi CVE nghiêm trọng nhất của EVNNPC tuần này và Sigma rule tương ứng | Đúng | |
| 3 | Finding nào ảnh hưởng nhiều đơn vị nhất và liệt kê các đơn vị đó | Đúng | |
| 4 | Tài sản nào của EVNGENCO1 có nhiều Finding nhất và các CVE liên quan | Đúng | |
| 5 | IOC nào xuất hiện nhiều nguồn nhất trong tuần và thông tin làm giàu của nó | Đúng | |

## Câu 6-10: phân giải tham chiếu ngầm (không nhắc lại CVE-ID)

| # | Câu hỏi | Đúng/Sai | Phân giải tham chiếu ngầm | Ghi chú |
|---|---|---|---|---|
| 6 | Sinh Sigma rule cho nó | Đúng (sau nhiều vòng fix) | Có | Xem "Lịch sử điều tra" bên dưới |
| 7 | Tạo playbook cho nó ở phân đoạn IT | Đúng (sau fix) | Có | Cần thêm tool `generate_playbook` mới |
| 8 | Tài sản nào của EVN có thể bị ảnh hưởng? | Đúng | Có | `relationships(entity_type=cve, entity_id=CVE-2025-68686)` -- tự động, không cần nhắc lại |
| 9 | Đơn vị nào nên được ưu tiên xử lý? | Đúng | Có | Tự gọi `get_customer_summary` cho cả 3 đơn vị để so sánh định lượng (finding/alert count) thay vì đoán |
| 10 | Tổng hợp lại toàn bộ điều tra vừa rồi | Đúng | Có | 0 tool call -- thuần suy luận từ lịch sử hội thoại, đúng bản chất câu hỏi tổng hợp |

**Kết quả: 10/10 câu ĐÚNG, phân giải tham chiếu ngầm THÀNH CÔNG xuyên
suốt** cả 5 câu (6-10), không có entity-drift dù trước đó trong cùng
phiên đã có nhiều CVE khác được nhắc tới.

## Lịch sử điều tra chi tiết: câu 6 (Sigma rule) và câu 7 (Playbook)

Đây là 2 câu phát hiện nhiều gap/bug nhất trong toàn bộ Nhóm test 6,
đáng ghi lại quá trình lặp thiết kế cho luận văn:

### Câu 6 — "Sinh Sigma rule cho nó"

**Gap ban đầu:** không có agent tool nào thực sự có thể sinh Sigma rule
qua free-text -- agent chỉ biết nói "chạy `/rule` đi", một phản hồi
"gãy" (broken response) chứ không phải an toàn.

**Fix:** thêm tool mới `generate_sigma_rule` (agent/tools/
generate_sigma_rule.py), wrap logic 3-tier có sẵn của `/rule`
(`rules/orchestrator.py`'s `get_rule_for_cve()`): community CVE-direct
→ community ATT&CK-behavioral → AI-generate.

**3 vòng lặp sửa ý nghĩa "sinh" vs "tìm":**
1. Lần 1: dạy "sinh/tạo" → `force_regen=True` -- nhưng UX sai (không
   hiện nguyên văn YAML).
2. Lần 2 (sửa quá đà): đổi default `force_regen=False` cho MỌI trường
   hợp -- sai, vì khi user nói rõ "sinh" phải AI-generate mới, không
   trả community rule có sẵn.
3. Lần 3 (quyết định cuối, qua xác nhận trực tiếp với người dùng):
   "sinh"/"tạo" → `force_regen=True` (giống `/rule --regen`); "tìm"/
   "tra" → `force_regen=False` (giống `/rule` trơn).

**Bug phụ phát hiện và fix trong cùng luồng:**
- HTTP 400 "grammar-constrained decoding" (9Router backend routing
  không tương thích) -- thêm retry 1 lần trong `llm/client.py`.
- `JSONExtractError` khi content không rỗng nhưng JSON bị cắt cụt giữa
  chừng (completion_tokens chạm đúng max_tokens) -- thêm retry với
  budget lớn hơn, cùng gốc rễ với 5-6 vị trí tương tự đã fix trước đó
  trong `chat_json()`.
- Agent paraphrase YAML thành văn xuôi thay vì hiện nguyên văn -- fix
  bằng chỉ dẫn tường minh trong tool description ("include the FULL
  raw YAML verbatim... do not paraphrase").

### Câu 7 — "Tạo playbook cho nó ở phân đoạn IT"

**Gap tương tự câu 6:** `get_playbook` (tool cũ) chỉ đọc cache
("Never triggers LLM generation" theo chính docstring của nó) -- báo
"Not cached" rồi dừng thay vì thực sự tạo playbook.

**Fix:** refactor `telegram/commands/playbook.py` tách hàm
`generate_playbook_for()` làm public entry point (logic sinh/cache
dùng chung cho cả slash-command và agent tool), thêm tool mới
`generate_playbook` (agent/tools/generate_playbook.py) wrap nó.

**Trở ngại kỹ thuật:** circular import (`telegram/commands/playbook.py`
→ `agent/loop/postfilter.py` → qua chain → `agent/tools/__init__.py`)
-- giải quyết bằng deferred import (import bên trong hàm tool, không
phải module-level).

**Verify không regression:** sau khi refactor, gõ trực tiếp
`/playbook CVE-2025-68686` (không `--regen`) trên Bot 2 -- kết quả
"freshly generated" đúng và hợp lý (đây là cache MISS đầu tiên cho tổ
hợp `(CVE-2025-68686, network_segment=None)`, vì trước đó chỉ từng
test qua finding_id suy ra segment=dmz, hoặc CLI override
segment=internal_it) -- xác nhận slash-command gốc không bị ảnh hưởng
bởi refactor.

## Tổng kết

- **10/10 câu ĐÚNG** -- bao gồm cả câu tổng hợp thuần suy luận (câu
  10, 0 tool call) và câu cần cross-reference dữ liệu định lượng để so
  sánh ưu tiên xử lý (câu 9).
- Phân giải tham chiếu ngầm hoạt động chính xác 100% qua 5 câu liên
  tiếp (6-10), kể cả khi đã có nhiều entity khác len vào lịch sử hội
  thoại trước đó trong cùng phiên -- không có entity-drift observed
  trong chuỗi test này (khác với lo ngại ban đầu về `last_cve_id` chỉ
  track 1 giá trị).
- 2 gap tool bị phát hiện và fix ngay trong quá trình test (Sigma rule
  generation, Playbook generation) -- cả 2 đều là trường hợp "agent
  biết vấn đề nhưng không có tool để hành động", không phải lỗi suy
  luận -- đúng class vấn đề với `top_attack_techniques` phát hiện ở
  Nhóm test 5 trước đó.
