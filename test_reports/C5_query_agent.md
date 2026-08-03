# Giai đoạn C — Nhóm test 5: Agent tra cứu qua câu hỏi tiếng Việt (15 câu, 3 nhóm)

Chạy qua `scripts/test_agent.py` (function-calling mode mặc định, tự
động fallback ReAct khi timeout) -- KHÔNG phải qua Bot 2 Telegram trực
tiếp, nhưng dùng chung agent loop thật (`run_agent()`), cùng cơ chế
với production. Chạy lại toàn bộ sau khi đã fix các bug/gap phát hiện ở
Nhóm test 6 (search_asset param, search_campaigns default status,
top_attack_techniques tool) đầu phiên.

## Nhóm 5.1 — Tra cứu Finding

| # | Câu hỏi | Đúng/Một phần/Sai | Thời gian | Tool call |
|---|---|---|---|---|
| 1 | Cho tôi xem những Finding HIGH của EVNNPC trong 7 ngày qua | Đúng | 40.3s | 1 |
| 2 | Có bao nhiêu Finding đang mở của EVN toàn tập đoàn? | Đúng | 6.9s | 1 |
| 3 | Liệt kê 5 Finding mới nhất | Đúng | 25.9s | 1 |
| 4 | Finding nào của EVNGENCO3 có mức độ HIGH? | Đúng | 57.7s | 2 (chạm token cap, force final answer) |
| 5 | Tổng hợp Finding theo đơn vị trong tháng này | **Một phần** (xem ghi chú) | timeout + retry 22.7s | 0 rồi 2 (2 lần thử) |

**Ghi chú câu 4:** Trả lời đúng (0 finding cho EVNGENCO3, không bịa),
nhưng chạm `TOKEN_SOFT_CAP=50,000` (dùng 62,593 token) chỉ với 2 tool
call -- xem phát hiện "system-prompt-bloat" bên dưới.

**Ghi chú câu 5:** Lần chạy đầu tiên **THẤT BẠI HOÀN TOÀN** -- cả
function-calling (2 lần timeout liên tiếp, có 1 lần kèm lỗi backend
"grammar-constrained decoding" HTTP 400) lẫn ReAct fallback đều không
trả lời được, agent trả về "Xin lỗi, agent bị timeout." Lần chạy lại
(retry) thành công qua ReAct nhưng phát hiện thêm 2 bug: (a)
`search_findings()` không hỗ trợ tham số `offset` -- model tự đoán ra
để phân trang qua giới hạn `HARD_CAP=20`/lần gọi, gây lỗi
`TypeError`; (b) câu trả lời cuối cùng bị **cắt cụt giữa chừng** (bảng
13 dòng dừng đột ngột ở "Tổng cộ..."). Cả 2 đã ghi vào
`scripts/audit_14b_backlog.md`.

## Nhóm 5.2 — Tra cứu tài sản, CVE, IOC

| # | Câu hỏi | Đúng/Một phần/Sai | Thời gian | Tool call |
|---|---|---|---|---|
| 6 | Tài sản nào của EVNHANOI đang chạy Windows Server? | Đúng | 12.0s (sau 2 lần function-calling timeout, fallback ReAct) | 1 |
| 7 | CVE-2026-49261 ảnh hưởng đến những đơn vị nào? | Đúng | 52.1s | 3 (chạm token cap 2 lần trong cùng run) |
| 8 | Cho tôi thông tin về cve-2026-47295 | Đúng | 50.6s | 3 |
| 9 | IOC 185.220.101.99 có xuất hiện trong hệ thống không? | Đúng | 18.6s | 2 (tự phục hồi sau search_ioc not-found) |
| 10 | Có tài sản nào của EVNNPC bị lộ ra Internet không? | Đúng | 16.8s | 1 |

**Ghi chú câu 6:** Function-calling timeout 60s **2 lần liên tiếp**
trước khi fallback ReAct thành công -- đáng chú ý vì cho thấy primary
path có thể timeout trong thực tế với tần suất không nhỏ, không chỉ lý
thuyết. Kết quả cuối đúng (asset #29 = `hnoi-win-dc-01`, khớp kỳ vọng
đề cương) nhưng câu trả lời chỉ ghi ID #29, thiếu hostname trong text
(điểm UX nhỏ).

**Ghi chú câu 9:** Agent tự phục hồi tốt khi `search_ioc` báo
"not found" (IP này thực chất là ThreatIndicator nội bộ, không phải
IOC feed) -- tự chuyển sang `search_indicators` và giải thích rõ sự
khác biệt 2 loại dữ liệu cho analyst, không chỉ báo lỗi.

## Nhóm 5.3 — Tra cứu tổng hợp và quan hệ

Chưa chạy lại trong đợt retest này (câu 11-15) -- đã test đầy đủ trong
phần hội thoại trước đó của cùng phiên làm việc (không còn dữ liệu
timing/tool-call chi tiết do bị tóm tắt ngữ cảnh). Kết luận định tính từ
lần chạy trước: cả 5 câu đều trả lời đúng, bao gồm `top_attack_techniques`
(tool mới thêm trong phiên) hoạt động đúng cho câu 14, và
`search_campaigns` gọi đúng cả 2 status (candidate + confirmed) cho câu
13 sau khi fix prompt rule.

## Phát hiện quan trọng: system-prompt-bloat được đo lường xác nhận

Trong 10 câu chạy lại (Nhóm 5.1 + 5.2), có **5/10 lần chạy** chạm
`TOKEN_SOFT_CAP=50,000` (một số chạm 2 lần trong cùng 1 turn), và
**2/10 lần chạy** function-calling timeout hoàn toàn phải fallback
ReAct -- trên các câu hỏi tra cứu bình thường (2-3 tool call), không
phải câu hỏi phức tạp bất thường.

Đo lường trực tiếp xác nhận nguyên nhân: `SYSTEM_PROMPT` (~7,069 token
ước tính) + JSON schema của 58 tool đã đăng ký (~9,956 token) = **~17,000
token cố định** gửi lại NGUYÊN VẸN mỗi bước LLM trong 1 turn
function-calling -- trước khi tính lịch sử hội thoại, câu hỏi, hay dữ
liệu tool trả về. Một turn chỉ cần 3 bước (2 tool call + câu trả lời
cuối) đã tốn >= 51,000 token overhead thuần, đã vượt ngưỡng cap dù
"không có gì" xảy ra thêm. Xem chi tiết + đề xuất hướng xử lý trong
`scripts/audit_14b_backlog.md` (mục "[MEASURED] Follow-up to
system-prompt-bloat").

## Tổng kết

- **9/10 câu ĐÚNG hoàn toàn, 1/10 một phần** (câu 5, thất bại lần đầu
  nhưng thành công khi retry, kèm 2 bug phụ phát hiện thêm).
- Không có câu nào trả lời SAI hay bịa dữ liệu -- điểm mạnh nhất quán
  của cả 2 loop mode qua toàn bộ đợt test.
- Vấn đề chính không phải độ chính xác mà là **độ ổn định/hiệu năng**:
  token budget bị chạm thường xuyên, timeout xảy ra trên cả câu hỏi
  đơn giản -- cần ưu tiên xử lý trước khi tối ưu thêm về mặt tính năng.
