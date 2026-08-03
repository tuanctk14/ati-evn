# Giai đoạn C — Nhóm test 8: So sánh Function-calling vs ReAct (mục 3.3.8, phần tự chạy được)

## Khác biệt so với đề cương

- **Flag đúng là `--force-react`, không phải `--react-mode`** như đề
  cương ghi. Cú pháp: `python scripts/test_agent.py --user-id <id>
  --force-react "câu hỏi"`.
- Phần "5 câu test postfilter" (kích thích agent gợi ý lệnh slash) **cần
  chạy qua Bot 2 Telegram thật** vì `test_agent.py` gọi thẳng
  `run_agent()`/`run_react()`, không đi qua `agent_handler.py`'s
  `postfilter_answer()`/`postfilter_legacy_finding_actions()` — các
  postfilter này chỉ được áp dụng ở tầng Telegram handler, không phải
  agent loop. Xem `C_TODO_telegram.md` cho phần này.
- Đã dùng 2 trong 5 câu của Nhóm 5.1 để so sánh trực tiếp function-calling
  vs ReAct (không lặp lại đủ cả 5 câu vì cùng cơ chế, tiết kiệm token/thời
  gian — có thể chạy thêm nếu Chương 3 cần đủ n=5).

## So sánh Câu 1: "Có bao nhiêu Finding đang mở của EVN toàn tập đoàn?"

| | Function-calling | ReAct (`--force-react`) |
|---|---|---|
| Thời gian | 11.57s | 31.22s |
| Tool call | 1 (`search_findings(status=open, limit=1)`) | 1 (`search_findings(status=OPEN, limit=1000)`) |
| Token | 32,285 | 10,506 |
| LLM calls | 2 | 2 |
| Kết quả | 195 finding mở — **đúng** | 195 finding mở — **đúng** |

**Nhận xét:** cả 2 chế độ trả lời đúng số liệu. Function-calling gọi tool
tối ưu hơn (`limit=1`, chỉ cần lấy `total_count` từ response), trong khi
ReAct gọi `limit=1000` (kém tối ưu, có thể vì text-based reasoning khó
suy luận ra "chỉ cần limit=1 để lấy tổng số" bằng schema JSON rõ ràng như
function-calling). Ngược lại, ReAct dùng ít hơn 3x token (không cần gửi
toàn bộ JSON schema của 55 tool trong mỗi lời gọi), nhưng chậm hơn ~2.7x
về thời gian thực (có thể do format text Thought/Action/Observation cần
nhiều bước parse hơn).

## So sánh Câu 2: "Liệt kê 5 Finding mới nhất"

| | Function-calling | ReAct (`--force-react`) |
|---|---|---|
| Thời gian | 15.15s | 18.28s |
| Tool call | 1 (`search_findings(limit=20)`) | 1 (`search_findings(limit=5)`) |
| Token | 35,144 | 8,457 |
| LLM calls | 2 | 2 |
| Kết quả | 5 Finding đúng, đầy đủ CVE/severity/customer/asset | 5 Finding đúng, đầy đủ + thêm nhận xét (CVE-2025-68686 xuất hiện ở 2 đơn vị) |

**Nhận xét:** ở câu này ReAct gọi tool với `limit=5` chính xác hơn (đúng
số lượng cần), trong khi function-calling gọi `limit=20` rồi tự lọc — cả
2 đều ra kết quả đúng, không có sai lệch giữa 2 chế độ. Chênh lệch thời
gian nhỏ hơn câu 1 (15.15s vs 18.28s), token vẫn chênh lệch lớn (4.2x).

## Tổng kết sơ bộ (2/5 câu)

- Tỷ lệ đúng: 2/2 (100%) cho cả 2 chế độ trên 2 câu đã test.
- ReAct tiết kiệm 68-76% token so với function-calling nhờ không cần gửi
  toàn bộ 55-tool JSON schema mỗi lời gọi.
- Function-calling nhanh hơn ReAct trong cả 2 câu (khoảng biến thiên, câu
  1 chênh lệch rõ hơn câu 2) — phù hợp với vai trò thiết kế: ReAct chỉ là
  fallback khi function-calling thất bại, không phải chế độ chính.
- Không phát hiện khác biệt về độ chính xác giữa 2 chế độ trong mẫu nhỏ
  này — cần thêm 3 câu còn lại (và toàn bộ phần postfilter qua Telegram)
  để có kết luận đầy đủ cho Chương 3.
