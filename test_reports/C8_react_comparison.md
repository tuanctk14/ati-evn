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

## So sánh Câu 3: "Liệt kê Finding liên quan Fortinet"

| | Function-calling | ReAct (`--force-react`) |
|---|---|---|
| Thời gian | ~8s (không log riêng, LLM calls=1) | 46.8s (lần 1), 57.7s (lần 2) |
| Tool call | 1 (không cần, trả lời trực tiếp từ context) | 2-3 (`search_findings`, `search_cve` — lần 2 gọi `search_cve` trùng lặp 2 lần) |
| Token | 19,960 | 20,756 / 26,784 |
| LLM calls | 1 | 3 / 4 |
| Kết quả | Đúng — 3 Finding Fortinet (#220/#221/#222), đầy đủ chi tiết | **SAI — thất bại cả 2 lần thử**, trả về "Agent không tạo được câu trả lời hợp lệ" dù đã có đủ dữ liệu từ tool calls |

**Phát hiện quan trọng:** ReAct thất bại NHẤT QUÁN (2/2 lần thử) ở câu hỏi
cần **tổng hợp/lọc chéo** giữa nhiều tool result (Finding + CVE liên quan
vendor Fortinet) — model gọi đủ tool, có đủ dữ liệu thô trong
Observation, nhưng không tạo được response khớp `FINAL_RE` (`Final
Answer:`) lẫn `ACTION_RE` (`Action:`/`Action Input:`) hợp lệ, rơi vào
nhánh "malformed response" của `_clean_malformed_response()`. Khác biệt
so với câu 1/2 (tra cứu đơn giản, 1 tool call) — nghi vấn: format
Thought/Action/Observation dạng text khó duy trì tính nhất quán khi
cần suy luận qua nhiều bước tổng hợp, so với function-calling's JSON
schema có cấu trúc rõ ràng hơn cho việc này.

## So sánh Câu 4: "Finding nào của EVNGENCO3 có mức độ HIGH?"

| | Function-calling | ReAct (`--force-react`) |
|---|---|---|
| Thời gian | 16.8s | 23.4s |
| Tool call | 2 (`search_findings` x2, severity=HIGH rồi không lọc severity) | 2 (cùng pattern) |
| Token | 62,541 (**vượt TOKEN_SOFT_CAP=50,000**, kích hoạt `_force_final_answer`) | 14,493 |
| LLM calls | 4 | 3 |
| Kết quả | Đúng — 0 finding cho EVNGENCO3, có gợi ý nguyên nhân | Đúng — 0 finding, kèm thêm chi tiết khách hàng (24 assets, finding_count=0), phát hiện thêm "tên đúng là GENCO3 không phải EVNGENCO3" |

**Phát hiện quan trọng:** function-calling ở câu này CHẠM token soft cap
(62,541 > 50,000) chỉ sau 2 tool call — bằng chứng thực nghiệm cho nghi
vấn "system prompt đã phình to" ghi trong `scripts/audit_14b_backlog.md`
(entry "Manual test 7.4"). ReAct không bị ảnh hưởng vì nó không gửi lại
toàn bộ tool JSON schema mỗi bước, chỉ gửi tools_list dạng text ngắn gọn.

## So sánh Câu 5: "Tổng hợp Finding theo đơn vị trong tháng này"

| | Function-calling | ReAct (`--force-react`) |
|---|---|---|
| Thời gian | 41.9s | 31.3s |
| Tool call | 8 (1 tổng quát + 6 lookup theo từng đơn vị + 1 asset lookup) | 1 (`search_findings(limit=500)`, chỉ nhận về 20 kết quả do tool tự giới hạn) |
| Token | 80,257 | 11,011 |
| LLM calls | 4 | 2 |
| Kết quả | Đúng, chi tiết theo từng đơn vị (199 finding, breakdown 6 đơn vị), tự thừa nhận "còn ~38 finding chưa tra cứu hết" | **SAI — thất bại**, "Agent không tạo được câu trả lời hợp lệ" ngay sau 1 tool call |

**Phát hiện quan trọng:** ReAct thất bại lần thứ 2 (3/5 tổng số câu) ở
đúng loại câu hỏi cần tổng hợp/group-by nhiều nguồn — củng cố giả thuyết
ở câu 3: model dừng lại sau khi có dữ liệu thô, không tự tổng hợp thành
câu trả lời cuối cùng đúng định dạng. function-calling ở đây lại thể
hiện tốt hơn hẳn (8 tool call có chủ đích, breakdown đúng theo từng đơn
vị) dù tốn token nhiều nhất trong cả 5 câu (80,257) nhưng không chạm cap
(khác câu 4) — có thể do cách tổng phân bổ token giữa các bước khác nhau.

## Tổng kết đầy đủ (5/5 câu)

| Câu | Function-calling | ReAct |
|---|---|---|
| 1. Tổng số Finding mở | Đúng | Đúng |
| 2. 5 Finding mới nhất | Đúng | Đúng |
| 3. Finding liên quan Fortinet | Đúng | **Sai (2/2 lần thử)** |
| 4. Finding HIGH của EVNGENCO3 | Đúng (chạm token cap) | Đúng |
| 5. Tổng hợp Finding theo đơn vị | Đúng | **Sai** |

- **Tỷ lệ đúng: function-calling 5/5 (100%); ReAct 3/5 (60%)** — ReAct
  thất bại nhất quán ở 2 câu đòi hỏi tổng hợp/lọc chéo nhiều nguồn dữ
  liệu (câu 3, câu 5), trong khi vẫn đáng tin cậy ở câu tra cứu đơn giản
  1-2 bước (câu 1, 2, 4).
- ReAct tiết kiệm token đáng kể ở hầu hết câu (68-76% ở câu 1-2, tới 86%
  ở câu 5) nhờ không gửi lại toàn bộ JSON schema của 60 tool mỗi bước —
  NGOẠI TRỪ khi cần nhiều bước retry/gọi trùng lặp do không tổng hợp
  được (câu 3 lần 2: 26,784 token, gần bằng function-calling).
- Function-calling ở câu 4 chạm `TOKEN_SOFT_CAP=50,000` — bằng chứng cho
  thấy system prompt hiện tại (được gửi lại nguyên vẹn mỗi bước LLM
  trong function-calling) đã phình to đủ để trở thành rủi ro thực tế
  cho các câu hỏi cần >= 2 bước tool call, không chỉ là giả thuyết lý
  thuyết.
- **Kết luận cho Chương 3**: function-calling xứng đáng là chế độ
  chính (100% đúng, xử lý tốt cả câu đơn giản lẫn phức tạp); ReAct phù
  hợp vai trò fallback nhưng có giới hạn thực sự với câu hỏi tổng hợp
  đa nguồn — cần lưu ý này khi ReAct được kích hoạt tự động (function-
  calling thất bại rồi fallback ReAct) cho đúng loại câu hỏi phức tạp,
  khả năng cao nó cũng sẽ thất bại theo, không chỉ đơn thuần "chậm hơn
  nhưng vẫn đúng" như giả định ban đầu.
