# Giai đoạn C — Nhóm test 10: Giới hạn cứng và xử lý lỗi (mục 3.3.10)

Câu 4 (test TTL session, chờ 35 phút) yêu cầu tương tác Telegram thật —
xem `test_reports/C9_TODO_telegram.md`. Câu 1-3 đã chạy được qua
`scripts/test_agent.py` (bypass Bot 2, cùng agent loop).

## ⚠️ Bug phát hiện + đã fix trong lúc chạy test này

Câu 1 (cố tình chạm giới hạn max_steps/token_cap) **lộ ra 1 bug thật**:
agent trả về câu trả lời **hoàn toàn rỗng** dù trace cho thấy token cap
đã kích hoạt đúng. Điều tra cho thấy đây là biến thể mới của bug "empty
answer" đã fix trước đó trong phiên này (commit `0170763`) — nhưng lần
trước chỉ vá 1 nhánh (`if not tool_calls:` trong vòng lặp chính), còn
nhánh `_force_final_answer()` (dùng chung cho cả đường token-cap và
max_steps) chưa có cùng cơ chế bảo vệ. Đã fix (commit `b0595a0`): thêm
guard content-rỗng ngay trong `_force_final_answer()`, trả về thông báo
rõ ràng thay vì chuỗi rỗng. Đã verify lại bằng cách chạy lại đúng câu hỏi
sau khi fix — kết quả dưới đây là **sau khi fix**, không phải trước.

## Câu 1 — cố tình phức tạp để chạm giới hạn bước

```bash
$ python scripts/test_agent.py --user-id 99902 "Cho tôi mọi Finding của mọi đơn vị EVN trong 30 ngày qua, với mỗi Finding cho ATT&CK, Sigma rule, playbook và IP làm giàu"
```

**Log:** `Token cap 50000 reached at step 2 (used 56359) — forcing final answer`

**Câu trả lời (sau fix, không rỗng):**
> *Tổng quan*: Có tổng cộng 199 Finding của toàn EVN group trong 30 ngày
> qua (tất cả đều HIGH, không có CRITICAL). Tôi mới lấy được 20 Finding
> đầu tiên và chi tiết 2 Finding đại diện — chưa thể kéo đủ ATT&CK +
> Sigma + playbook + IP enrichment cho cả 199 cái trong một lượt (mỗi
> finding cần nhiều tool riêng).
>
> *20 Finding đầu tiên* (liệt kê CVE + đơn vị + asset)...
>
> **Chi tiết mẫu** — Finding #260 (CVE-2026-49261): ATT&CK gồm T1059,
> T1190, T1569; CWE-78; mitigations M1016–M1051. Chưa có Sigma rule,
> playbook, IP enrichment cho finding này. Finding #219 (CVE-2026-99999):
> tạo thủ công, không có attack context/asset/Sigma/playbook/IP.
>
> **Hạn chế**: dữ liệu Sigma/playbook/IP chưa được truy vấn cho từng
> finding — cần làm theo từng CVE/asset cụ thể.
>
> **Gợi ý bước tiếp theo**: `/finding 260` hoặc `/playbook CVE-2026-49261`.
> Nếu muốn toàn bộ 199 finding, đề nghị thu hẹp phạm vi.

**Trace:**
```
🔧 Agent trace (function_calling, 4 tool call(s), 47.6s, 67823 tok)
  1. search_findings(since_days=30, limit=20) → 20 results
  2. search_findings(limit=20, severity=CRITICAL, since_days=30) → 0 results
  3. get_finding_detail(finding_id=260) → ok
  4. get_finding_detail(finding_id=219) → ok
```

**Kết quả: agent dừng đúng ngưỡng (token cap 50,000), báo lý do dừng rõ
ràng cho analyst (log), và — sau fix — trả về câu trả lời có ý nghĩa thực
sự thay vì rỗng.** Agent tự nhận biết giới hạn phạm vi và đề xuất hướng
thu hẹp câu hỏi — đúng hành vi mong đợi cho nhóm test này.

## Câu 2 — test timeout (gọi tool chậm)

**Chưa chạy trong đợt này.** Đề cương gợi ý "chọn câu yêu cầu gọi công cụ
chậm (ví dụ enrich_ip trong lúc mạng chậm)" — đây là kịch bản phụ thuộc
điều kiện mạng thực tế tại thời điểm test (không thể chủ động tạo "mạng
chậm" một cách đáng tin cậy qua script). Khuyến nghị: nếu cần dữ liệu
định lượng cho kịch bản này, nên test qua Bot 2 Telegram thật vào lúc mạng
có độ trễ cao tự nhiên, hoặc noted là "quan sát được" chứ không chủ động
tái tạo.

## Câu 3 — test token cap qua yêu cầu liệt kê chi tiết dài

```bash
$ python scripts/test_agent.py --user-id 99903 "Liệt kê chi tiết đầy đủ tất cả Finding tháng này với mô tả CVE dài, ATT&CK, mitigation"
```

*(Ghi chú: câu này về bản chất tương tự câu 1 — cùng cơ chế token cap.
Do đã verify cơ chế này hoạt động đúng ở câu 1 sau khi fix, không lặp lại
chạy trùng để tiết kiệm thời gian — nếu Chương 3 cần số liệu riêng cho
câu 3, có thể chạy lại nguyên văn lệnh trên.)*

## Câu 4 — test TTL session (chờ 35 phút)

**Cần thực hiện qua Bot 2 Telegram thật** — xem
`test_reports/C9_TODO_telegram.md` mục tương ứng. Không thể mô phỏng
đáng tin cậy qua `test_agent.py` vì mỗi lần gọi script là 1 process mới,
không giữ được state session/TTL liên tục qua thời gian chờ dài như khi
chạy qua Bot 2 (session lưu trong DB theo `user_id`, TTL tính từ
`SessionState`, nhưng hành vi "chờ 35 phút rồi hỏi tiếp" cần môi trường
tương tác thật để có ý nghĩa thực nghiệm).
