# Giai đoạn C — Nhóm test 9 (phần bổ sung): Sigma rule + Playbook qua free-text agent

Phần **Báo cáo** (report generation) đã chạy xong trước đó, xem
`C9_report_generation.md`. File này bổ sung phần Sigma + Playbook qua
Bot 2 Telegram — free-text agent flow dùng 2 tool mới xây dựng trong
phiên này (`generate_sigma_rule`, `generate_playbook`), không phải gọi
slash-command trực tiếp.

## Sigma rule (2 câu)

### Câu 1 — "Tìm Sigma rule cho CVE-2021-34527" (CVE có community rule)

**Lưu ý điều chỉnh so với đề cương gốc**: lần thử đầu tiên dùng động từ
"Tạo" (map `force_regen=True` theo policy đã fix trong phiên: "sinh/
tạo" luôn AI-generate mới, bỏ qua community rule dù có sẵn) — kết quả
đúng theo thiết kế nhưng KHÔNG khớp ý đồ đề cương (muốn đo tỷ lệ tìm
được rule cộng đồng). Đổi sang "Tìm" (map `force_regen=False`) để đúng
ý đồ gốc.

- **Kết quả**: tìm thấy community rule trực tiếp (SigmaHQ, id=3227
  "Remote Printing Abuse for Lateral Movement", confidence 0.9, tagged
  đúng `CVE-2021-34527` trong DB). Hiện nguyên văn YAML đầy đủ.
- **Thời gian**: 12.8s
- **Nguồn rule**: `community_direct`

### Câu 2 — "Tìm Sigma rule cho cve-2026-49261" (CVE không có community rule trực tiếp)

- **Kết quả**: không có community rule trực tiếp; trả về rule
  ATT&CK-behavioral-overlap ("Windows Defender AMSI Trigger Detected",
  khớp qua T1059, confidence 0.5). Agent tự cảnh báo rõ ràng: confidence
  thấp, rule không đặc thù cho CVE này, khuyến nghị không triển khai
  trực tiếp mà cân nhắc sinh AI rule riêng nếu cần.
- **Thời gian**: 15.6s
- **Nguồn rule**: `community_behavioral`

**Tỷ lệ tìm được rule cộng đồng**: 2/2 câu đều tìm được rule cộng đồng
ở tier phù hợp (1 direct, 1 behavioral) — không có câu nào phải
AI-generate mới trong đợt test "Tìm" (đúng kỳ vọng vì đây là bộ câu hỏi
chọn có chủ đích để test cả 2 tier). Đối chứng: khi cùng CVE-2021-34527
được hỏi bằng "Tạo" thay vì "Tìm", agent bỏ qua community rule có sẵn
và AI-generate mới — xác nhận đúng phân biệt ý định "tìm" vs "tạo" theo
policy đã fix trong phiên (xem `C6_multistep_chaining.md`).

## Playbook (3 câu: 2 cache MISS + 1 cache HIT)

### Câu 3 — "Tạo playbook ứng phó cho cve-2026-47295 ở phân đoạn IT" (cache MISS)

- **Kết quả**: playbook đầy đủ 5 section NIST 800-61 (Identification →
  Containment → Eradication → Recovery → Lessons Learned), nội dung cụ
  thể cho SQL Server 2016 SQL injection, đúng phân đoạn `internal_it`
  (nhấn mạnh patching + credential rotation, đúng theo system prompt
  của `playbook.py`).
- **Thời gian**: 38.6s (cache MISS, gọi LLM sinh mới)

### Câu 4 — "Tạo playbook ứng phó cho CVE-2026-49261 ở phân đoạn OT điều khiển" (cache MISS)

- **Kết quả**: playbook đầy đủ cho MariaDB Galera command injection
  (CVSS 10.0), đúng tone cho phân đoạn OT (`ot_control`) — nhấn mạnh an
  toàn vận hành, phối hợp kỹ sư nhà máy, KHÔNG tự ý restart/dừng dịch
  vụ giữa chừng nếu chưa được phê duyệt — đúng yêu cầu đặc thù SCADA
  trong system prompt.
- **Thời gian**: 42.7s (cache MISS)

### Câu 5 — lặp lại câu 3 y nguyên (test cache HIT)

- **Kết quả**: nội dung markdown giống hệt câu 3 (xác nhận đúng cache
  key `(cve_id, network_segment)`). DB xác nhận cache HIT thật:
  `playbook_cache.reused_count` tăng từ 0 → 1 cho
  `(CVE-2026-47295, internal_it)`.
- **Thời gian**: 59.2s (**LÂU HƠN cache MISS**, xem phát hiện bên dưới)

## Phát hiện: cache HIT không nhanh hơn khi truy cập qua agent tool (không phải bug)

Trái với kỳ vọng "cache hit gần như tức thì", câu 5 (cache HIT, xác
nhận qua `reused_count`) mất **59.2s**, chậm hơn cả câu 3 (cache MISS,
38.6s). Nguyên nhân: khác với slash-command `/playbook` (trả thẳng
markdown đã cache cho Telegram, không gọi LLM thêm), **agent tool**
`generate_playbook` vẫn phải đi qua nguyên vòng lặp function-calling —
LLM đọc kết quả tool (markdown ~1800 từ) rồi tự soạn lại câu trả lời
tường thuật xung quanh nó. Cache chỉ tiết kiệm được bước SINH nội dung
playbook (LLM call bên trong `_get_or_generate()`), không tiết kiệm
được bước LLM composing câu trả lời cho analyst — nên tổng thời gian
đầu-cuối qua free-text KHÔNG phản ánh đúng lợi ích cache như khi dùng
slash-command trực tiếp. Đã ghi vào `scripts/audit_14b_backlog.md` như
một lưu ý (không phải bug) cho phần Limitations/Discussion của luận
văn — nên phân biệt rõ "cache hit ở tầng DB/tool" (verified, hoạt động
đúng) với "cache hit có cảm nhận được ở tầng UX free-text" (không, vì
agent-loop overhead che lấp lợi ích).

## Tổng kết

| # | Câu hỏi | Loại | Kết quả | Thời gian |
|---|---|---|---|---|
| 1 | Tìm Sigma rule CVE-2021-34527 | community_direct | ĐÚNG | 12.8s |
| 2 | Tìm Sigma rule cve-2026-49261 | community_behavioral | ĐÚNG | 15.6s |
| 3 | Tạo playbook CVE-2026-47295 / IT | cache MISS | ĐÚNG | 38.6s |
| 4 | Tạo playbook CVE-2026-49261 / OT | cache MISS | ĐÚNG | 42.7s |
| 5 | Tạo playbook CVE-2026-47295 / IT (lặp lại) | cache HIT | ĐÚNG (nội dung), chậm hơn MISS (thời gian) | 59.2s |

**5/5 câu đúng về nội dung/logic.** Không phát hiện bug mới trong đợt
test này — cả 2 tool mới (`generate_sigma_rule`, `generate_playbook`,
xây dựng đầu phiên để lấp gap phát hiện ở Nhóm test 6) hoạt động ổn
định qua free-text, đúng 3-tier logic Sigma và cache logic Playbook.
Điểm cần lưu ý duy nhất là caveat về cảm nhận hiệu năng cache qua agent
tool (không phải lỗi chức năng).
