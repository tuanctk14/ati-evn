# Giai đoạn C — Nhóm test 4: Làm giàu ATT&CK và Sigma matching (mục 3.3.4)

## Khác biệt so với đề cương

1. **`enrich_findings.py` mặc định chỉ xử lý finding CHƯA có `attack_context`.**
   Lần chạy đầu (`python scripts/enrich_findings.py --limit 30`, không cờ
   khác) trả về **"Empty context: 30/30"** — nhìn tưởng là lỗi, nhưng điều
   tra kỹ cho thấy 30 finding đầu tiên đủ điều kiện xử lý đều là **legacy
   non-CVE finding** (ipv4, exposure, exposed_document, brand_abuse — cùng
   nhóm 58 finding `correlation_type=NULL` đã thấy ở Nhóm test 2).
   `enrich_finding()` chỉ suy luận ATT&CK technique cho `ioc_type='cve_id'`
   qua CWE chain hoặc BERT semantic trên mô tả CVE — với finding phi-CVE,
   trả về context rỗng là **đúng thiết kế**, không phải bug.
2. Vì gần như toàn bộ finding CVE hiện có (220/221) đã enrich từ các phiên
   test trước, chỉ còn **1 CVE finding thật sự thiếu context**. Để có mẫu
   đủ lớn minh họa cho Chương 3, đã chạy lại với `--only-cve --force
   --limit 30` (re-enrich 30 finding CVE, ghi đè context cũ) thay vì chạy
   mặc định.
3. **5 CVE nổi tiếng trong đề cương gốc** (`CVE-2021-44228` Log4Shell,
   `CVE-2017-0144` EternalBlue, `CVE-2021-34527` PrintNightmare,
   `CVE-2023-34362` MOVEit, `CVE-2024-21762` FortiOS) **không tồn tại**
   trong `detections`/`findings` của DB test này (dữ liệu ingest chỉ có
   CVE thật cũ 2000-2006 hoặc CVE giả lập năm 2026/2025). Tuy nhiên,
   riêng tầng **Sigma rule** (`sigma_rules`, đồng bộ trực tiếp từ SigmaHQ
   community, độc lập với dữ liệu Detection/Finding test) vẫn chứa các
   CVE này trong `cve_refs` của một số rule thật — nên bộ 5 CVE gốc **vẫn
   dùng được cho test Sigma matching** (không cần thay thế), dù không
   dùng được cho test enrichment/agent (không có Finding tương ứng).

## Chạy `enrich_findings.py`

```
$ python scripts/enrich_findings.py --only-cve --force --limit 30
[OK] BERT mapper loaded (846 techniques cached).
[INFO] 30 findings queued for enrichment.
  [20/30] enriched, 11.9/s, elapsed 1.7s
  [30/30] enriched, 13.0/s, elapsed 2.3s

============================================================
  Enrichment Complete
============================================================
  Total processed      : 30
  Successfully enriched: 30
  Empty context         : 0
  Errors                : 0
  SMET used             : 30
  Chain used            : 27
  IOC heuristic used    : 0
  Total techniques      : 301
  Elapsed               : 2.3s
============================================================
```

**Nhận xét:** 100% (30/30) finding dùng BERT semantic similarity (SMET),
90% (27/30) đồng thời có deterministic CWE-chain match — cho thấy 2 tầng
enrichment hoạt động bổ trợ nhau (chain cho match chắc chắn, SMET mở rộng
phạm vi phát hiện technique không map trực tiếp qua CWE). Trung bình
~10 technique/finding (301/30).

## Số Finding có `attack_context` (toàn DB, không chỉ batch vừa chạy)

```sql
SELECT count(*) FROM findings WHERE metadata::jsonb ? 'attack_context';
```

**Kết quả: 221 / 257 finding (86.0%)** có attack_context — 36 finding còn
lại là phần lớn thuộc 58 legacy non-CVE finding đã nêu ở mục 1.

**⚠️ Lưu ý cột tên:** đề cương dùng cú pháp `metadata_ ? 'attack_context'`
— tên cột thật của bảng `findings` là **`metadata`** (không có dấu gạch
dưới cuối), và cần ép kiểu `::jsonb` vì cột này khai báo kiểu `json` chứ
không phải `jsonb` (toán tử `?` chỉ áp dụng cho jsonb).

## Tỷ lệ dùng BERT (SMET) vs chỉ CWE-chain (toàn DB)

```sql
SELECT (metadata::jsonb->'attack_context'->>'smet_used')::bool AS via_bert, count(*)
FROM findings WHERE metadata::jsonb ? 'attack_context' GROUP BY via_bert;
```

| via_bert | count | % |
|---|---|---|
| false (chỉ CWE-chain) | 191 | 86.4% |
| true (có dùng SMET) | 30 | 13.6% |

**Diễn giải:** đây là số liệu tích lũy toàn bộ 221 finding (không chỉ 30
vừa re-enrich) — phần lớn finding trong lịch sử test được enrich bằng
CWE-chain thuần (deterministic, nhanh hơn), chỉ 30 finding vừa chạy lại
lần này có SMET (vì `--force` ghi đè, và các lần enrich trước trong lịch
sử dự án phần lớn dùng chain-only mode `--no-bert` để tiết kiệm thời
gian test — không phải vì BERT hiếm khi kích hoạt được).

## Ví dụ Finding có ATT&CK context đầy đủ (dùng cho Hình 3.6)

Finding #16 — `cve-2026-48163`, kết hợp cả 2 nguồn (chain qua CWE-78 +
SMET semantic):

```json
{
  "cwe_ids": ["CWE-78"],
  "smet_used": true,
  "chain_used": true,
  "techniques": [
    {"id": "T1059", "name": "Command and Scripting Interpreter", "source": "chain", "confidence": 0.9, "chain_via_cwe": "CWE-78"},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "source": "chain", "confidence": 0.9, "chain_via_cwe": "CWE-78"},
    {"id": "T1569", "name": "System Services", "source": "chain", "confidence": 0.9, "chain_via_cwe": "CWE-78"},
    {"id": "T1570", "name": "Lateral Tool Transfer", "source": "smet", "confidence": 0.48},
    {"id": "T1074.002", "name": "Remote Data Staging", "source": "smet", "confidence": 0.471},
    {"id": "T1074", "name": "Data Staged", "source": "smet", "confidence": 0.459},
    {"id": "T1105", "name": "Ingress Tool Transfer", "source": "smet", "confidence": 0.437},
    {"id": "T1537", "name": "Transfer Data to Cloud Account", "source": "smet", "confidence": 0.415}
  ],
  "mitigations": [ /* 20 mitigation, ví dụ M1016 Vulnerability Scanning, M1030 Network Segmentation, M1051 Update Software */ ],
  "kill_chain_phases": ["collection", "command-and-control", "execution", "exfiltration", "initial-access", "lateral-movement"]
}
```

## Test Sigma rule matching (2 tầng: CVE-direct + behavior/ATT&CK)

Dùng đúng 5 CVE gốc trong đề cương (Sigma rule data độc lập với
Detection/Finding test, xem giải thích ở mục "Khác biệt" phía trên):

```bash
python scripts/test_tool.py search_sigma_rules --args='{"cve_id":"CVE-2021-44228"}'
python scripts/test_tool.py search_sigma_rules --args='{"cve_id":"CVE-2017-0144"}'
python scripts/test_tool.py search_sigma_rules --args='{"cve_id":"CVE-2021-34527"}'
python scripts/test_tool.py search_sigma_rules --args='{"cve_id":"CVE-2023-34362"}'
python scripts/test_tool.py search_sigma_rules --args='{"cve_id":"CVE-2024-21762"}'
```

| CVE | Tầng 1 (CVE-direct) | Tầng 2 (behavior/ATT&CK) |
|---|---|---|
| CVE-2021-44228 (Log4Shell) | 0 rule | 0 rule* |
| CVE-2017-0144 (EternalBlue) | 0 rule | 0 rule* |
| CVE-2021-34527 (PrintNightmare) | **1 rule** — "Remote Printing Abuse for Lateral Movement" (level=high, `rules/application/rpc_firewall/rpc_firewall_printing_lateral_movement.yml`) | — |
| CVE-2023-34362 (MOVEit) | 0 rule | 0 rule* |
| CVE-2024-21762 (FortiOS) | 0 rule | 0 rule* |

\* `search_sigma_rules` chỉ nhận `cve_id` làm tham số — tool không tự
động fallback sang tra theo ATT&CK technique nếu không có Finding tương
ứng để lấy `attack_context` (công cụ không có tham số `technique_id`
trực tiếp trong bộ test này). Vì 4/5 CVE trên không có Finding trong DB
test, tầng 2 (qua attack_context của Finding) không thể minh họa được
qua cùng lời gọi này — muốn test tầng 2 cần một Finding CVE thật đã
enrich xong (ví dụ Finding #16 ở trên) rồi tra Sigma theo `technique_id`
suy ra từ đó, không phải theo `cve_id` trực tiếp.

**Kết quả tổng: 1/5 CVE tìm được rule CVE-direct (20%).** Con số này
**khớp thống kê tổng thể** đã tính ở Giai đoạn B: chỉ 63/3142 rule
(2.0%) trong toàn bộ Sigma repo có gắn `cve_refs` — nên với 5 CVE bất kỳ
(kể cả CVE nổi tiếng), xác suất trúng rule CVE-direct vốn thấp. Đây là
minh chứng thực nghiệm hợp lý cho luận điểm "Tier-1 CVE-direct matching
hiếm, phần lớn phải dựa vào Tier-2 behavior/ATT&CK matching" mà Chương 3
cần trình bày.
