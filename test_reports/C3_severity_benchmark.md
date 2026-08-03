# Giai đoạn C — Nhóm test 3: Severity scoring benchmark 8 sự cố (mục 3.3.3)

```bash
$ python tests/smoke/test_severity_benchmark.py
```

## Kết quả đầy đủ

```
Benchmark cases: 8

ID                   CVE                Expected   Actual     Score  Pass
--------------------------------------------------------------------------------
log4shell            CVE-2021-44228     CRITICAL   CRITICAL   100    PASS
eternalblue          CVE-2017-0144      CRITICAL   CRITICAL    87    PASS
heartbleed           CVE-2014-0160      CRITICAL   CRITICAL   100    PASS
struts-equifax       CVE-2017-5638      CRITICAL   CRITICAL   100    PASS
internal-poc-only-moderate SYNTHETIC-MODERATE-01 HIGH       HIGH        51    PASS
air-gapped-critical-cvss-no-exploit SYNTHETIC-AIRGAPPED-01 MEDIUM     MEDIUM      39    PASS
low-severity-baseline SYNTHETIC-LOW-01   LOW        LOW         18    PASS
printnightmare       CVE-2021-34527     CRITICAL   CRITICAL    89    PASS
--------------------------------------------------------------------------------
Total: 8/8  (100% accuracy)
```

## Bảng chi tiết 8 sự cố

| # | Tên sự cố | CVE / mã | Điểm số | Nhóm nghiêm trọng dự đoán | Nhóm thực tế | Kết quả |
|---|---|---|---|---|---|---|
| 1 | log4shell | CVE-2021-44228 | 100 | CRITICAL | CRITICAL | PASS |
| 2 | eternalblue | CVE-2017-0144 | 87 | CRITICAL | CRITICAL | PASS |
| 3 | heartbleed | CVE-2014-0160 | 100 | CRITICAL | CRITICAL | PASS |
| 4 | struts-equifax | CVE-2017-5638 | 100 | CRITICAL | CRITICAL | PASS |
| 5 | internal-poc-only-moderate | SYNTHETIC-MODERATE-01 | 51 | HIGH | HIGH | PASS |
| 6 | air-gapped-critical-cvss-no-exploit | SYNTHETIC-AIRGAPPED-01 | 39 | MEDIUM | MEDIUM | PASS |
| 7 | low-severity-baseline | SYNTHETIC-LOW-01 | 18 | LOW | LOW | PASS |
| 8 | printnightmare | CVE-2021-34527 | 89 | CRITICAL | CRITICAL | PASS |

## Nhận xét

- **8/8 đúng (100% accuracy)** — cả 4 sự cố CVE thật nổi tiếng (Log4Shell,
  EternalBlue, Heartbleed, Struts/Equifax, PrintNightmare — tổng 5 case
  CVE thật) lẫn 3 case tổng hợp (synthetic) kiểm tra riêng biệt các yếu
  tố ngữ cảnh (nội bộ/PoC-only, air-gapped dù CVSS cao, baseline thấp)
  đều được scoring engine phân loại đúng nhóm nghiêm trọng.
- Điểm số trải rộng hợp lý theo mức độ (18 → 100), không có hiện tượng
  dồn cụm hay overfit vào 1 khoảng điểm — cho thấy công thức chấm điểm
  phân biệt được các mức độ nghiêm trọng khác nhau, không chỉ đơn thuần
  đúng/sai nhị phân.
- 2 case đáng chú ý về mặt thiết kế: case 6 (air-gapped-critical-cvss-
  no-exploit) chứng minh hệ thống không chỉ dựa vào CVSS thô — một CVE
  có CVSS cao nhưng ở môi trường air-gapped, không có exploit công khai
  vẫn được hạ xuống MEDIUM đúng logic; case 5 (internal-poc-only-
  moderate) cho thấy hệ thống phân biệt được PoC nội bộ (không phải
  active exploitation) để xếp HIGH thay vì CRITICAL.

## Kết luận

Severity scoring engine đạt độ chính xác tuyệt đối trên bộ benchmark
chuẩn hoá 8 sự cố, bao gồm cả CVE thực tế lịch sử lẫn case tổng hợp
kiểm tra các yếu tố ngữ cảnh đặc thù (network exposure, exploit
availability, environment). Không phát hiện regression hay sai lệch
nào trong lần chạy này.
