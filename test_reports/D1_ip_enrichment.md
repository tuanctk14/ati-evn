# Giai đoạn D1 — Multi-provider IP enrichment (3 IP đại diện)

## Khác biệt so với đề cương

- Ban đầu định dùng `8.8.8.8` làm ví dụ "IP sạch" — **đã đổi sang
  `192.0.2.100`** vì `8.8.8.8` là Google Public DNS quá nổi tiếng, tính
  minh họa "IP thật sự trung tính" không cao (và thực tế enrichment vẫn
  có 1 provider — LeakIX — báo "suspicious" nhẹ cho nó, làm ví dụ kém rõ
  ràng). `192.0.2.100` là IP trong dải TEST-NET-1 (RFC 5737,
  documentation-only), có sẵn dữ liệu enrichment cache thật trong hệ
  thống, và cho kết quả "benign" đồng thuận tuyệt đối ở cả 5 provider —
  ví dụ "sạch" rõ ràng hơn.

## IP 1 — Sạch (`192.0.2.100`)

```json
{
  "aggregate_risk_score": 0.0,
  "max_provider_score": 0.0,
  "confidence_score": 0.0,
  "coverage_score": 1.0,
  "positive_provider_count": 0,
  "supporting_provider_count": 0,
  "responded_provider_count": 5,
  "consensus_status": "consensus",
  "provider_verdicts": {
    "abuseipdb": "benign", "otx": "benign", "pulsedive": "benign",
    "leakix": "benign", "virustotal": "benign"
  }
}
```
**Diễn giải:** 5/5 provider đồng thuận "benign", risk_score=0, coverage
100% — trường hợp lý tưởng, không có tín hiệu nghi ngờ nào.

## IP 2 — Nhiều cảnh báo (`185.220.101.99`)

```json
{
  "aggregate_risk_score": 78.7,
  "max_provider_score": 100.0,
  "confidence_score": 0.6,
  "coverage_score": 1.0,
  "positive_provider_count": 3,
  "supporting_provider_count": 5,
  "responded_provider_count": 5,
  "consensus_status": "consensus",
  "provider_mask": "abuseipdb|otx|virustotal",
  "provider_verdicts": {
    "abuseipdb": "malicious", "virustotal": "malicious", "otx": "malicious",
    "leakix": "suspicious", "pulsedive": "suspicious"
  }
}
```
**Diễn giải:** 3/5 provider xác nhận "malicious" (AbuseIPDB, VirusTotal,
OTX — điểm 90-100), 2/5 còn lại "suspicious" (LeakIX, Pulsedive) — tất cả
5 provider đều hướng cùng chiều tiêu cực → `consensus_status=consensus`,
risk_score cao (78.7/100), confidence 0.6.

## IP 3 — Tranh cãi (`50.16.16.211`)

```json
{
  "aggregate_risk_score": 47.33,
  "max_provider_score": 100.0,
  "confidence_score": 0.2,
  "coverage_score": 1.0,
  "positive_provider_count": 1,
  "supporting_provider_count": 2,
  "responded_provider_count": 5,
  "consensus_status": "disputed",
  "provider_mask": "pulsedive",
  "provider_verdicts": {
    "pulsedive": "malicious", "virustotal": "suspicious",
    "abuseipdb": "benign", "leakix": "unknown", "otx": "unknown"
  }
}
```
**Diễn giải:** Pulsedive báo "malicious" (100 điểm) nhưng AbuseIPDB lại
báo "benign" (15 điểm) — 2 provider mâu thuẫn trực tiếp, 2 provider khác
"unknown" (không đủ dữ liệu) → `consensus_status=disputed`, confidence
thấp (0.2) dù risk_score trung bình vẫn ở mức đáng chú ý (47.33) do
trọng số Pulsedive cao. Đây là ví dụ rõ ràng cho giá trị của cơ chế
multi-provider consensus: nếu chỉ dựa 1 nguồn (ví dụ chỉ Pulsedive),
phân tích sẽ kết luận "malicious" quá tự tin; nếu chỉ dựa AbuseIPDB, kết
luận ngược lại "benign" — consensus tổng hợp giúp phản ánh đúng mức độ
không chắc chắn thực tế.

## Bảng tổng hợp

| IP | risk_score | confidence | coverage | consensus_status | Số provider đồng thuận |
|---|---|---|---|---|---|
| 192.0.2.100 (sạch) | 0.0 | 0.0 | 1.0 | consensus | 5/5 benign |
| 185.220.101.99 (nhiều cảnh báo) | 78.7 | 0.6 | 1.0 | consensus | 5/5 tiêu cực (3 malicious + 2 suspicious) |
| 50.16.16.211 (tranh cãi) | 47.33 | 0.2 | 1.0 | disputed | mâu thuẫn (malicious vs benign) |
