"""LLM narrative for report Executive Summary.

3-paragraph structure:
  1. Overview -- số liệu tổng quan + trend
  2. Key threats -- top 3-5 finding/campaign/IP đáng chú ý
  3. Recommendations -- hành động ưu tiên cho tuần tới
"""
from __future__ import annotations

import logging
import re

from ati_evn.config import get_settings
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.reports.narrative")

_PARAGRAPH_LABEL_RE = re.compile(r"^\s*Đoạn\s*\d\s*[:\-–]\s*", re.IGNORECASE | re.MULTILINE)


def _postprocess_narrative(text: str) -> str:
    """Check for truncation (log only, doesn't change output), then
    strip the "Đoạn N:" labels the system prompt asks the LLM to use
    to self-structure the 3 paragraphs -- those labels are how we
    verify structure, but they read as scaffolding in the final report
    so they're removed before the text reaches the template.
    """
    text = text.strip()

    if text and text.rstrip()[-1] not in ".!?)":
        logger.warning("Narrative may be truncated (ends without punctuation): last 100 chars: %r", text[-100:])

    if "Đoạn 3" not in text:
        logger.warning("Narrative missing Đoạn 3 (Recommendations section). Length: %d chars", len(text))

    return _PARAGRAPH_LABEL_RE.sub("", text).strip()

SYSTEM_PROMPT = """Bạn là SOC lead analyst của EVN (Tập đoàn Điện lực
Việt Nam) viết Executive Summary cho báo cáo Cyber Threat Intelligence
tuần này. Viết TIẾNG VIỆT, giữ nguyên thuật ngữ tiếng Anh cho các khái
niệm kỹ thuật (CVE, IOC, ATT&CK, phishing, C2, botnet, typosquat, ...).

Cấu trúc BẮT BUỘC 3 đoạn:

Đoạn 1 - Overview: 3-5 câu tổng quan về số lượng finding, phân bố
theo severity, source chính, customer bị ảnh hưởng nhiều nhất. Chỉ tóm
tắt số liệu -- không diễn giải quá sâu.

Đoạn 2 - Key threats: 3-5 mối đe dọa nổi bật nhất tuần này, có thể
là (a) CRITICAL finding, (b) campaign đang active, (c) brand abuse thật,
(d) document leak, (e) malicious IP score cao. Mỗi mối đe dọa 1-2 câu
mô tả cụ thể (nêu tên IOC, CVE, domain, IP thật).

Đoạn 3 - Recommendations: 3-4 hành động ưu tiên tuần sau, cụ thể
theo dữ liệu vừa thấy. Ví dụ: "Patch CVE-2024-XXXX cho ManageEngine
đang chạy tại NPC", "Request takedown evngov.cc qua urlscan",
"Rotate credentials nếu có match trong document leak".

KHÔNG dùng markdown heading (##, **). Dùng "Đoạn 1:", "Đoạn 2:",
"Đoạn 3:" ở đầu mỗi đoạn để phân biệt.
"""


async def generate_narrative(report_data: dict) -> str:
    """Generate 3-paragraph Executive Summary from gathered data."""
    settings = get_settings()
    client = LLMClient(settings)

    meta = report_data.get("meta", {})
    findings = report_data.get("findings", {})
    campaigns = report_data.get("campaigns", {})
    exposures = report_data.get("exposures", {})
    doc_leaks = report_data.get("document_leaks", {})
    brand = report_data.get("brand_abuse", {})
    malicious_ips = report_data.get("malicious_ips", {})

    context = {
        "window_days": meta.get("window_days"),
        "customer_count": meta.get("customer_count"),
        "findings_total": findings.get("total"),
        "findings_by_severity": findings.get("by_severity"),
        "findings_by_source_top5": (findings.get("by_source") or [])[:5],
        "findings_by_customer_top5": (findings.get("by_customer") or [])[:5],
        "top_critical_5": [
            {"title": t["title"], "severity": t["severity"], "customer": t["customer"], "sources": t["sources"]}
            for t in (findings.get("top_critical") or [])[:5]
        ],
        "campaign_count": campaigns.get("total"),
        "active_campaigns_top3": (campaigns.get("list") or [])[:3],
        "exposure_count": exposures.get("in_window"),
        "doc_leak_count": doc_leaks.get("in_window"),
        "brand_abuse_count": brand.get("in_window"),
        "top_brand_abuse_3": [
            {"page_domain": s["page_domain"], "rule": s["rule_matched"]}
            for s in (brand.get("sightings") or [])[:3]
        ],
        "malicious_ip_top5": [
            {"ip": i["ip"], "score": i["aggregate_risk_score"], "verdicts": i["verdicts"]}
            for i in (malicious_ips.get("list") or [])[:5]
        ],
    }

    prompt = (
        f"Dữ liệu tuần này ({meta.get('window_days')} ngày):\n"
        f"{context}\n\n"
        "Viết Executive Summary 3 đoạn theo cấu trúc quy định."
    )

    try:
        text = await client.chat_text(
            system=SYSTEM_PROMPT,
            user=prompt,
            max_tokens=settings.report_llm_max_tokens,
            temperature=0.3,
        )
    except Exception as e:
        logger.exception("Narrative LLM failed")
        return (
            f"Đoạn 1: [LLM narrative không khả dụng: {e}]\n\n"
            f"Đoạn 2: Xem chi tiết ở 8 section bên dưới.\n\n"
            f"Đoạn 3: Ưu tiên xử lý các finding CRITICAL và HIGH "
            f"theo thứ tự severity trong section 1."
        )

    return _postprocess_narrative(text)


CUSTOMER_SYSTEM_PROMPT = """Bạn là SOC lead analyst của EVN viết
Executive Summary cho một customer cụ thể của EVN (ví dụ EVN NPC,
GENCO1). Report này gửi cho executive của customer đó. Viết
TIẾNG VIỆT, giữ nguyên English cho thuật ngữ kỹ thuật.

Cấu trúc BẮT BUỘC 3 đoạn:

Đoạn 1 - Overview: 2-4 câu tổng quan cho CUSTOMER NÀY: số finding,
phân bố severity, exposure/leak/brand abuse có liên quan trực tiếp.

Đoạn 2 - Key threats: 2-4 mối đe dọa cụ thể ảnh hưởng customer này.
Nêu tên asset, CVE, IP, domain THẬT từ dữ liệu.

Đoạn 3 - Recommendations: 2-4 hành động ưu tiên cho customer này.
Cụ thể theo dữ liệu (patch CVE X trên asset Y, request takedown
domain Z, rotate credentials sau doc leak, ...).

Nếu customer không có finding nào trong kỳ ("all clear"), viết ngắn
gọn xác nhận và khuyến nghị giữ nguyên baseline monitoring.

KHÔNG dùng markdown heading. Dùng "Đoạn 1:", "Đoạn 2:", "Đoạn 3:"
ở đầu mỗi đoạn.
"""


async def generate_customer_narrative(report_data: dict) -> str:
    settings = get_settings()
    client = LLMClient(settings)

    meta = report_data["meta"]
    customer = meta["customer"]
    findings = report_data["findings"]
    exposures = report_data["exposures"]
    doc_leaks = report_data["document_leaks"]
    brand = report_data["brand_abuse"]
    malicious_ips = report_data["malicious_ips"]

    context = {
        "customer_name": customer["name"],
        "customer_short_code": customer["short_code"],
        "window_days": meta["window_days"],
        "findings_total": findings["total"],
        "findings_by_severity": findings["by_severity"],
        "findings_by_source": findings["by_source"][:5],
        "top_critical_5": [
            {"title": t["title"], "severity": t["severity"], "ioc": t.get("ioc_value"), "asset": t.get("matched_asset")}
            for t in findings["top_critical"][:5]
        ],
        "exposure_count": exposures["in_window"],
        "exposure_examples": [
            {"ip": e["ip"], "port": e["port"], "service": e["service"]}
            for e in exposures["list"][:3]
        ],
        "doc_leak_count": doc_leaks["in_window"],
        "doc_leak_examples": [
            {"file": d["filename"], "bucket": d["bucket_url"]}
            for d in doc_leaks["sightings"][:3]
        ],
        "brand_abuse_count": brand["in_window"],
        "brand_abuse_examples": [
            {"domain": s["page_domain"], "rule": s["rule_matched"]}
            for s in brand["sightings"][:3]
        ],
        "malicious_ips_count": malicious_ips["total"],
    }

    prompt = (
        f"Customer: {customer['name']} ({customer['short_code']})\n"
        f"Kỳ báo cáo: {meta['window_days']} ngày\n"
        f"Dữ liệu:\n{context}\n\n"
        "Viết Executive Summary 3 đoạn cho customer này."
    )

    try:
        text = await client.chat_text(
            system=CUSTOMER_SYSTEM_PROMPT,
            user=prompt,
            max_tokens=settings.report_llm_max_tokens,
            temperature=0.3,
        )
    except Exception as e:
        logger.exception("Customer narrative LLM failed")
        return (
            f"Đoạn 1: [LLM narrative không khả dụng: {e}]\n\n"
            f"Đoạn 2: Xem chi tiết ở các section bên dưới.\n\n"
            f"Đoạn 3: Ưu tiên các finding CRITICAL/HIGH của {customer['name']}."
        )
    return _postprocess_narrative(text)
