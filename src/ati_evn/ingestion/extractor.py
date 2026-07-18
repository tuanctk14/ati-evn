"""LLM-driven extraction from article text -> structured CTI data."""
from __future__ import annotations

import logging
import re

from ati_evn.config import get_settings
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.ingestion.extractor")

EXTRACTION_SYSTEM = """You are a Cyber Threat Intelligence (CTI) extraction
analyst for Vietnam Electricity (EVN) SOC. Given an article, blog post,
security report, or technical write-up, extract structured threat data.

Return JSON ONLY (no markdown fences, no preamble) matching this schema:

{
  "iocs": [
    {
      "type": "ipv4|ipv6|domain|url|md5|sha1|sha256|email",
      "value": "the exact IOC value",
      "context": "brief role in the article (e.g. 'C2 server', 'phishing landing', 'dropper hash')"
    }
  ],
  "cves": [
    {
      "id": "CVE-YYYY-NNNNN",
      "context": "how mentioned in article (e.g. 'exploited pre-auth', '2nd stage chain')"
    }
  ],
  "malware_families": ["Cobalt Strike", "Emotet"],
  "attack_techniques": ["T1190", "T1059"],
  "sectors_targeted": ["energy", "finance"],
  "attribution_hints": "concise attribution claim from article or 'Not attributed'",
  "summary": "Vietnamese 2-3 sentence summary -- narrative, not bullet list",
  "confidence": 0.85
}

## Rules

1. Extract ONLY what is EXPLICITLY in the article. NEVER hallucinate
   IOCs, CVE-IDs, or techniques.
2. Defang notation: if article writes "1[.]2[.]3[.]4" or "example[.]com",
   normalize to "1.2.3.4" and "example.com" (real IOC value, no brackets).
3. URLs: include only full URLs (with http:// or https://). Not just
   domain fragments -- those go as type=domain instead.
4. CVE IDs: uppercase (CVE-2024-38856), no lowercase.
5. attack_techniques: MITRE ATT&CK IDs only (T1XXX or T1XXX.001).
   Do not invent techniques the article doesn't mention.
6. malware_families: use canonical names ("Cobalt Strike" not "CobaltStrike",
   "Emotet" not "Feodo/Emotet").
7. confidence: your self-assessment of source quality + extraction
   completeness:
   - 0.9+ : peer-reviewed research (CrowdStrike, Mandiant, Kaspersky
     report), vendor advisory
   - 0.7-0.9: reputable news/blog (BleepingComputer, TheHackerNews),
     government advisory (CISA, VNCERT)
   - 0.5-0.7: anonymous blog, community post, indirect writeup
   - <0.5: unclear source, promotional content
8. summary: Vietnamese 2-3 sentences, English tech terms preserved
   (CVE-IDs, T-numbers, product/vendor names, malware names).
9. If article does NOT mention IOCs/CVEs/etc, return empty arrays.
   Do not invent to fill.
10. Return ONLY the JSON object. No markdown, no explanation, no
    "```json" fences.
"""

VALID_IOC_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


async def extract_from_text(text: str) -> tuple[dict, str | None]:
    """Extract structured CTI data from article text.

    Returns (extracted_dict, model_name). On failure, the dict has an
    "_error" key and model_name may be None (before the call) or the
    configured model (if the call itself failed).
    """
    if not text or len(text) < 100:
        return {"_error": "Content too short (< 100 chars)"}, None

    settings = get_settings()
    client = LLMClient(settings)
    model = settings.llm_model

    user_prompt = f"Article content:\n\n{text[:15000]}"

    try:
        raw = await client.chat_json(
            system=EXTRACTION_SYSTEM,
            user=user_prompt,
            max_tokens=8192,
            temperature=0.1,
            timeout=90.0,
        )
    except Exception as e:
        logger.exception("Extraction LLM error: %s", e)
        return {"_error": f"LLM error: {str(e)[:200]}"}, model

    if not isinstance(raw, dict):
        return {"_error": "LLM did not return dict"}, model

    result = {
        "iocs": raw.get("iocs") or [],
        "cves": raw.get("cves") or [],
        "malware_families": raw.get("malware_families") or [],
        "attack_techniques": [
            t.strip().upper()
            for t in (raw.get("attack_techniques") or [])
            if t and isinstance(t, str)
        ],
        "sectors_targeted": raw.get("sectors_targeted") or [],
        "attribution_hints": raw.get("attribution_hints") or "Not attributed",
        "summary": raw.get("summary") or "",
        "confidence": float(raw.get("confidence") or 0.5),
    }

    # Validate CVE-ID format
    result["cves"] = [
        {"id": c["id"].upper().strip(), "context": (c.get("context") or "")[:200]}
        for c in result["cves"]
        if isinstance(c, dict) and c.get("id") and CVE_RE.match(c["id"].upper().strip())
    ]

    # Validate IOC types
    clean_iocs = []
    for ioc in result["iocs"]:
        if not isinstance(ioc, dict):
            continue
        it = (ioc.get("type") or "").lower().strip()
        iv = (ioc.get("value") or "").strip()
        if not it or not iv or it not in VALID_IOC_TYPES:
            continue
        clean_iocs.append({
            "type": it, "value": iv,
            "context": (ioc.get("context") or "")[:200],
        })
    result["iocs"] = clean_iocs

    return result, model
