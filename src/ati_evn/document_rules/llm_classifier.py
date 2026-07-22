"""Stage 3: LLM relevance check.

Trigger conditions (decided by the caller in external/document_ingest.py):
  - Rule matched but severity is 'low' (need confirmation)
  - No rule matched (need discovery: might be a relevant EVN doc the
    rule set missed)

Skipped when a rule matched with severity high/critical AND the bucket
is whitelisted (deterministic pass, saves an LLM call).
"""
from __future__ import annotations

import logging

from ati_evn.config import get_settings
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.document_rules.llm")

RELEVANCE_SYSTEM = """You are an EVN (Vietnam Electricity) SOC analyst.
Given a document filename + bucket URL, decide if this document is
LIKELY related to Vietnam Electricity (EVN) or its subsidiaries.

Vietnam Electricity (EVN) subsidiaries include:
- EVN corporate (evn.com.vn)
- EVN NPC (Northern Power Corporation)
- EVN CPC (Central Power Corporation)
- EVN SPC (Southern Power Corporation)
- EVN HANOI, EVN HCMC (city power corps)
- GENCO1/2/3 (generation)
- EVN NPT (transmission)
- A0 (National Power Control Center)
- EVN EPS (Electrical Power Services)

Return JSON ONLY (no markdown):
{
  "relevant": true | false,
  "reason": "brief 1-sentence explanation"
}

Rules:
1. Return true only if filename/bucket clearly indicates EVN affiliation
   (Vietnamese language + electricity/energy terms, or explicit EVN mention).
2. Generic filenames on unrelated buckets -> false (e.g. "report.pdf" on
   a US healthcare bucket is NOT EVN).
3. Vietnamese language + generic terms + EVN keyword in bucket -> true.
4. When unsure, err on false (skip false positive over false positive noise).
"""


async def check_relevance(doc: dict) -> tuple[bool, str]:
    """Return (is_relevant, reason)."""
    settings = get_settings()
    client = LLMClient(settings)

    prompt = (
        f"Bucket URL: {doc.get('bucket_url', '')}\n"
        f"File path: {doc.get('file_path', '')}\n"
        f"Filename: {doc.get('filename', '')}\n"
        f"Extension: {doc.get('file_extension', 'none')}\n"
        f"Keyword that matched: {doc.get('keyword_matched', '')}\n"
    )
    try:
        raw = await client.chat_json(
            system=RELEVANCE_SYSTEM,
            user=prompt,
            max_tokens=512,
            temperature=0.1,
        )
    except Exception as e:
        logger.warning("LLM relevance check failed: %s", e)
        return False, f"LLM error: {str(e)[:100]}"

    if not isinstance(raw, dict):
        return False, "LLM did not return dict"
    relevant = bool(raw.get("relevant"))
    reason = str(raw.get("reason") or "")[:300]
    return relevant, reason
