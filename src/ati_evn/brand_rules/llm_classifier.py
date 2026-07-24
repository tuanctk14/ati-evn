"""Stage 3: LLM classifier for brand abuse sightings.

Trigger conditions (decided by the caller in external/brand_abuse_ingest.py):
  - No rule matched (need discovery: might be a coincidental title hit,
    or a genuine impersonation the rule set missed)
  - Rule matched but severity is 'low' (rules.yaml currently has no
    'low' rule, but the check stays symmetric with document_rules)

Skipped when a rule matched with severity high/critical -- deterministic
signal (malicious verdict, multiple engines, or typosquat) is strong
enough on its own.
"""
from __future__ import annotations

import logging

from ati_evn.config import get_settings
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.brand_rules.llm")

RELEVANCE_SYSTEM = """You are an EVN (Vietnam Electricity) SOC analyst.
Given a scanned URL's domain and page title, decide if this URL is
LIKELY a brand abuse / impersonation / phishing site targeting Vietnam
Electricity (EVN) or its subsidiaries.

Vietnam Electricity (EVN) subsidiaries include:
- EVN corporate (evn.com.vn)
- EVN NPC (Northern Power Corporation)
- EVN CPC (Central Power Corporation)
- EVN SPC (Southern Power Corporation)
- EVN HANOI, EVN HCMC (city power corps)
- GENCO1/2/3 (generation)
- EVN NPT (transmission)
- A0 / National Load Dispatch Center
- EVN EPS (Electrical Power Services)

Return JSON ONLY (no markdown):
{
  "relevant": true | false,
  "reason": "brief 1-sentence explanation"
}

Rules:
1. Return true only if the domain/title plausibly impersonates or
   targets EVN (e.g. EVN branding on a domain that isn't EVN's own,
   Vietnamese electricity-bill-payment phishing themes).
2. A page merely mentioning "electricity" in an unrelated country or
   context -> false.
3. When unsure, err on false (skip false positive over false positive noise).
"""


async def check_relevance(sighting: dict) -> tuple[bool, str]:
    """Return (is_relevant, reason)."""
    settings = get_settings()
    client = LLMClient(settings)

    prompt = (
        f"URL: {sighting.get('url', '')}\n"
        f"Domain: {sighting.get('domain', '')}\n"
        f"Page title: {sighting.get('page_title', '')}\n"
        f"Keyword that matched: {sighting.get('keyword_matched', '')}\n"
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
