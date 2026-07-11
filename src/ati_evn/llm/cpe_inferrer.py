"""LLM-based CVE -> vendor/product/version_range inference.

Runs only when NVD hasn't attached CPE data yet (the CVE is in
"Awaiting Analysis" or similar status). We extract vendor/product/version
signal directly from the free-text description as a lazy fallback — this
is a fuzzy heuristic aid, not authoritative NVD data, hence
source='llm_inferred' and confidence < 1.0 downstream in cve_product_map.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from ati_evn.llm.client import LLMClient
from ati_evn.llm.json_extract import JSONExtractError

logger = logging.getLogger("ati_evn.llm.cpe_inferrer")

SYSTEM_PROMPT = """You are a CPE extraction assistant. Given a CVE description, extract
the affected vendor, product, and version range in NVD CPE 2.3 style.

Rules:
- Output ONLY a JSON object with key "affected_products", an array.
- Each array element MUST have keys: vendor, product, version_range,
  confidence, reasoning.
- vendor: lowercase, one word if possible (e.g. "microsoft", "cisco",
  "siemens"). Match NVD CPE vendor namespace when known.
- product: lowercase, snake_case for multi-word (e.g. "windows_server_2019",
  "simatic_s7-1200_firmware", "fortios").
- version_range: PEP 440 specifier syntax:
    ">= 4.5.0, < 4.5.7"  for bounded
    "<= 3.2.1"           for upper only
    ">= 2.0"             for lower only
    "== 1.4.3"           for exact
    ""                    (empty string) if the description is unclear
- confidence: 0.0-1.0. Give 0.9+ only when vendor and product are
  explicitly named. Give 0.6-0.8 for reasonable inference. Give
  <=0.5 if you are guessing.
- reasoning: 1 short sentence explaining what in the description
  supports the extraction.
- If the description mentions multiple distinct products, emit one
  array entry per product.
- If the description is too generic to identify a product, return
  {"affected_products": []}.
- Do NOT hallucinate CVE IDs, CVSS scores, or any data not in the
  description.

Return ONLY the JSON object. No prose, no markdown fences."""

USER_PROMPT_TEMPLATE = """CVE ID: {cve_id}
Description: {description}
{hint_line}
Return the JSON now."""


@dataclass
class InferredCpe:
    vendor: str
    product: str
    version_range: str
    confidence: float
    reasoning: str


def _validate_and_clamp(raw: dict) -> InferredCpe | None:
    vendor = str(raw.get("vendor") or "").strip().lower()
    product = str(raw.get("product") or "").strip().lower()
    if not vendor or not product:
        return None

    version_range = str(raw.get("version_range") or "").strip()

    try:
        confidence = float(raw.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    reasoning = str(raw.get("reasoning") or "").strip()

    return InferredCpe(
        vendor=vendor,
        product=product,
        version_range=version_range,
        confidence=confidence,
        reasoning=reasoning,
    )


async def infer_cpe_for_cve(
    client: LLMClient,
    cve_id: str,
    description: str,
    context_hint_vendors: list[str] | None = None,
) -> list[InferredCpe]:
    """Extract vendor/product/version_range tuples from a CVE description.
    Returns [] if the description gives no clear signal, or on any API/parse
    failure (logged, not raised — a single bad CVE shouldn't kill the batch)."""
    hint_line = ""
    if context_hint_vendors:
        vendor_list = ", ".join(sorted(set(context_hint_vendors)))
        hint_line = (
            f"Hint: our environment includes vendors: {vendor_list}. "
            f"If the description matches one, prefer that spelling."
        )

    user_prompt = USER_PROMPT_TEMPLATE.format(
        cve_id=cve_id, description=description, hint_line=hint_line,
    )

    try:
        # This model emits a reasoning_content preamble before the actual
        # JSON answer, so a low max_tokens cap was truncating the response
        # before it ever reached the JSON object. Use the client's higher
        # default (4096) rather than capping it further here.
        response = await client.chat_json(SYSTEM_PROMPT, user_prompt)
    except JSONExtractError as e:
        logger.warning("CVE %s: LLM returned unparseable JSON: %s", cve_id, e)
        return []
    # LLMError intentionally propagates — caller tracks it as an llm_error.

    raw_products = response.get("affected_products")
    if not isinstance(raw_products, list):
        logger.warning("CVE %s: response missing 'affected_products' list", cve_id)
        return []

    results: list[InferredCpe] = []
    for raw in raw_products:
        if not isinstance(raw, dict):
            continue
        inferred = _validate_and_clamp(raw)
        if inferred is not None:
            results.append(inferred)

    return results
