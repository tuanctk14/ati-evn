"""LLM-based CVE -> vendor/product/version_range (CPE) and CWE inference.

Called inline from the NVD fetcher (and the rescan module) only when
cve_filter.should_run_llm() says a CVE both has a structured-data gap and
looks relevant to an EVN vendor. One LLM call extracts CPE and CWE together
since both come from the same description text — no reason to pay for two
round trips. need_cpe/need_cwe let the caller skip asking for whichever
NVD already supplied, saving output tokens.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ati_evn.llm.client import LLMClient
from ati_evn.llm.json_extract import JSONExtractError

logger = logging.getLogger("ati_evn.llm.cpe_inferrer")

SYSTEM_PROMPT = """You are a CPE/CWE extraction assistant. Given a CVE description and
reference URLs, extract structured metadata.

Output ONLY a JSON object.

### CPE section (only if requested)
Key "affected_products": array. Each element has:
  - vendor: lowercase, NVD CPE style ("microsoft", "cisco", "siemens")
  - product: lowercase, snake_case ("windows_server_2019")
  - version_range: PEP 440 specifier (">= 4.5.0, < 4.5.7") or "" if unclear
  - confidence: 0.0-1.0
  - reasoning: 1-sentence justification

### CWE section (only if requested)
Key "cwe_ids": array of CWE IDs from https://cwe.mitre.org/, e.g.
["CWE-79", "CWE-89"]. Only include ones you can justify from the
description. If none, use [].

### Overall
Key "reasoning": 1-sentence overall justification.

Rules:
- Never hallucinate CVSS, CVE IDs, or data not in the input.
- If confidence < 0.5 for a product, still include but mark it.
- Multiple products → multiple entries.
- Return ONLY the JSON object. No prose, no markdown."""

USER_PROMPT_TEMPLATE = """CVE ID: {cve_id}
Description: {description}
References: {reference_urls}
{hint_line}
Extract:{cpe_instruction}{cwe_instruction}

Return the JSON now."""


@dataclass
class InferredCpe:
    vendor: str
    product: str
    version_range: str
    confidence: float
    reasoning: str


@dataclass
class InferredCveMetadata:
    cpe_entries: list[InferredCpe] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    reasoning: str = ""


def _validate_and_clamp_cpe(raw: dict) -> InferredCpe | None:
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
        vendor=vendor, product=product, version_range=version_range,
        confidence=confidence, reasoning=reasoning,
    )


def _validate_cwe_ids(raw: list) -> list[str]:
    cwe_ids: list[str] = []
    for item in raw or []:
        value = str(item).strip().upper()
        if value.startswith("CWE-") and value[4:].isdigit():
            cwe_ids.append(value)
    return cwe_ids


async def infer_missing_metadata(
    client: LLMClient,
    cve_id: str,
    description: str,
    references: list[dict],
    *,
    need_cpe: bool,
    need_cwe: bool,
    context_hint_vendors: list[str] | None = None,
) -> InferredCveMetadata:
    """Extract CPE and/or CWE metadata from a CVE description + references.
    Returns an empty InferredCveMetadata on any parse failure (logged, not
    raised — a single bad CVE shouldn't kill the batch)."""
    hint_line = ""
    if context_hint_vendors:
        vendor_list = ", ".join(sorted(set(context_hint_vendors)))
        hint_line = (
            f"Hint: our environment includes vendors: {vendor_list}. "
            f"If the description matches one, prefer that spelling."
        )

    reference_urls = [r.get("url", "") for r in (references or [])[:5] if r.get("url")]

    cpe_instruction = "" if need_cpe else " (SKIP CPE, cpe already present)"
    cwe_instruction = "" if need_cwe else " (SKIP CWE, cwe already present)"

    user_prompt = USER_PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        description=description,
        reference_urls=reference_urls,
        hint_line=hint_line,
        cpe_instruction=cpe_instruction,
        cwe_instruction=cwe_instruction,
    )

    try:
        response = await client.chat_json(SYSTEM_PROMPT, user_prompt)
    except JSONExtractError as e:
        logger.warning("CVE %s: LLM returned unparseable JSON: %s", cve_id, e)
        return InferredCveMetadata()
    # LLMError intentionally propagates — caller tracks it as an llm_error.

    cpe_entries: list[InferredCpe] = []
    if need_cpe:
        raw_products = response.get("affected_products")
        if isinstance(raw_products, list):
            for raw in raw_products:
                if isinstance(raw, dict):
                    inferred = _validate_and_clamp_cpe(raw)
                    if inferred is not None:
                        cpe_entries.append(inferred)

    cwe_ids: list[str] = []
    if need_cwe:
        raw_cwe = response.get("cwe_ids")
        if isinstance(raw_cwe, list):
            cwe_ids = _validate_cwe_ids(raw_cwe)

    reasoning = str(response.get("reasoning") or "").strip()

    return InferredCveMetadata(cpe_entries=cpe_entries, cwe_ids=cwe_ids, reasoning=reasoning)
