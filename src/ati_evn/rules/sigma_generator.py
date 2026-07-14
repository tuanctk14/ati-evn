"""LLM-based Sigma rule generation for CVEs lacking community coverage.

Uses the project's OpenAI-compatible LLMClient (9Router / deepseek-v4-flash,
see llm/client.py). Uses a similar-product community rule as few-shot when
available.

Output: dict with `sigma_yaml`, `confidence`, `analyst_notes`. Caller
converts YAML -> AQL separately (aql_converter.py).
"""
from __future__ import annotations

import logging

from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.rules.sigma_generator")

SYSTEM_PROMPT = """You are a Sigma rule authoring assistant for a Vietnamese
electric utility SOC. Given a CVE and its context, generate ONE experimental
Sigma detection rule in YAML.

Rules:
- Output JSON with keys: sigma_yaml, confidence (0.0-1.0), analyst_notes.
- sigma_yaml MUST be valid YAML string, single-doc, Sigma schema.
- Set status: experimental
- Set level based on CVSS: critical if >=9, high if >=7, medium if >=4, low.
- Include tags: attack.<technique_id_lowercase>, attack.<tactic>, cve.<cve_id_dotted>
- ALWAYS include this metadata block in the YAML (verbatim):
  metadata:
    ai_generated: true
    analyst_review_required: true
    generator: ati-evn/slice-4.7
- references: include nvd.nist.gov URL and any vendor advisory known.
- detection.selection MUST use real field names for the product's log source
  (e.g. Windows Sysmon EventID, IIS cs-uri-stem, Fortinet syslog msg).
- If uncertain about field names, add <ANALYST_FILL: description> placeholders.
- Do NOT hallucinate CVE IDs, CVSS scores, or facts not provided.
- analyst_notes: 2-3 sentence explanation of the detection logic, plus
  what analyst should verify before deploying (e.g. "verify the URI paths
  match your Fortinet SSL-VPN version's logging").

Return ONLY the JSON. No markdown fences."""

USER_PROMPT_TEMPLATE = """CVE: {cve_id}
Description: {description}
CVSS: {cvss}
Vendor/Product: {vendor} / {product} {version_range}
CWE: {cwe_ids}
ATT&CK techniques (from enrichment): {attack_context}
Kill chain phase: {kill_chain}

{community_example}

Generate the Sigma rule JSON."""


async def generate_sigma_rule(
    client: LLMClient,
    *, cve_id: str, description: str, cvss: float | None,
    vendor: str | None, product: str | None, version_range: str | None,
    cwe_ids: list[str], attack_techniques: list[dict],
    kill_chain_phases: list[str],
    community_example_yaml: str | None = None,
) -> dict:
    # Compact ATT&CK context for the prompt
    tech_list = ", ".join(
        f"{t.get('id')} ({t.get('name')}, conf {t.get('confidence')})"
        for t in (attack_techniques or [])[:5]
    )
    community_block = ""
    if community_example_yaml:
        community_block = (
            "Reference — similar product Sigma rule (for style, do NOT copy):\n"
            "---\n" + community_example_yaml[:2000] + "\n---\n"
        )

    user = USER_PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        description=(description or "")[:1500],
        cvss=cvss if cvss else "unknown",
        vendor=vendor or "unknown",
        product=product or "unknown",
        version_range=version_range or "",
        cwe_ids=", ".join(cwe_ids or []),
        attack_context=tech_list or "unknown",
        kill_chain=", ".join(kill_chain_phases or []),
        community_example=community_block,
    )

    raw = await client.chat_json(
        system=SYSTEM_PROMPT, user=user,
        # This model emits a reasoning_content preamble before the actual
        # JSON answer (same behavior hit in llm/cpe_inferrer.py — slice 4).
        # 1500 was getting truncated before the JSON (a full Sigma YAML rule
        # plus notes) ever appeared; 4096 gives enough headroom for both.
        max_tokens=4096, temperature=0.2,
    )
    return {
        "sigma_yaml": raw.get("sigma_yaml", ""),
        "confidence": float(raw.get("confidence") or 0.5),
        "analyst_notes": raw.get("analyst_notes", ""),
        "source": "ai_generated",
        "model": client.settings.llm_model,
    }
