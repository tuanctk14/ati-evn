"""generate_sigma_rule — get (or AI-generate) a Sigma detection rule for
a CVE, wrapping the same 3-tier logic /rule already uses.

Added after a manual test showed the agent had no tool for this and
incorrectly told the analyst "I have no tool to generate Sigma
rules" -- rules/orchestrator.py's get_rule_for_cve() already does
exactly this (tier 1: direct CVE-tagged community rule, tier 2:
ATT&CK-technique-overlap community rule, tier 3: AI-generated via
LLM), it just wasn't exposed as an agent tool, only via the /rule
slash-command. Read-only + LLM-compute, no DB writes -- registered as
a non-destructive query tool like search_sigma_rules, not an action
tool needing confirmation.
"""
from __future__ import annotations

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.rules.orchestrator import get_rule_for_cve


@register_tool(
    name="generate_sigma_rule",
    description=(
        "Get a Sigma detection rule for a CVE -- same 3-tier logic the "
        "/rule slash-command uses. With force_regen=False (matches plain "
        "/rule), tries a direct CVE-tagged community rule first, then an "
        "ATT&CK-technique-overlap community rule, and only AI-generates a "
        "new rule via LLM if neither exists. With force_regen=True "
        "(matches /rule --regen) it skips straight to AI-generating a rule "
        "written specifically for this CVE. source field in the response "
        "tells you which happened: 'community_direct', "
        "'community_behavioral', or 'ai_generated'. "
        "IMPORTANT for your final answer: include the FULL raw YAML "
        "(response['primary_rule']['yaml']) verbatim in a ```yaml code "
        "block, exactly like /rule does -- do not paraphrase or summarize "
        "the rule content into prose instead of showing it, the analyst "
        "needs the literal YAML to copy into their SIEM."
    ),
    parameters={
        "type": "object",
        "properties": {
            "cve_id": {"type": "string", "description": "CVE-ID, e.g. CVE-2024-1709"},
            "force_regen": {
                "type": "boolean", "default": False,
                "description": (
                    "Skip the community rule lookup and force a fresh "
                    "AI-generated rule. Only set true when the analyst "
                    "explicitly asks for a new/different rule despite an "
                    "existing community match, not for ordinary requests."
                ),
            },
        },
        "required": ["cve_id"],
    },
)
async def generate_sigma_rule(cve_id: str, force_regen: bool = False) -> dict:
    if not cve_id or not cve_id.strip():
        return tool_error("cve_id is required.")
    try:
        return await get_rule_for_cve(cve_id, force_regen=force_regen)
    except Exception as e:
        return tool_error(f"Rule generation failed: {str(e)[:200]}")
