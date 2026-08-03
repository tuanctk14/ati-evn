"""generate_playbook — get (or AI-generate) a NIST 800-61 incident-response
playbook for a CVE/Finding, wrapping the same logic /playbook already uses.

Added after a manual test showed the agent had no way to actually
trigger playbook generation for free-text -- get_playbook.py (the
existing agent tool) is explicitly read-only cache lookup ("Never
triggers LLM generation", per its own docstring), so the agent could
only tell the analyst "run /playbook yourself" instead of doing it.
telegram/commands/playbook.py's generate_playbook_for() already does
the real work (cache hit/miss + LLM generation); this just exposes it
as a directly-callable, non-destructive tool -- same rationale as
generate_sigma_rule.py for /rule.
"""
from __future__ import annotations

from ati_evn.agent.tools._base import register_tool, tool_error


@register_tool(
    name="generate_playbook",
    description=(
        "Get a NIST 800-61 incident-response playbook for a CVE-ID or "
        "Finding id -- same logic the /playbook slash-command uses. "
        "Checks the cache first (keyed by cve_id + network_segment); "
        "generates a fresh AI playbook via LLM on a cache miss. Takes "
        "10-30s on a cache miss, near-instant on a cache hit. "
        "IMPORTANT for your final answer: include the FULL raw markdown "
        "(response['markdown']) verbatim, not a paraphrase or summary -- "
        "the analyst needs the literal step-by-step playbook, same as "
        "what /playbook shows."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "CVE-ID (e.g. CVE-2024-1709) or a Finding id (integer as string)",
            },
            "network_segment": {
                "type": "string",
                "description": (
                    "Override network segment (e.g. 'internal_it', 'dmz', "
                    "'ot_control'). Optional -- if target is a finding_id "
                    "and this is omitted, the segment is inferred from the "
                    "finding's matched asset."
                ),
            },
        },
        "required": ["target"],
    },
)
async def generate_playbook(target: str, network_segment: str | None = None) -> dict:
    # Deferred import: telegram/commands/playbook.py imports
    # agent/loop/postfilter.py, which is reachable from
    # agent/loop/__init__.py -> function_calling.py -> agent/tools
    # (this package) -- a module-level import here would be circular.
    from ati_evn.telegram.commands.playbook import generate_playbook_for

    if not target or not target.strip():
        return tool_error("target is required.")
    try:
        result = await generate_playbook_for(target, network_segment_override=network_segment)
    except Exception as e:
        return tool_error(f"Playbook generation failed: {str(e)[:200]}")
    if "error" in result:
        return tool_error(result["error"])
    return {
        "success": True,
        "cve_id": result["cve_id"],
        "network_segment": result["network_segment"],
        "markdown": result["markdown"],
        "was_cached": result["was_cached"],
    }
