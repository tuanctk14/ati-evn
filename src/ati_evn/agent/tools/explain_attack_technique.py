"""explain_attack_technique — deterministic MITRE ATT&CK technique lookup."""
from __future__ import annotations

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.enrichment.attack_catalog import (
    _load_techniques,
    get_mitigation_name,
    get_mitigations_for_technique,
    get_tactics_for_technique,
    get_technique_description,
    get_technique_name,
)


@register_tool(
    name="explain_attack_technique",
    description="Explain a MITRE ATT&CK technique: name, description, tactics, mitigations, platforms.",
    parameters={
        "type": "object",
        "properties": {
            "technique_id": {"type": "string", "description": "T-number, e.g. T1190 or T1059.001"},
        },
        "required": ["technique_id"],
    },
)
async def explain_attack_technique(technique_id: str) -> dict:
    tid = technique_id.upper().strip()
    techniques = _load_techniques()
    entry = techniques.get(tid)
    if not entry and "." in tid:
        entry = techniques.get(tid.split(".", 1)[0])
    if not entry:
        return tool_error(
            f"Technique '{technique_id}' not found in ATT&CK catalog",
            hint="Check the T-number format, e.g. T1190.",
        )

    mitigation_ids = get_mitigations_for_technique(tid)
    mitigations = [{"id": m, "name": get_mitigation_name(m)} for m in mitigation_ids]

    return {
        "technique_id": tid,
        "name": get_technique_name(tid),
        "description": get_technique_description(tid)[:800],
        "tactics": get_tactics_for_technique(tid),
        "mitigations": mitigations,
        "platforms": entry.get("platforms") or [],
    }
