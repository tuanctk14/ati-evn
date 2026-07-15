"""explain_mitigation — deterministic MITRE ATT&CK mitigation lookup."""
from __future__ import annotations

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.enrichment.attack_catalog import _load_mitigations


@register_tool(
    name="explain_mitigation",
    description="Explain a MITRE ATT&CK mitigation: name, description, and which techniques it applies to.",
    parameters={
        "type": "object",
        "properties": {
            "mitigation_id": {"type": "string", "description": "M-number, e.g. M1051"},
        },
        "required": ["mitigation_id"],
    },
)
async def explain_mitigation(mitigation_id: str) -> dict:
    mid = mitigation_id.upper().strip()
    data = _load_mitigations()
    entry = data.get("mitigations", {}).get(mid)
    if not entry:
        return tool_error(
            f"Mitigation '{mitigation_id}' not found in ATT&CK catalog",
            hint="Check the M-number format, e.g. M1051.",
        )

    t2m = data.get("technique_to_mitigations") or {}
    applies_to = sorted(tid for tid, mids in t2m.items() if mid in (mids or []))

    return {
        "mitigation_id": mid,
        "name": entry.get("name") or mid,
        "description": (entry.get("description") or "")[:800],
        "applies_to_techniques": applies_to,
    }
