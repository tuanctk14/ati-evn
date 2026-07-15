"""Track tool calls for user-facing trace + telemetry."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCallTrace:
    tool_name: str
    args: dict[str, Any]
    result_summary: str  # e.g. "5 results", "1 finding", "error: X"
    duration_ms: int
    success: bool


@dataclass
class AgentRunTrace:
    tool_calls: list[ToolCallTrace] = field(default_factory=list)
    total_llm_calls: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_duration_ms: int = 0
    method: str = "function_calling"  # or "react"
    fallback_reason: str | None = None

    def summarize_tool_result(self, result: dict) -> str:
        """Short human-readable line for one tool result."""
        if not result.get("success", True):
            return f"error: {(result.get('error') or '')[:60]}"
        for key in ("returned_count", "total_count", "event_count",
                    "finding_count"):
            if key in result:
                return f"{result[key]} results"
        if result.get("finding"):
            return "1 finding"
        if result.get("cve"):
            return "1 CVE"
        if result.get("technique_id"):
            return f"technique {result['technique_id']}"
        if result.get("mitigation_id"):
            return f"mitigation {result['mitigation_id']}"
        return "ok"


def format_args_compact(args: dict, max_len: int = 80) -> str:
    """Compact repr for trace display."""
    parts = []
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 30:
            v = v[:27] + "…"
        parts.append(f"{k}={v}")
    s = ", ".join(parts)
    return s if len(s) <= max_len else s[:max_len - 1] + "…"


def format_trace(trace: AgentRunTrace) -> str:
    """Vietnamese-friendly detailed trace block.

    ------------------------
    Agent trace (function-calling, 3 steps, 4.2s, 2140 tok)
      1. search_findings(customer=NPC, severity=HIGH) -> 5 results
      2. get_finding_detail(finding_id=12847) -> 1 finding
      3. search_sigma_rules(cve_id=CVE-X) -> 2 results
    """
    if not trace.tool_calls:
        return ""
    header = (
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔧 Agent trace ({trace.method}, "
        f"{len(trace.tool_calls)} tool call(s), "
        f"{trace.total_duration_ms/1000:.1f}s, "
        f"{trace.total_prompt_tokens + trace.total_completion_tokens} tok)"
    )
    if trace.fallback_reason:
        header += f"\n  ⚠ Fallback: {trace.fallback_reason}"
    lines = [header]
    for i, c in enumerate(trace.tool_calls, 1):
        args_str = format_args_compact(c.args)
        status = "" if c.success else " ❌"
        lines.append(
            f"  {i}. {c.tool_name}({args_str}) → {c.result_summary}{status}"
        )
    return "\n".join(lines)
