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


def _is_pending_confirmation(c: ToolCallTrace) -> bool:
    return "PENDING_CONFIRMATION" in (c.result_summary or "") or "pending" in (c.result_summary or "").lower()


def format_trace(trace: AgentRunTrace) -> str:
    """Vietnamese-friendly detailed trace block.

    ------------------------
    Agent trace (function-calling, 3 steps, 4.2s, 2140 tok)
      1. search_findings(customer=NPC, severity=HIGH) -> 5 results
      2. get_finding_detail(finding_id=12847) -> 1 finding
      3. search_sigma_rules(cve_id=CVE-X) -> 2 results

    A destructive tool called twice within the SAME turn -- once
    without confirmed=True (returns PENDING_CONFIRMATION) and once with
    it after the analyst confirms mid-turn -- is one action lifecycle,
    not two independent calls; display groups these together (e.g.
    "1. create_finding: pending -> executed") instead of listing them
    as call 1 and call 2, which read as a duplicate/retry to an analyst
    reviewing the trace.
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

    i = 0
    idx = 1
    calls = trace.tool_calls
    while i < len(calls):
        c = calls[i]
        args_str = format_args_compact(c.args)
        # Lifecycle pair: this call was PENDING_CONFIRMATION and the
        # NEXT call is the same tool with the same args (minus
        # `confirmed`) actually executing -- group as 1 action.
        if (
            _is_pending_confirmation(c)
            and i + 1 < len(calls)
            and calls[i + 1].tool_name == c.tool_name
        ):
            nxt = calls[i + 1]
            status = "" if nxt.success else " ❌"
            lines.append(
                f"  {idx}. {c.tool_name}({args_str}) → pending → executed: "
                f"{nxt.result_summary}{status}"
            )
            i += 2
        else:
            status = "" if c.success else " ❌"
            lines.append(
                f"  {idx}. {c.tool_name}({args_str}) → {c.result_summary}{status}"
            )
            i += 1
        idx += 1
    return "\n".join(lines)
