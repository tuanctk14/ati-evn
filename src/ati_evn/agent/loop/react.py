"""ReAct fallback for when function-calling fails.

Uses text-based Thought/Action/Observation format. Parses model
output with regex + JSON. Less reliable than function-calling but
survives some LLM providers' spotty function-calling support.
"""
from __future__ import annotations

import json
import logging
import re
import time

from ati_evn.agent.loop.config import (
    EVN_SCOPE_RULES, MAX_STEPS, TOKEN_SOFT_CAP, TOOL_SELECTION_HEURISTICS,
    render_context_prefix,
)
from ati_evn.agent.loop.trace import AgentRunTrace, ToolCallTrace
from ati_evn.agent.session.state import SessionState
from ati_evn.agent.tools import TOOL_REGISTRY

logger = logging.getLogger("ati_evn.agent.react")

REACT_SYSTEM = """You are ATI-EVN's analyst assistant (ReAct fallback mode).

You have access to tools. To use a tool, output EXACTLY this format
(no code fences, no markdown):

Thought: <what you're trying to figure out>
Action: <tool_name>
Action Input: <JSON args>

Then wait for `Observation:` and respond. When you have enough info:

Thought: I have enough information.
Final Answer: <Vietnamese answer for analyst>

Available tools:
{tools_list}

Rules:
- Some tools are DESTRUCTIVE (their description contains
  "[DESTRUCTIVE ...]"). For those: call once WITHOUT confirmed=True,
  it returns PENDING_CONFIRMATION with a summary -- show that summary
  to the analyst and wait for explicit confirmation ("xac nhan", "yes")
  before calling the same tool again with confirmed=True. NEVER pass
  confirmed=True on the first call. Non-destructive tools (no such
  marker, e.g. enrich_ip, list_reports, download_report) auto-execute.
- If a tool exists for the analyst's request, call it -- do not
  redirect to a /command instead of calling an available tool.
- Cap at 8 tool calls.
- Preserve English tech terms (CVE-IDs, T-numbers, product names).
- Do NOT invent numbers or IDs.
- Cap your Final Answer to ~400 Vietnamese words. For a list of many
  items (e.g. several Findings), summarize with bullet points instead
  of a wide markdown table -- a long table is more likely to get cut
  off before you finish it. Prioritize the most important 5-10 items
  plus a total count over listing every single one.

## Tool selection heuristics

{tool_selection_heuristics}

{evn_scope_rules}
"""

REACT_SYSTEM = REACT_SYSTEM.replace("{evn_scope_rules}", EVN_SCOPE_RULES)
REACT_SYSTEM = REACT_SYSTEM.replace("{tool_selection_heuristics}", TOOL_SELECTION_HEURISTICS)

ACTION_RE = re.compile(
    r"Action:\s*(?P<name>\w+).*?Action Input:\s*(?P<args>\{.*?\})",
    re.DOTALL,
)
FINAL_RE = re.compile(r"Final Answer:\s*(?P<answer>.+)", re.DOTALL)
_THOUGHT_PREFIX_RE = re.compile(r"^\s*Thought:.*?(?:\n|$)", re.DOTALL)


def _clean_malformed_response(raw: str) -> str:
    """Fallback path when the model's output has neither a parseable
    Final Answer nor a valid Action/Action Input pair (e.g. truncated
    mid-thought, observed during LLM provider degradation). Previously
    this raw text -- including a leading "Thought: ..." fragment --
    was sent to the analyst verbatim, reading as an unfinished internal
    monologue rather than an answer. Strip that prefix and fall back to
    an explicit retry notice if nothing meaningful is left."""
    cleaned = _THOUGHT_PREFIX_RE.sub("", raw).strip()
    if not cleaned:
        return (
            "⚠️ Agent không tạo được câu trả lời hợp lệ. "
            "Vui lòng thử lại hoặc dùng command trực tiếp."
        )
    return cleaned[:2000]


async def run_react(
    client, session_state: SessionState, user_message: str,
    *, max_steps: int = MAX_STEPS, token_soft_cap: int = TOKEN_SOFT_CAP,
    fallback_reason: str = "",
) -> tuple[str, AgentRunTrace]:
    trace = AgentRunTrace(method="react", fallback_reason=fallback_reason)
    overall_start = time.monotonic()

    def _param_names(t) -> str:
        props = (t.parameters or {}).get("properties") or {}
        required = set((t.parameters or {}).get("required") or [])
        names = [f"{p}*" if p in required else p for p in props]
        return f" (params: {', '.join(names)})" if names else ""

    tools_list = "\n".join(
        f"- {t.name}{_param_names(t)}: {t.description[:120]}"
        for t in TOOL_REGISTRY.values()
    )
    system = REACT_SYSTEM.format(tools_list=tools_list)
    context_prefix = render_context_prefix(
        session_state.entity_summary(),
        session_state.command_log_summary(),
        user_message,
    )

    transcript = context_prefix + "\n\n" + f"User question: {user_message}\n\n"

    for step in range(max_steps):
        step_max_tokens = 2048
        try:
            raw = await client.chat_text(
                system=system,
                user=transcript + "\n(Continue with Thought/Action/Action Input, or Final Answer)",
                max_tokens=step_max_tokens,
                temperature=0.1,
            )
            usage = getattr(client, "_last_usage", {}) or {}
            # Observed live, two variants of the same failure: completion
            # hits exactly max_tokens=2048 mid-generation, cutting off
            # either (a) a Final Answer containing a multi-row table
            # (FINAL_RE still matched -- it only needs "Final Answer:" to
            # appear, not a complete sentence after it -- so the
            # truncated text silently became the analyst's answer), or
            # (b) a Thought/Action block before either header was even
            # written (neither FINAL_RE nor ACTION_RE match at all, so
            # this would otherwise fall into "no action found -> treat
            # as malformed answer" below). Retry once with a larger
            # budget whenever completion lands right at the cap and the
            # response doesn't contain a complete, parseable
            # Final-Answer-or-Action block yet -- same failure-mode class
            # as chat_json()'s truncation retry.
            hit_cap = usage.get("completion_tokens", 0) >= step_max_tokens
            looks_incomplete = not (FINAL_RE.search(raw) or ACTION_RE.search(raw))
            if hit_cap and ("Final Answer:" in raw or looks_incomplete):
                logger.warning(
                    "ReAct step %d: completion hit max_tokens with no "
                    "complete Final Answer/Action -- retrying once with "
                    "a larger budget", step,
                )
                raw = await client.chat_text(
                    system=system,
                    user=transcript + "\n(Continue with Thought/Action/Action Input, or Final Answer)",
                    max_tokens=step_max_tokens * 2,
                    temperature=0.1,
                    # A larger max_tokens needs a longer timeout budget
                    # too -- the default 30s was observed insufficient
                    # for a 4096-token completion (28.5s just under the
                    # limit), causing the retry itself to fail with a
                    # ReadTimeout on a slow step.
                    timeout=60.0,
                )
                usage = getattr(client, "_last_usage", {}) or {}
        except Exception as e:
            logger.warning("ReAct LLM error at step %d: %s", step, e)
            return (
                f"Xin lỗi, agent gặp lỗi ở bước {step+1}: {str(e)[:100]}. "
                f"Hãy thử lại hoặc dùng command trực tiếp.",
                trace,
            )

        trace.total_llm_calls += 1
        trace.total_prompt_tokens += usage.get("prompt_tokens", 0)
        trace.total_completion_tokens += usage.get("completion_tokens", 0)

        total_tok = trace.total_prompt_tokens + trace.total_completion_tokens
        if total_tok > token_soft_cap:
            logger.warning("ReAct token cap reached at step %d — forcing stop", step)
            trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
            return _clean_malformed_response(raw), trace

        # Check for final answer first
        m_final = FINAL_RE.search(raw)
        if m_final:
            trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
            return m_final.group("answer").strip(), trace

        # Parse action
        m_action = ACTION_RE.search(raw)
        if not m_action:
            # Model didn't follow format — treat as final answer attempt
            logger.info("ReAct: no action found at step %d, treating as answer", step)
            trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
            return _clean_malformed_response(raw), trace

        tool_name = m_action.group("name")
        try:
            fn_args = json.loads(m_action.group("args"))
        except json.JSONDecodeError:
            observation = "Error: Action Input must be valid JSON."
            transcript += raw + "\nObservation: " + observation + "\n"
            continue

        if tool_name not in TOOL_REGISTRY:
            observation = f"Error: Unknown tool '{tool_name}'."
            trace.tool_calls.append(ToolCallTrace(
                tool_name=tool_name, args=fn_args,
                result_summary="error: unknown tool",
                duration_ms=0, success=False,
            ))
            transcript += raw + "\nObservation: " + observation + "\n"
            continue

        call_start = time.monotonic()
        tool_result = await TOOL_REGISTRY[tool_name].handler(
            **fn_args, _session_id=session_state.user_id,
            _bot=session_state._bot, _chat_id=session_state._chat_id,
        )
        call_duration = int((time.monotonic() - call_start) * 1000)

        # Update session
        from ati_evn.agent.loop.function_calling import _update_session_from_tool
        _update_session_from_tool(session_state, tool_name, fn_args, tool_result)

        trace.tool_calls.append(ToolCallTrace(
            tool_name=tool_name, args=fn_args,
            result_summary=trace.summarize_tool_result(tool_result),
            duration_ms=call_duration,
            success=tool_result.get("success", True),
        ))

        observation = json.dumps(tool_result, ensure_ascii=False,
                                  default=str)[:2500]
        transcript += raw + "\nObservation: " + observation + "\n"

    # max_steps
    logger.warning("ReAct hit max_steps")
    trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
    return (
        "Tôi đã tìm nhưng chưa đủ dữ liệu để trả lời chắc chắn. "
        "Có thể narrow câu hỏi lại được không?",
        trace,
    )
