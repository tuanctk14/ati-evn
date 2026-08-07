"""Function-calling agent loop.

Loops: send messages+tools -> parse response -> if tool_calls: execute ->
append tool results -> repeat. Terminates when model returns content
with no tool_calls, or on max_steps / timeout / token cap.
"""
from __future__ import annotations

import json
import logging
import re
import time

from ati_evn.agent.loop.config import (
    MAX_STEPS, SYSTEM_PROMPT, TOKEN_SOFT_CAP, render_context_prefix,
)
from ati_evn.agent.loop.trace import AgentRunTrace, ToolCallTrace
from ati_evn.agent.session.state import SessionState
from ati_evn.agent.tools import TOOL_REGISTRY
from ati_evn.agent.tools._base import get_all_openai_schemas

logger = logging.getLogger("ati_evn.agent.fc")

# Matches a provider's internal special-token markup for tool calls
# leaking into `message.content` as literal text instead of being
# parsed into the structured `tool_calls` field -- observed live with
# DeepSeek's "<｜DSML｜tool calls>" / "<｜DSML｜invoke name=...>" tokens
# (both the full-width "｜" variant and a plain "|" fallback in case a
# different provider/version emits ASCII pipes for the same markup).
_RAW_TOOL_SYNTAX_RE = re.compile(r"<[｜|]DSML[｜|](?:tool[_ ]calls|invoke)")


class FunctionCallingFailure(Exception):
    """Raised when function-calling loop fails structurally (bad
    tool name, invalid JSON args, model refuses schema). Runner
    catches and falls back to ReAct."""


async def run_function_calling(
    client, session_state: SessionState, user_message: str,
    *, max_steps: int = MAX_STEPS, token_soft_cap: int = TOKEN_SOFT_CAP,
) -> tuple[str, AgentRunTrace]:
    """Return (final_answer_text, trace)."""
    trace = AgentRunTrace(method="function_calling")
    overall_start = time.monotonic()

    tools_schema = get_all_openai_schemas()
    context_prefix = render_context_prefix(
        session_state.entity_summary(),
        session_state.command_log_summary(),
        user_message,
    )

    # Build initial messages from session history + this user turn.
    # `history` (free-text turns) is untouched by slice 16A -- it still
    # feeds this loop verbatim, exactly as before; command_log_recent
    # only reaches the model via context_prefix above, so this dict-key
    # access contract is unaffected by the new field.
    messages: list[dict] = []
    for h in session_state.history[-10:]:
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({
        "role": "user",
        "content": (context_prefix + "\n\n" + user_message).strip(),
    })

    # Destructive tools that failed the confirmed=True guard anywhere
    # in this turn (any step, not just the current LLM response) --
    # models sometimes respond to that failure by immediately retrying
    # the same tool in a later step instead of stopping to ask the
    # analyst again, which would bypass the point of the confirmation
    # step. Persists across the whole run_function_calling call (one
    # analyst turn), not just within a single tool_calls batch.
    blocked_after_pending_failure: set[str] = set()

    for step in range(max_steps):
        step_max_tokens = 2048
        try:
            response = await client.chat_with_tools(
                system=SYSTEM_PROMPT,
                messages=messages,
                tools=tools_schema,
                max_tokens=step_max_tokens,
                temperature=0.1,
                timeout=30.0,
            )
        except Exception as e:
            raise FunctionCallingFailure(f"LLM API error: {e}") from e

        trace.total_llm_calls += 1
        usage = response.get("usage") or {}
        trace.total_prompt_tokens += usage.get("prompt_tokens", 0)
        trace.total_completion_tokens += usage.get("completion_tokens", 0)

        total_tok = trace.total_prompt_tokens + trace.total_completion_tokens
        if total_tok > token_soft_cap:
            logger.warning(
                "Token cap %d reached at step %d (used %d) — forcing final answer",
                token_soft_cap, step, total_tok,
            )
            answer, trace = await _force_final_answer(client, messages, trace)
            trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
            return answer, trace

        choices = response.get("choices") or []
        if not choices:
            raise FunctionCallingFailure("Empty choices in response")
        msg = choices[0].get("message") or {}
        tool_calls = msg.get("tool_calls") or []
        content = msg.get("content") or ""
        finish_reason = choices[0].get("finish_reason")

        if not tool_calls:
            # Observed live: the model sometimes writes its tool-call
            # attempt as literal text using the provider's internal
            # special-token format (e.g. DeepSeek's "<｜DSML｜tool
            # calls>...<｜DSML｜invoke name=...>...") instead of the
            # provider correctly parsing it into the structured
            # `tool_calls` field -- likely a backend-routing hiccup
            # (same class of issue as the "grammar-constrained decoding"
            # 400 errors elsewhere in this client). Left unguarded, this
            # non-empty, non-truncated content would be treated as a
            # valid final answer and sent verbatim to the analyst,
            # leaking raw model-internal syntax into the Telegram
            # message. Treat it as a structural failure (like invalid
            # JSON args below) so runner.py retries function-calling
            # once, then falls back to ReAct -- which uses plain-text
            # Thought/Action format and doesn't depend on the
            # provider's structured tool_calls parsing at all.
            if _RAW_TOOL_SYNTAX_RE.search(content):
                raise FunctionCallingFailure(
                    f"Model leaked raw tool-call syntax instead of "
                    f"structured tool_calls: {content[:150]!r}"
                )
            if not content.strip():
                # Empty content + no tool_calls + finish_reason="length" means
                # the model's response got cut off mid-generation by
                # max_tokens=2048 before it emitted either a real answer or a
                # complete tool_calls block -- returning "" here would send
                # the analyst a blank message (observed live: completion_tok
                # landed exactly on the 2048 cap). Force a final answer with
                # a larger budget instead of treating empty as a valid reply.
                logger.warning(
                    "Empty content + no tool_calls at step %d (finish_reason=%s) "
                    "— forcing final answer with larger budget",
                    step, finish_reason,
                )
                answer, trace = await _force_final_answer(client, messages, trace)
                trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
                return answer, trace
            # Final answer -- but check for silent truncation first.
            # finish_reason="length" with non-empty content means the
            # model hit max_tokens mid-sentence (distinct from the
            # empty-content case above, which is a total generation
            # failure) -- observed live: "Tong hop Finding theo don vi"
            # answer cut off mid-word ("...toi can thuc hien them truy
            # van") because it happened to land right at step_max_tokens
            # while composing a long multi-customer breakdown. Same
            # failure-mode class already fixed for ReAct
            # (agent/loop/react.py) and chat_json() -- retry ONCE with a
            # larger budget instead of silently returning the truncated
            # text as if it were complete.
            if finish_reason == "length" and content.strip():
                logger.warning(
                    "Step %d final answer hit max_tokens=%d mid-sentence "
                    "(finish_reason=length) -- retrying once with a "
                    "larger budget", step, step_max_tokens,
                )
                retry_response = await client.chat_with_tools(
                    system=SYSTEM_PROMPT,
                    messages=messages,
                    tools=tools_schema,
                    max_tokens=step_max_tokens * 2,
                    temperature=0.1,
                    timeout=60.0,
                )
                trace.total_llm_calls += 1
                retry_usage = retry_response.get("usage") or {}
                trace.total_prompt_tokens += retry_usage.get("prompt_tokens", 0)
                trace.total_completion_tokens += retry_usage.get("completion_tokens", 0)
                retry_choices = retry_response.get("choices") or []
                if retry_choices:
                    retry_msg = retry_choices[0].get("message") or {}
                    retry_content = retry_msg.get("content") or ""
                    if retry_content.strip():
                        content = retry_content
            trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
            return content, trace

        # Append assistant message (with tool_calls) to history. When the
        # provider runs in "thinking mode" it returns a reasoning_content
        # field alongside content/tool_calls -- 9Router then REJECTS the
        # next request with HTTP 400 ("reasoning_content ... must be
        # passed back to the API") if that field isn't echoed back in
        # this same assistant message on the next call. This isn't
        # optional metadata; it must round-trip exactly like tool_calls
        # does. Observed live: this being missing broke function-calling
        # entirely for a turn, which then also exhausted the ReAct
        # fallback's timeout.
        assistant_msg = {
            "role": "assistant",
            "content": content,
            "tool_calls": tool_calls,
        }
        reasoning_content = msg.get("reasoning_content")
        if reasoning_content:
            assistant_msg["reasoning_content"] = reasoning_content
        messages.append(assistant_msg)

        # Execute each tool call, append tool responses.
        for tc in tool_calls:
            tc_id = tc.get("id")
            fn = tc.get("function") or {}
            fn_name = fn.get("name")
            fn_args_raw = fn.get("arguments") or "{}"

            if fn_name in blocked_after_pending_failure:
                tool_result = {
                    "success": False,
                    "error": (
                        f"Blocked: {fn_name} already failed its confirmation "
                        "check earlier in this same turn. Do not retry it "
                        "automatically -- stop and ask the analyst to "
                        "confirm again in a new message."
                    ),
                }
                trace.tool_calls.append(ToolCallTrace(
                    tool_name=fn_name, args={},
                    result_summary="blocked: retry after pending-confirmation failure",
                    duration_ms=0, success=False,
                ))
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": json.dumps(tool_result),
                })
                continue

            if not fn_name or fn_name not in TOOL_REGISTRY:
                trace.tool_calls.append(ToolCallTrace(
                    tool_name=fn_name or "unknown",
                    args={},
                    result_summary="error: unknown tool",
                    duration_ms=0,
                    success=False,
                ))
                tool_result = {
                    "success": False,
                    "error": f"Unknown tool: {fn_name}",
                }
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": json.dumps(tool_result),
                })
                continue

            try:
                fn_args = json.loads(fn_args_raw)
            except json.JSONDecodeError as e:
                raise FunctionCallingFailure(
                    f"Model returned invalid JSON args for {fn_name}: {e}"
                )

            call_start = time.monotonic()
            tool_result = await TOOL_REGISTRY[fn_name].handler(
                **fn_args, _session_id=session_state.user_id,
                _bot=session_state._bot, _chat_id=session_state._chat_id,
            )
            call_duration = int((time.monotonic() - call_start) * 1000)

            if (
                fn_args.get("confirmed")
                and not tool_result.get("success", True)
                and "PENDING_CONFIRMATION" in str(tool_result.get("error", ""))
            ):
                blocked_after_pending_failure.add(fn_name)

            _update_session_from_tool(session_state, fn_name, fn_args, tool_result)

            trace.tool_calls.append(ToolCallTrace(
                tool_name=fn_name,
                args=fn_args,
                result_summary=trace.summarize_tool_result(tool_result),
                duration_ms=call_duration,
                success=tool_result.get("success", True),
            ))

            messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": json.dumps(tool_result, ensure_ascii=False,
                                       default=str)[:8000],
            })

    # max_steps reached without final answer — force summary
    logger.warning("Agent hit max_steps=%d — forcing final answer", max_steps)
    answer, trace = await _force_final_answer(client, messages, trace)
    trace.total_duration_ms = int((time.monotonic() - overall_start) * 1000)
    return answer, trace


async def _force_final_answer(client, messages, trace) -> tuple[str, AgentRunTrace]:
    """When budget exhausted, ask model for final answer with no tools."""
    messages.append({
        "role": "user",
        "content": (
            "Đã dùng hết budget hoặc max steps. Hãy tổng hợp câu trả lời "
            "cuối cùng cho analyst dựa trên dữ liệu đã thu thập được, "
            "không cần gọi thêm tool. Trả lời ngắn gọn, tiếng Việt -- "
            "TRỪ KHI một tool result phía trên chứa nội dung cần giữ "
            "nguyên văn theo đúng chỉ dẫn của tool đó (ví dụ Sigma rule "
            "YAML từ generate_sigma_rule/search_sigma_rules, markdown "
            "playbook từ generate_playbook/get_playbook) -- trong "
            "trường hợp đó VẪN PHẢI dán nguyên văn toàn bộ nội dung đó, "
            "không paraphrase hay tóm tắt thành văn xuôi, chỉ được rút "
            "gọn phần bình luận/giải thích xung quanh nó."
        ),
    })
    response = await client.chat_with_tools(
        system=SYSTEM_PROMPT,
        messages=messages,
        tools=[],
        tool_choice="none",
        max_tokens=1500,
        temperature=0.1,
    )
    content = (response.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
    trace.total_llm_calls += 1
    usage = response.get("usage") or {}
    trace.total_prompt_tokens += usage.get("prompt_tokens", 0)
    trace.total_completion_tokens += usage.get("completion_tokens", 0)
    if not content.strip():
        # Same failure mode as the empty-content guard in the main loop
        # (see the "not tool_calls" branch above): the model's forced
        # final-answer request can itself get cut off with empty content
        # (observed with a token cap reached mid-way through a very
        # complex multi-tool-call turn). Both callers of this helper
        # (token-cap path, max_steps path) would otherwise send the
        # analyst a blank Telegram message with no explanation.
        logger.warning(
            "_force_final_answer got empty content (completion_tokens=%s) "
            "— returning an explicit fallback message instead of blank text",
            usage.get("completion_tokens"),
        )
        content = (
            "⚠️ Câu hỏi này cần quá nhiều bước để trả lời đầy đủ trong một "
            "lượt — agent đã thu thập một phần dữ liệu nhưng không kịp tổng "
            "hợp câu trả lời cuối cùng. Vui lòng chia nhỏ câu hỏi (ví dụ hỏi "
            "riêng từng đơn vị hoặc từng loại thông tin) hoặc dùng lệnh "
            "slash trực tiếp."
        )
    return content, trace


def _update_session_from_tool(state: SessionState, fn_name: str,
                               args: dict, result: dict) -> None:
    """Update SessionState entities based on tool call + result.

    Field names here match the ACTUAL dict shapes returned by the 15
    tools implemented in slice 5B.3A (get_finding_detail/search_cve/etc
    return their fields flattened at the top level, not nested under a
    "finding"/"cve" key).
    """
    if fn_name == "get_finding_detail" and result.get("success"):
        state.update_entity(
            last_finding_id=result.get("id"),
            last_cve_id=(result.get("cve_id") or "").upper() or None,
        )
        customer = result.get("customer") or {}
        if customer.get("name"):
            state.update_entity(last_customer_name=customer["name"])
        asset = result.get("asset") or {}
        if asset.get("id"):
            state.update_entity(last_asset_id=asset["id"])
    elif fn_name == "search_cve" and result.get("success"):
        cves = result.get("cves") or []
        if cves:
            state.update_entity(last_cve_id=cves[0].get("cve_id"))
    elif fn_name == "search_findings" and result.get("success"):
        findings = result.get("findings") or []
        state.update_entity(
            last_result_ids=[f.get("id") for f in findings if f.get("id")],
            last_filters=args,
        )
        if args.get("customer"):
            state.update_entity(last_customer_name=args["customer"])
    elif fn_name in ("get_customer_summary", "summarize_customer", "timeline") and args.get("customer"):
        state.update_entity(last_customer_name=args["customer"])
    elif fn_name == "search_ioc" and result.get("success"):
        state.update_entity(
            last_ioc_value=result.get("ioc_value"),
            last_ioc_type=result.get("ioc_type"),
        )
    elif fn_name == "search_asset" and args.get("customer"):
        state.update_entity(last_customer_name=args["customer"])
