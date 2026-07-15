"""Public entry: run_agent — handles fallback logic + timeout."""
from __future__ import annotations

import asyncio
import logging

from ati_evn.agent.loop.config import FUNCTION_CALLING_RETRY, TIMEOUT_SECONDS
from ati_evn.agent.loop.function_calling import FunctionCallingFailure, run_function_calling
from ati_evn.agent.loop.react import run_react
from ati_evn.agent.loop.trace import AgentRunTrace, format_trace
from ati_evn.agent.session.state import SessionState, save

logger = logging.getLogger("ati_evn.agent.runner")


async def run_agent(
    client, session_state: SessionState, user_message: str,
) -> tuple[str, AgentRunTrace, str]:
    """Run agent loop with fallback logic.

    Returns (answer_text, trace, trace_display_block).
    """
    fallback_reason = ""

    # Try function-calling with retry
    for attempt in range(1 + FUNCTION_CALLING_RETRY):
        try:
            answer, trace = await asyncio.wait_for(
                run_function_calling(client, session_state, user_message),
                timeout=TIMEOUT_SECONDS,
            )
            # Append to session history
            session_state.append_history("user", user_message)
            session_state.append_history("assistant", answer)
            await save(session_state)
            trace_block = format_trace(trace)
            return answer, trace, trace_block

        except asyncio.TimeoutError:
            logger.warning("Function-calling timeout on attempt %d", attempt + 1)
            fallback_reason = f"Timeout after {TIMEOUT_SECONDS}s"
        except FunctionCallingFailure as e:
            logger.warning("Function-calling failure attempt %d: %s", attempt + 1, e)
            fallback_reason = str(e)[:100]

    # Fallback to ReAct
    try:
        answer, trace = await asyncio.wait_for(
            run_react(client, session_state, user_message,
                      fallback_reason=fallback_reason),
            timeout=TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        answer = (
            "Xin lỗi, agent bị timeout. Có thể thử lại hoặc dùng command "
            "trực tiếp cho câu hỏi cụ thể."
        )
        trace = AgentRunTrace(method="react", fallback_reason="timeout in fallback")

    session_state.append_history("user", user_message)
    session_state.append_history("assistant", answer)
    await save(session_state)
    trace_block = format_trace(trace)
    return answer, trace, trace_block
