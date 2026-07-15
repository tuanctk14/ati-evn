"""Run the agent against a real question from CLI. Bypasses Bot 2.

Usage:
  python scripts/test_agent.py --user-id 999 "Tuần này có CVE nào HIGH?"
  python scripts/test_agent.py --user-id 999 --force-react "..."
"""
import argparse
import asyncio
import sys

from ati_evn.agent.loop import format_trace, run_agent
from ati_evn.agent.loop.react import run_react
from ati_evn.agent.session.state import load_or_create, save
from ati_evn.config import get_settings
from ati_evn.llm.client import LLMClient


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("question", nargs="+")
    ap.add_argument("--user-id", type=int, default=999)
    ap.add_argument("--force-react", action="store_true",
                     help="Skip function-calling, use ReAct directly (debug)")
    args = ap.parse_args()

    question = " ".join(args.question)
    settings = get_settings()
    client = LLMClient(settings)

    session = await load_or_create(args.user_id)

    if args.force_react:
        answer, trace = await run_react(client, session, question,
                                          fallback_reason="--force-react CLI flag")
        session.append_history("user", question)
        session.append_history("assistant", answer)
        await save(session)
        trace_block = format_trace(trace)
    else:
        answer, trace, trace_block = await run_agent(client, session, question)

    print("\n=== ANSWER ===\n")
    print(answer)
    print("\n=== TRACE ===\n")
    print(trace_block)
    print(f"\nLLM calls: {trace.total_llm_calls}")
    print(f"Total tokens: {trace.total_prompt_tokens + trace.total_completion_tokens}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
