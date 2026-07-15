"""Standalone tool CLI. Bypasses Bot 2 and agent loop — calls
tool handlers directly with JSON args.

Usage:
  python scripts/test_tool.py --list
  python scripts/test_tool.py search_findings --args='{"customer": "NPC", "severity": "HIGH"}'
  python scripts/test_tool.py get_finding_detail --args='{"finding_id": 12847}'
  python scripts/test_tool.py --list-schemas
"""
import argparse
import asyncio
import json
import sys

from ati_evn.agent.tools import TOOL_REGISTRY
from ati_evn.agent.tools._base import get_all_openai_schemas


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tool_name", nargs="?")
    ap.add_argument("--args", default="{}",
                    help="JSON string of kwargs")
    ap.add_argument("--list", action="store_true",
                    help="List all tools")
    ap.add_argument("--list-schemas", action="store_true",
                    help="Print full OpenAI function-calling schemas")
    args = ap.parse_args()

    if args.list:
        for name, tool in TOOL_REGISTRY.items():
            print(f"{name:35s} {tool.description[:80]}")
        return 0

    if args.list_schemas:
        print(json.dumps(get_all_openai_schemas(), indent=2))
        return 0

    if not args.tool_name:
        ap.error("tool_name required")

    if args.tool_name not in TOOL_REGISTRY:
        print(f"Tool '{args.tool_name}' not registered. Use --list to see all.")
        return 1

    try:
        kwargs = json.loads(args.args)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in --args: {e}")
        return 1

    result = await TOOL_REGISTRY[args.tool_name].handler(**kwargs)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
