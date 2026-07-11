"""Smoke test: verify the configured LLM provider responds before running
the big CPE-inference batch.

Usage:
    python scripts/smoke_llm.py
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time

from ati_evn.config import get_settings
from ati_evn.llm.client import LLMClient, LLMError


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    settings = get_settings()
    if not settings.openai_api_key:
        print("ERROR: OPENAI_API_KEY missing from .env — cannot smoke-test LLM.")
        print("Set OPENAI_API_KEY / OPENAI_BASE_URL / LLM_MODEL in .env first.")
        return 2

    client = LLMClient(settings)
    print("\n=== LLM smoke test ===")
    print(f"Model    : {settings.llm_model}")
    print(f"Base URL : {settings.openai_base_url}")

    started = time.perf_counter()
    try:
        result = await client.chat_json(
            system='Return {"status":"ok"} in JSON.',
            user="say ok",
        )
    except LLMError as e:
        print(f"FAILED: {e}")
        return 1
    duration_ms = (time.perf_counter() - started) * 1000

    print(f"\nResponse content : {result}")
    print(f"Latency          : {duration_ms:.0f}ms")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
