"""Thin async client for the project's LLM provider: 9Router (DeepSeek),
via an OpenAI-compatible /chat/completions endpoint. Configured through
OPENAI_API_KEY / OPENAI_BASE_URL / LLM_MODEL / LLM_PROVIDER in .env.
"""
from __future__ import annotations

import json
import logging
import time

import httpx

from ati_evn.config import Settings

logger = logging.getLogger("ati_evn.llm.client")


class LLMError(Exception):
    """Raised when the LLM API call itself fails (non-200, transport error)."""


class LLMClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._last_usage: dict = {}

    def is_configured(self) -> bool:
        return bool(self.settings.openai_api_key)

    async def chat_json(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        timeout: float = 60.0,
    ) -> dict:
        """POST /chat/completions with JSON-object response format.

        Returns the parsed message content as a dict. Raises LLMError on
        API/transport failure, JSONExtractError (from json_extract) on
        parse failure of an otherwise-successful response.
        """
        from ati_evn.llm.json_extract import extract_json_dict

        if not self.is_configured():
            raise LLMError("OPENAI_API_KEY missing — LLM client not configured")

        url = f"{self.settings.openai_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.settings.llm_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "top_p": 0.9,
            "stream": False,
        }

        started = time.perf_counter()
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                resp = await client.post(url, headers=headers, json=payload)
            except httpx.HTTPError as e:
                detail = str(e) or f"{type(e).__name__} (no detail -- e.g. timeout after {timeout}s)"
                raise LLMError(f"LLM transport error: {detail}") from e

        duration_ms = (time.perf_counter() - started) * 1000

        if resp.status_code != 200:
            body = resp.text[:300]
            logger.error("LLM HTTP %s (%.0fms): %s", resp.status_code, duration_ms, body)
            raise LLMError(f"LLM API returned HTTP {resp.status_code}: {body}")

        # 9Router appends a stray "data: [DONE]" SSE trailer even with
        # stream=False, which breaks a plain resp.json() ("Extra data").
        # raw_decode reads only the first valid JSON object and ignores
        # whatever trailing bytes follow it.
        try:
            data, _ = json.JSONDecoder().raw_decode(resp.text)
        except json.JSONDecodeError as e:
            raise LLMError(f"LLM response was not valid JSON: {resp.text[:300]!r}") from e

        usage = data.get("usage", {})
        logger.info(
            "LLM call ok model=%s duration_ms=%.0f prompt_tokens=%s completion_tokens=%s total_tokens=%s",
            self.settings.llm_model, duration_ms,
            usage.get("prompt_tokens"), usage.get("completion_tokens"), usage.get("total_tokens"),
        )

        content = data["choices"][0]["message"]["content"]
        return extract_json_dict(content)

    async def chat_text(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 2048,
        temperature: float = 0.1,
        timeout: float = 30.0,
    ) -> str:
        """POST /chat/completions WITHOUT forcing JSON mode — returns the
        raw text content. Used by the ReAct fallback loop, whose
        Thought/Action/Observation format isn't JSON."""
        if not self.is_configured():
            raise LLMError("OPENAI_API_KEY missing — LLM client not configured")

        url = f"{self.settings.openai_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.settings.llm_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": 0.9,
            "stream": False,
        }

        started = time.perf_counter()
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                resp = await client.post(url, headers=headers, json=payload)
            except httpx.HTTPError as e:
                detail = str(e) or f"{type(e).__name__} (no detail -- e.g. timeout after {timeout}s)"
                raise LLMError(f"LLM transport error: {detail}") from e

        duration_ms = (time.perf_counter() - started) * 1000

        if resp.status_code != 200:
            body = resp.text[:300]
            logger.error("LLM text HTTP %s (%.0fms): %s", resp.status_code, duration_ms, body)
            raise LLMError(f"LLM API returned HTTP {resp.status_code}: {body}")

        try:
            data, _ = json.JSONDecoder().raw_decode(resp.text)
        except json.JSONDecodeError as e:
            raise LLMError(f"LLM response was not valid JSON: {resp.text[:300]!r}") from e

        usage = data.get("usage", {})
        self._last_usage = usage
        logger.info(
            "LLM text call ok model=%s duration_ms=%.0f prompt_tokens=%s completion_tokens=%s",
            self.settings.llm_model, duration_ms,
            usage.get("prompt_tokens"), usage.get("completion_tokens"),
        )
        return data["choices"][0]["message"]["content"]

    async def chat_with_tools(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        timeout: float = 30.0,
        tool_choice: str = "auto",  # auto | required | none
    ) -> dict:
        """POST to /chat/completions with the `tools` param (OpenAI
        function-calling format).

        messages format:
          [{"role": "system", "content": "..."},
           {"role": "user", "content": "..."},
           {"role": "assistant", "content": "...", "tool_calls": [...]},
           {"role": "tool", "tool_call_id": "...", "content": "..."}]

        Returns the raw API response dict. Caller inspects
        `.choices[0].message` for content or tool_calls.
        """
        if not self.is_configured():
            raise LLMError("OPENAI_API_KEY missing — LLM client not configured")

        url = f"{self.settings.openai_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.settings.llm_model,
            "messages": [{"role": "system", "content": system}] + messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": 0.9,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        started = time.perf_counter()
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                resp = await client.post(url, headers=headers, json=payload)
            except httpx.HTTPError as e:
                detail = str(e) or f"{type(e).__name__} (no detail -- e.g. timeout after {timeout}s)"
                raise LLMError(f"LLM transport error: {detail}") from e

        duration_ms = (time.perf_counter() - started) * 1000

        if resp.status_code != 200:
            body = resp.text[:300]
            logger.error("LLM tools HTTP %s (%.0fms): %s", resp.status_code, duration_ms, body)
            raise LLMError(f"LLM API returned HTTP {resp.status_code}: {body}")

        # Same 9Router SSE [DONE] trailer issue as chat_json.
        try:
            data, _ = json.JSONDecoder().raw_decode(resp.text)
        except json.JSONDecodeError as e:
            raise LLMError(f"LLM response was not valid JSON: {resp.text[:300]!r}") from e

        usage = data.get("usage", {})
        logger.info(
            "LLM tools call: prompt_tok=%s completion_tok=%s total=%s",
            usage.get("prompt_tokens"), usage.get("completion_tokens"),
            usage.get("total_tokens"),
        )
        return data
