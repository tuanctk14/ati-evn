"""Thin async client for the project's LLM provider: 9Router (DeepSeek),
via an OpenAI-compatible /chat/completions endpoint. Configured through
OPENAI_API_KEY / OPENAI_BASE_URL / LLM_MODEL / LLM_PROVIDER in .env.
"""
from __future__ import annotations

import json
import logging
import time

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import Settings

logger = logging.getLogger("ati_evn.llm.client")

# Only 2 attempts / short backoff -- this sits inside the agent turn's overall
# timeout budget (see agent/loop/runner.py TIMEOUT_SECONDS), so retrying here
# must not itself risk blowing that budget on a slow/degraded provider.
_LLM_RETRY = retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(min=1, max=3),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)


@_LLM_RETRY
async def _post(url: str, headers: dict, payload: dict, timeout: float) -> httpx.Response:
    async with httpx.AsyncClient(timeout=timeout) as client:
        return await client.post(url, headers=headers, json=payload)


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
        _retry_on_empty: bool = True,
        _retry_on_backend_error: bool = True,
    ) -> dict:
        """POST /chat/completions with JSON-object response format.

        Returns the parsed message content as a dict. Raises LLMError on
        API/transport failure, JSONExtractError (from json_extract) on
        parse failure of an otherwise-successful response.
        """
        from ati_evn.llm.json_extract import JSONExtractError, extract_json_dict

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
        try:
            resp = await _post(url, headers, payload, timeout)
        except httpx.HTTPError as e:
            detail = str(e) or f"{type(e).__name__} (no detail -- e.g. timeout after {timeout}s)"
            raise LLMError(f"LLM transport error: {detail}") from e

        duration_ms = (time.perf_counter() - started) * 1000

        if resp.status_code != 200:
            body = resp.text[:300]
            # 9Router load-balances across backends; some (observed:
            # "DFLASH") don't support grammar-constrained decoding (what
            # response_format={"type":"json_object"} relies on) and
            # reject the request outright with HTTP 400 instead of just
            # that backend failing over. This isn't a malformed request
            # on our end -- retrying once typically routes to a
            # different, compatible backend. Only retry this specific
            # transient-backend signature, not HTTP 400 in general
            # (which is usually a real request problem that retrying
            # won't fix).
            if (
                resp.status_code == 400
                and _retry_on_backend_error
                and "grammar-constrained decoding" in body
            ):
                logger.warning(
                    "chat_json got a backend-incompatibility 400 (%s) — "
                    "retrying once, likely routes to a different backend",
                    body[:150],
                )
                return await self.chat_json(
                    system, user, max_tokens=max_tokens, temperature=temperature,
                    timeout=timeout, _retry_on_empty=_retry_on_empty,
                    _retry_on_backend_error=False,
                )
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
        completion_tokens = usage.get("completion_tokens")
        # Truncation shows up two ways, both meaning the same thing (the
        # completion got cut off mid-structure before valid JSON was
        # complete): (1) content comes back fully empty, or (2) content is
        # present but is a partial JSON fragment (e.g. a string value cut
        # off mid-word) that fails to parse. Observed at 5 independent
        # call sites (/playbook, generate_report, brand_rules,
        # document_rules classifiers, sigma_generator) -- (1) and (2) can
        # both happen depending on exactly where the cutoff lands. Retry
        # once with a larger budget for either; only retry once
        # (_retry_on_empty=False on the recursive call) so a persistently
        # bad response still surfaces as a real error rather than looping.
        if not content and _retry_on_empty:
            logger.warning(
                "chat_json got empty content (completion_tokens=%s, max_tokens=%s) "
                "— retrying once with a larger token budget",
                completion_tokens, max_tokens,
            )
            return await self.chat_json(
                system, user,
                max_tokens=min(max_tokens * 2, 16000),
                temperature=temperature, timeout=timeout,
                _retry_on_empty=False,
            )
        try:
            return extract_json_dict(content)
        except JSONExtractError:
            if _retry_on_empty and completion_tokens and completion_tokens >= max_tokens:
                logger.warning(
                    "chat_json got truncated/unparseable content (completion_tokens=%s, "
                    "max_tokens=%s) — retrying once with a larger token budget",
                    completion_tokens, max_tokens,
                )
                return await self.chat_json(
                    system, user,
                    max_tokens=min(max_tokens * 2, 16000),
                    temperature=temperature, timeout=timeout,
                    _retry_on_empty=False,
                )
            raise

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
        try:
            resp = await _post(url, headers, payload, timeout)
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
        try:
            resp = await _post(url, headers, payload, timeout)
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
