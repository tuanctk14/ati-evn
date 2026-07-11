"""Robust JSON extraction from LLM output.

Small/quantized models in JSON mode are usually clean, but occasionally wrap
the object in markdown fences or prepend a stray sentence. Ported from
CyberGuard's crew.py _extract_json — 3-tier fallback rather than a single
strict json.loads, so a minor formatting slip doesn't blow up the whole
batch run.
"""
from __future__ import annotations

import json
import re


class JSONExtractError(Exception):
    """Raised when no valid JSON could be extracted from the text."""


def _find_balanced_braces(text: str, open_char: str, close_char: str) -> str | None:
    start = text.find(open_char)
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == open_char:
            depth += 1
        elif text[i] == close_char:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _strip_markdown_fences(text: str) -> str:
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    return match.group(1) if match else text


def _extract_json_any(text: str) -> object:
    text = text.strip()

    # Tier 1: direct parse.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Tier 2: strip ```json ... ``` fences, then parse.
    fenced = _strip_markdown_fences(text)
    if fenced != text:
        try:
            return json.loads(fenced.strip())
        except json.JSONDecodeError:
            pass

    # Tier 3: find the first '{' or '[' and balance braces/brackets.
    for open_char, close_char in (("{", "}"), ("[", "]")):
        candidate = _find_balanced_braces(text, open_char, close_char)
        if candidate:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

    raise JSONExtractError(f"Could not extract valid JSON from text: {text[:200]!r}")


def extract_json_dict(text: str) -> dict:
    """Extract a JSON object from LLM output. Raises JSONExtractError if the
    extracted value isn't a dict."""
    value = _extract_json_any(text)
    if not isinstance(value, dict):
        raise JSONExtractError(f"Extracted JSON is not a dict (got {type(value).__name__})")
    return value


def extract_json_list(text: str) -> list:
    """Extract a JSON array from LLM output. Raises JSONExtractError if the
    extracted value isn't a list."""
    value = _extract_json_any(text)
    if not isinstance(value, list):
        raise JSONExtractError(f"Extracted JSON is not a list (got {type(value).__name__})")
    return value
