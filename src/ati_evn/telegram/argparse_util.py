"""Parse Telegram command args. Support both positional and --flag=value.

Example: /list_open --severity=HIGH --customer=NPC --limit=5
         -> {"severity": "HIGH", "customer": "NPC", "limit": "5", "_positional": []}

Example: /finding 12847
         -> {"_positional": ["12847"]}
"""
from __future__ import annotations

import shlex


def parse_args(text: str, command: str) -> dict:
    """Extract args after `/command`. Returns dict with parsed flags and
    a '_positional' list."""
    prefix = f"/{command}"
    idx = text.find(prefix)
    if idx < 0:
        return {}
    rest = text[idx + len(prefix):].strip()
    if not rest:
        return {"_positional": []}
    try:
        tokens = shlex.split(rest)
    except ValueError:
        tokens = rest.split()

    result: dict = {"_positional": []}
    for tok in tokens:
        if tok.startswith("--"):
            if "=" in tok:
                key, val = tok[2:].split("=", 1)
                result[key.strip()] = val.strip().strip('"').strip("'")
            else:
                result[tok[2:].strip()] = True
        else:
            result["_positional"].append(tok)
    return result
