"""Convert Sigma YAML -> QRadar AQL using pysigma-backend-qradar.

Degrades gracefully if the backend isn't installed. Returns None instead
of raising when conversion fails — caller displays YAML only.

pysigma-backend-qradar is intentionally NOT a hard dependency of this
project (see pyproject.toml comment): the only published release pins
pysigma<0.10 + packaging<23, which conflicts with pysigma>=0.11 and
packaging>=24.0 used elsewhere (match/version_range.py). Install it in
an isolated environment if QRadar AQL output is needed; this module
just detects its absence and reports AQL_AVAILABLE=False.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("ati_evn.rules.aql")

try:
    from sigma.backends.qradar import QRadarBackend
    from sigma.collection import SigmaCollection
    AQL_AVAILABLE = True
except ImportError as e:
    logger.warning(
        "pysigma QRadar backend not installed: %s. Rules will be delivered "
        "as YAML only (this is expected — see pyproject.toml comment).", e,
    )
    AQL_AVAILABLE = False


def sigma_yaml_to_aql(yaml_text: str) -> str | None:
    if not AQL_AVAILABLE:
        return None
    try:
        collection = SigmaCollection.from_yaml(yaml_text)
        backend = QRadarBackend()
        queries = backend.convert(collection)
        if not queries:
            return None
        return "\n".join(queries)
    except Exception as e:
        logger.warning("AQL conversion failed: %s", e)
        return None
