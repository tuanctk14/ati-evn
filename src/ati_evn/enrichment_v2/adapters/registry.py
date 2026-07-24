"""Maps provider name -> adapter instance."""
from __future__ import annotations

from ati_evn.enrichment_v2.adapters.abuseipdb import AbuseIPDBAdapter
from ati_evn.enrichment_v2.adapters.leakix import LeakIXAdapter
from ati_evn.enrichment_v2.adapters.otx import OTXAdapter
from ati_evn.enrichment_v2.adapters.pulsedive import PulsediveAdapter
from ati_evn.enrichment_v2.adapters.virustotal import VirusTotalAdapter

_REGISTRY = {
    "abuseipdb": AbuseIPDBAdapter(),
    "virustotal": VirusTotalAdapter(),
    "otx": OTXAdapter(),
    "pulsedive": PulsediveAdapter(),
    "leakix": LeakIXAdapter(),
}


def get_adapter(provider: str):
    adapter = _REGISTRY.get(provider)
    if not adapter:
        raise ValueError(f"Unknown provider: {provider}")
    return adapter


def all_providers() -> list[str]:
    return list(_REGISTRY.keys())
