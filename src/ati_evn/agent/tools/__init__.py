"""Tool registry.

Each tool module exposes:
  - name: str
  - description: str          (for LLM to decide when to use)
  - parameters: dict          (JSON schema, OpenAI function-calling format)
  - handler: async callable   (returns dict result)

Tools are auto-discovered — importing this module registers all.
"""
from ati_evn.agent.tools._base import TOOL_REGISTRY, Tool, tool_error

# Import each tool module — side effect registers it
from ati_evn.agent.tools import search_findings          # noqa
from ati_evn.agent.tools import get_finding_detail        # noqa
from ati_evn.agent.tools import search_cve                # noqa
from ati_evn.agent.tools import search_ioc                # noqa
from ati_evn.agent.tools import search_asset               # noqa
from ati_evn.agent.tools import timeline                   # noqa
from ati_evn.agent.tools import relationships               # noqa
from ati_evn.agent.tools import search_software             # noqa
from ati_evn.agent.tools import summarize_customer          # noqa
from ati_evn.agent.tools import generate_report             # noqa
from ati_evn.agent.tools import get_customer_summary        # noqa
from ati_evn.agent.tools import search_sigma_rules          # noqa
from ati_evn.agent.tools import get_playbook                # noqa
from ati_evn.agent.tools import explain_attack_technique    # noqa
from ati_evn.agent.tools import explain_mitigation          # noqa
from ati_evn.agent.tools import search_campaigns            # noqa
from ati_evn.agent.tools import get_campaign_detail         # noqa
from ati_evn.agent.tools import search_exposures             # noqa
from ati_evn.agent.tools import get_exposure_detail          # noqa
from ati_evn.agent.tools import search_exposed_documents     # noqa
from ati_evn.agent.tools import get_document_leak_detail     # noqa
from ati_evn.agent.tools import search_brand_abuse           # noqa
from ati_evn.agent.tools import get_brand_abuse_detail       # noqa
from ati_evn.agent.tools import get_ip_enrichment            # noqa
from ati_evn.agent.tools import search_malicious_ips         # noqa
from ati_evn.agent.tools import search_pulses                # noqa

__all__ = ["Tool", "TOOL_REGISTRY", "tool_error"]
