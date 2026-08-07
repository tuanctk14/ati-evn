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
from ati_evn.agent.tools import generate_sigma_rule         # noqa
from ati_evn.agent.tools import get_playbook                # noqa
from ati_evn.agent.tools import generate_playbook            # noqa
from ati_evn.agent.tools import explain_attack_technique    # noqa
from ati_evn.agent.tools import explain_mitigation          # noqa
from ati_evn.agent.tools import top_attack_techniques       # noqa
from ati_evn.agent.tools import top_cve_by_finding_count    # noqa
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

# Action tools (slice 14A) -- destructive/mutating, confirmation + audit log
from ati_evn.agent.tools import acknowledge_alert            # noqa
from ati_evn.agent.tools import action_enrich_ip              # noqa
from ati_evn.agent.tools import add_customer                  # noqa
from ati_evn.agent.tools import add_customer_asset            # noqa
from ati_evn.agent.tools import remove_customer_asset         # noqa
from ati_evn.agent.tools import update_customer                # noqa
from ati_evn.agent.tools import add_ioc                        # noqa
from ati_evn.agent.tools import update_ioc                      # noqa
from ati_evn.agent.tools import delete_ioc                      # noqa
from ati_evn.agent.tools import create_finding                  # noqa
from ati_evn.agent.tools import update_finding_status           # noqa
from ati_evn.agent.tools import rescan_finding                   # noqa
from ati_evn.agent.tools import export_findings                  # noqa
from ati_evn.agent.tools import list_reports                      # noqa
from ati_evn.agent.tools import download_report                   # noqa
from ati_evn.agent.tools import trigger_report_generation          # noqa

# Phase 5 action tools (slice 14A) -- scan/campaign/ingestion
from ati_evn.agent.tools import scan_document_leak            # noqa
from ati_evn.agent.tools import scan_brand_abuse               # noqa
from ati_evn.agent.tools import scan_censys                     # noqa
from ati_evn.agent.tools import force_fetch_feed                 # noqa
from ati_evn.agent.tools import create_campaign                   # noqa
from ati_evn.agent.tools import confirm_campaign                   # noqa
from ati_evn.agent.tools import reject_campaign                     # noqa
from ati_evn.agent.tools import ingest_article                       # noqa

# ThreatIndicator tools (slice 15B) -- non-CVE signals split from Finding
from ati_evn.agent.tools import search_indicators             # noqa
from ati_evn.agent.tools import get_indicator_detail            # noqa
from ati_evn.agent.tools import acknowledge_indicator             # noqa
from ati_evn.agent.tools import add_indicator_note                  # noqa
from ati_evn.agent.tools import export_indicators                    # noqa

__all__ = ["Tool", "TOOL_REGISTRY", "tool_error"]
