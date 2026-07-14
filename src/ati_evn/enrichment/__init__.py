"""Attack context enrichment.

Given a Finding, compute:
  - ATT&CK techniques (via ATTACK-BERT semantic similarity, with CWE-based
    deterministic chain as backup)
  - CWEs (already stored in cve_cwe_map from slice 4)
  - Mitigations (deterministic from ATT&CK STIX bundle)
  - Kill chain phases (deterministic from ATT&CK bundle)

Output lands in Finding.metadata_['attack_context'].

Architecture:
  - attack_catalog: loads static JSON data (techniques, mitigations, kill chain)
  - cwe_chain:      CWE → ATT&CK deterministic backup mapping
  - attack_bert:    lazy-loaded sentence-transformers model + cached
                    technique embeddings, cosine similarity ranking
  - orchestrator:   enrich_finding() — public API called from customer_router

Imports are lazy so smoke-testing the catalog+chain path does not require
DB models or torch to be importable.
"""
# Do not eagerly import orchestrator — it depends on ORM models (CveCweMap,
# Detection, Finding) which may not exist yet on installations that
# haven't run slice-4 REDO. Consumers import from `ati_evn.enrichment.orchestrator`
# directly.
