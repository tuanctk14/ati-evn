# Slice 4.5 — Attack Context Enrichment

Adds ATT&CK techniques, mitigations, and kill-chain phases to every Finding
via ATTACK-BERT semantic similarity (with deterministic CWE→ATT&CK fallback).

## What's shipped

    src/ati_evn/enrichment/
      attack_bert.py         — sentence-transformers cosine ranker (BERT)
      attack_catalog.py      — loads static ATT&CK/mitigations/CWE JSON
      cwe_chain.py           — CWE → ATT&CK deterministic backup
      orchestrator.py        — enrich_finding() public API
      _config_snippet.py     — 3 settings to append to your config.py

    src/ati_evn/data/
      attack_mitigations.json     — 44 mitigations + 586 technique→miti mapping
      cwe_to_attack.json          — 33 curated CWE→technique entries

    scripts/
      setup_embeddings.py         — one-time: download BERT + build cache
      smoke_enrichment.py         — offline sanity check (no torch needed)
      enrich_findings.py          — backfill runner + inline hook target

## Install steps

1. Extract the zip on top of your existing `D:\ati-evn` (safe — no overwrites
   of existing files, only additions in `enrichment/`, `data/`, `scripts/`).

2. Install the 2 new dependencies:

    pip install "torch>=2.1,<2.5" "sentence-transformers>=2.6"

   ~2GB download, ~5 min on typical connection. Python 3.11 wheels exist for
   Windows — no C compile step. If pip errors on torch, try:

    pip install torch --index-url https://download.pytorch.org/whl/cpu

3. Append these 3 lines to your `Settings` class in `src/ati_evn/config.py`:

    attack_bert_model: str = "basel/ATTACK-BERT"
    attack_bert_device: str = "cpu"
    smet_embeddings_cache: str = "./src/ati_evn/data/technique_embeddings.npz"

4. Verify offline path works (no network, no torch load):

    python scripts/smoke_enrichment.py

   Expected: prints 697 techniques + 44 mitigations + 33 CWE map entries.

5. Download BERT model + build embedding cache (one-time, ~2 min on CPU):

    python scripts/setup_embeddings.py

   First run downloads `basel/ATTACK-BERT` from HuggingFace (~440 MB).
   If HuggingFace unreachable, it auto-falls back to MiniLM:

    python scripts/setup_embeddings.py --model sentence-transformers/all-MiniLM-L6-v2

   Output ends with a Log4j sanity check — expect `T1190` or `T1210` in top-3.

6. Backfill enrichment on your existing 132 Findings:

    python scripts/enrich_findings.py

   Prints a progress line every 20 findings + summary. Takes ~1-2 min for 132.

7. Wire the hook into your `route_detections()` — see next section.

## Integration into route_detections

Open `src/ati_evn/match/customer_router.py`. Find where `route_detections()`
commits after creating findings. Add this block right before the final return:

    # ── Slice 4.5: enrich newly-created findings ───────────────────
    if newly_created_findings:
        from ati_evn.enrichment.orchestrator import enrich_finding, load_smet_lazy
        mapper = load_smet_lazy()  # cached module-global, safe to call each route
        for finding in newly_created_findings:
            try:
                await enrich_finding(session, finding, smet_mapper=mapper)
            except Exception as e:
                logger.warning("Enrichment failed for finding %d: %s", finding.id, e)
        await session.commit()

If your slice-3 code tracks the created findings under a different variable
name (e.g. `newly_created`, `created_findings`, `route_stats.new_findings`),
adapt the loop accordingly. The `enrich_finding()` call itself is idempotent
and safe.

## Verifying it works

After backfill + a fresh `run_matcher.py --all` pass:

    docker compose exec postgres psql -U ati_evn -d ati_evn -c "
    SELECT count(*) AS enriched
    FROM findings WHERE metadata_ ? 'attack_context';
    "

    docker compose exec postgres psql -U ati_evn -d ati_evn -c "
    SELECT f.ioc_value,
           jsonb_array_length(f.metadata_->'attack_context'->'techniques') AS n_tech,
           jsonb_array_length(f.metadata_->'attack_context'->'mitigations') AS n_miti,
           f.metadata_->'attack_context'->'kill_chain_phases' AS phases,
           (f.metadata_->'attack_context'->>'smet_used')::bool AS smet
    FROM findings f
    WHERE f.metadata_ ? 'attack_context'
    ORDER BY f.severity DESC, f.first_seen DESC
    LIMIT 5;
    "

Expected: 5 rows with 3-8 techniques, 5-15 mitigations, real T-numbered
IDs, at least a few with `smet=true`.

## When things go wrong

**Torch install fails** — use the CPU-only pytorch index:

    pip install torch --index-url https://download.pytorch.org/whl/cpu

**HuggingFace ATTACK-BERT unreachable** — the setup script auto-falls back
to MiniLM. Or force it manually:

    python scripts/setup_embeddings.py --model sentence-transformers/all-MiniLM-L6-v2

**Enrichment produces empty attack_context for all findings** — run without
BERT to confirm the chain path works:

    python scripts/enrich_findings.py --force --no-bert

If chain path works but BERT path doesn't, the model didn't load — check
`scripts/setup_embeddings.py` output for the error.

**Old cache mismatch** — force rebuild:

    python scripts/setup_embeddings.py --force

## What's NOT in this slice

- No Sigma/YARA/Suricata rule retrieval (slice 4.7)
- No playbook generation (slice 5)
- No Telegram alert formatting with the new context (slice 5)
- No malware-family → technique mapping (would need another data file
  for MITRE Software S-series relationships; adding this to slice 4.7)

Enrichment for network/hash IOCs currently uses IOC-type heuristics only
(e.g. domain → T1071 C2). Precision is intentionally low here because
without a Software-catalog lookup we're guessing.
