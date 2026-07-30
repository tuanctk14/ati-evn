# Slice 16B Phase 4 decision — Problem 3 verify

## Scenarios (via real Bot 2 Telegram, no simulation)

**V1 — Domain enrichment intent**: "Enrich domain evngov.cc"
Result: **PASS**. Agent called `enrich_ip(ip=evngov.cc, full=True)`
directly per the updated tool description ("domain string also works,
partial coverage"). Got 3/5 provider responses (VirusTotal, Pulsedive,
LeakIX), AbuseIPDB errored as expected ("only supports IP"), OTX
timed out. No "khong co cong cu DNS" conclusion.

**V2 — Asset lookup by value**: "Asset evn-web-01 co finding nao khong?"
Result: **PASS**. Agent used the new `asset_value` parameter on
`search_asset` (added in Phase 1 -- this parameter didn't exist
before this slice) instead of hallucinating a `value=` kwarg. Took 2
calls (exact match returned 0, partial match found it) due to a real
data quirk (asset name vs. Finding.matched_asset string differ
slightly), not a tool-selection failure. No hallucinated tool/kwarg.

**V3 — Scope inference**: "Tong cong co bao nhieu finding CRITICAL?"
Result: **PASS**. Agent called `search_findings(severity=CRITICAL,
limit=1)` and read `total_count` from the response, per the updated
tool description's explicit guidance for total-count queries. No
narrow-scoped/last-N-results sampling.

## Decision

**3/3 PASS → Phase 4 (the "don't conclude no tool exists" prompt
rule) is NOT implemented.** Per the spec's decision gate, schema
clarity (Phase 1: enrich_ip's domain-acceptance note, search_asset's
new asset_value param, search_findings'/search_indicators' total_count
and cap clarifications) resolved Problem 3 without needing an
additional prompt-level rule.

This is consistent with the layer-selection principle established
earlier in the manual-test phase (prompt-level fixes are unreliable
for behavioral discipline, e.g. confirm-recovery, scope-bleed -- both
needed code-layer fixes) but *schema/description clarity* is a
different kind of fix: it's giving the model correct information it
was previously missing, not asking it to suppress a tendency. That
kind of fix reliably worked here on the first try.

## Caveat

V2's 2-call pattern (exact match then partial) reflects a real data
inconsistency (asset table vs. Finding.matched_asset naming) rather
than a tool problem -- not treated as a Problem-3 regression, but
worth noting if a future data-cleanup slice touches asset naming.
