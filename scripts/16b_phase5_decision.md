# Slice 16B Phase 5 decision — S2 cache assessment

## Note on scenario adaptation

Step (a) of the original S2 sequence ("Scan brand abuse cho EVN")
hit the agent turn's 60s TIMEOUT_SECONDS -- confirmed via a follow-up
control query (an unrelated question succeeded in 6s immediately
after) that this was a genuine slow-tool-vs-turn-timeout mismatch, not
an LLM provider outage. Logged separately in
scripts/audit_14b_backlog.md. Adapted the cache-assessment sequence to
use `search_brand_abuse` (reads already-ingested DB rows, no live
urlscan.io call) instead of `scan_brand_abuse` for step (b)'s
prerequisite data, since the goal here is measuring tool-call
repetition in the reasoning chain, not re-verifying the scan tool
itself (already covered elsewhere in this session's testing).

## Result

**"Sighting nao cua EVN co typosquat distance nho nhat?"**
Tool calls: 2 (`search_brand_abuse(keyword=EVN, malicious_only=True,
limit=50)` → 1 result, then `search_brand_abuse(keyword=EVN,
limit=50)` → 20 results). Correctly identified sighting #14
(evn.io.vn, typosquat_distance=2) and cross-referenced it to
ThreatIndicator #72, matching previously-verified data.

2 calls to arrive at the answer, both directly relevant (first a
narrower malicious-only filter, then falling back to the full set when
that returned only 1 row) -- not the 3-4 exploratory/repeated lookups
originally observed in the retest's Test A pattern.

## Decision

**1-2 lookups per step → cache NOT NEEDED.** Per the spec's Phase 5
gate ("If 1-2 lookups per step: cache NOT NEEDED. Ghi backlog"), no
in-session tool-call cache is implemented in this slice.

The improvement from the original retest (which showed the agent
scope-limiting itself to 7 just-scanned sightings and missing
evn.io.vn/#14 entirely) is attributable to two things fixed earlier in
this session, not to slice 16B directly:
1. The Phase 1 schema clarity work generally reduced confused
   tool selection (verified in Phase 4's V1-V3).
2. Using `search_brand_abuse` (full DB read) instead of
   `scan_brand_abuse` (live scan, naturally scoped to only what that
   scan run returns) sidesteps the original failure mode, where the
   agent conflated "sightings from my last scan" with "all known
   sightings" -- a distinction that's about tool semantics, not
   call-count efficiency, and outside a cache's ability to fix (a
   cache would just serve the same too-narrow scan result faster).

No cache design work is warranted based on this evidence.
