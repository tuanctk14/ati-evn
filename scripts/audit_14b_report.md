# ATI-EVN Slice 14B Audit Report

Generated: 2026-07-27T20:13:33.233662+00:00

## Summary

- CRITICAL: 0 issue(s)
- HIGH: 0 issue(s)
- MEDIUM: 2 issue(s) — deferred to backlog
- LOW: 6 issue(s) — deferred to backlog
- INFO: 5 note(s)

## A. Data consistency

### [MEDIUM] A.2: 1 soft-deleted customer(s) with active findings/assets
Soft-deleted customers still have OPEN/ACKED findings or live (non-deleted) assets. This data still surfaces in global reports/queries that don't filter by customer status.

**Evidence:**
```
  Customer #14 'TEST_CORP': 1 open/acked findings, 0 active assets
```

**Recommended fix:** Either cascade-close findings and soft-delete assets when a customer is soft-deleted, or exclude soft-deleted customers' children explicitly in report queries. Deferred.

## B. Code duplication

### [LOW] B.1: 2 file(s) with duplicate import statements
Duplicate import statements clutter files.

**Evidence:**
```
  src\ati_evn\external\censys_client.py: {'asyncio': 2}
  src\ati_evn\telegram\commands\query.py: {'ati_evn.telegram.formatter.common.fmt_dt': 2}
```

**Recommended fix:** Manual cleanup or `ruff check --select F811 --fix`.

### [LOW] B.3: renderer.py has 2 similar path builders
`_output_paths` and `_customer_output_paths` share nearly identical logic (day-folder + timestamped filename). Could be unified with a prefix parameter.

**Evidence:**
```
Both functions found in src/ati_evn/reports/renderer.py
```

**Recommended fix:** Unify to _output_paths(prefix='global'|f'customer_{code}').

### [LOW] B.4: 58 unused imports across codebase
Dead imports increase cognitive load, no runtime impact.

**Evidence:**
```
src\ati_evn\config.py:9:1: 'pydantic.Field' imported but unused
src\ati_evn\agent\tools\relationships.py:22:1: 'ati_evn.db.query_utils.only_live_customer' imported but unused
src\ati_evn\agent\tools\summarize_customer.py:12:1: 'ati_evn.db.models.FindingStatus' imported but unused
src\ati_evn\agent\tools\__init__.py:14:1: 'ati_evn.agent.tools.search_findings' imported but unused
src\ati_evn\agent\tools\__init__.py:15:1: 'ati_evn.agent.tools.get_finding_detail' imported but unused
src\ati_evn\agent\tools\__init__.py:16:1: 'ati_evn.agent.tools.search_cve' imported but unused
src\ati_evn\agent\tools\__init__.py:17:1: 'ati_evn.agent.tools.search_ioc' imported but unused
src\ati_evn\agent\tools\__init__.py:18:1: 'ati_evn.agent.tools.search_asset' imported but unused
src\ati_evn\agent\tools\__init__.py:19:1: 'ati_evn.agent.tools.timeline' imported but unused
src\ati_evn\agent\tools\__init__.py:20:1: 'ati_evn.agent.tools.relationships' imported but unused
src\ati_evn\agent\tools\__init__.py:21:1: 'ati_evn.agent.tools.search_software' imported but unused
src\ati_evn\agent\tools\__init__.py:22:1: 'ati_evn.agent.tools.summarize_customer' imported but unused
src\ati_evn\agent\tools\__init__.py:23:1: 'ati_evn.agent.tools.generate_report' imported but unused
src\ati_evn\agent\tools\__init__.py:24:1: 'ati_evn.agent.tools.get_customer_summary' imported but unused
src\ati_evn\agent\tools\__init__.py:25:1: 'ati_evn.agent.tools.search_sigma_rules' imported but unused
```

**Recommended fix:** Run `ruff check --select F401 --fix` or manual cleanup.

### [INFO] B.5: Schema naming inconsistency (informational)
Finding uses first_seen/last_seen; Exposure/ExposedDocument/BrandAbuseSighting use first_seen_local/last_seen_local (distinct from first_seen_censys/last_seen_censys on Exposure).

**Evidence:**
```
  Finding: ['first_seen', 'last_seen']
  Exposure: ['first_seen_censys', 'last_seen_censys', 'first_seen_local', 'last_seen_local']
  ExposedDocument: ['last_modified', 'first_seen_local', 'last_seen_local']
  BrandAbuseSighting: ['first_seen_local', 'last_seen_local']
  Detection: ['first_seen', 'last_seen']
```

**Recommended fix:** Deferred — rename would be a breaking change. Document in thesis Limitations chapter.

## C. Configuration

### [LOW] C.1: load_config() uses lru_cache — YAML edits need a process restart
Editing enrichment_config.yaml (e.g. provider weights) does not take effect until the Bot process restarts, since load_config() caches the parsed result for the life of the process.

**Recommended fix:** Document in ops runbook, or add a /reload_config command.

## D. Resource management

### [INFO] D.1: reports/ folder = 0.5 MB, 16 files
Within acceptable range for now.

### [INFO] D.2: No dedicated log files found on disk
Logging may go to stdout/journald only — check deployment setup.

### [INFO] D.3: Table sizes: detections=24691, findings=212
Below the archive-policy threshold for now.

## E. Error handling

### [LOW] E.1: 76 bare/broad except clauses (no re-raise)
Silent exception swallowing risks hiding bugs -- this pattern was the root cause of several earlier silent-bug fixes in this project's fetcher code (see commit history: 'fix silent HTTP-error swallowing in fetchers', 'fix silent CVE batch-insert bugs').

**Evidence:**
```
  src\ati_evn\agent\loop\react.py:91
  src\ati_evn\agent\tools\action_enrich_ip.py:37
  src\ati_evn\agent\tools\add_ioc.py:91
  src\ati_evn\agent\tools\force_fetch_feed.py:39
  src\ati_evn\agent\tools\ingest_article.py:61
  src\ati_evn\agent\tools\ingest_article.py:69
  src\ati_evn\agent\tools\rescan_finding.py:58
  src\ati_evn\agent\tools\scan_brand_abuse.py:71
  src\ati_evn\agent\tools\scan_censys.py:42
  src\ati_evn\agent\tools\scan_document_leak.py:36
  src\ati_evn\agent\tools\summarize_customer.py:126
  src\ati_evn\agent\tools\_action_base.py:162
  src\ati_evn\agent\tools\_base.py:50
  src\ati_evn\brand_rules\llm_classifier.py:72
  src\ati_evn\document_rules\llm_classifier.py:70
  src\ati_evn\enrichment\attack_bert.py:195
  src\ati_evn\enrichment\orchestrator.py:113
  src\ati_evn\enrichment_v2\epss_client.py:58
  src\ati_evn\enrichment_v2\kev_client.py:50
  src\ati_evn\enrichment_v2\adapters\abuseipdb.py:40
```

**Recommended fix:** Audit each — either log-and-continue with an explicit reason, or re-raise. Fetchers in particular must re-raise on network/HTTP errors rather than swallow them.

### [MEDIUM] E.2: 15 LLM call site(s) without an explicit timeout wrap
An LLM call that hangs can block the scheduler or agent loop. Note: the agent function-calling loop already passes timeout=30.0 into client.chat_with_tools directly at the call site (see agent/loop/function_calling.py), so this check is line-grep-based and may double count sites where the timeout is a kwarg on the same call rather than a separate wait_for/timeout keyword nearby.

**Evidence:**
```
src\ati_evn/agent/loop/function_calling.py:52:            response = await client.chat_with_tools(
src\ati_evn/agent/loop/function_calling.py:170:    response = await client.chat_with_tools(
src\ati_evn/agent/loop/react.py:85:            raw = await client.chat_text(
src\ati_evn/agent/tools/summarize_customer.py:116:        raw = await client.chat_json(
src\ati_evn/brand_rules/llm_classifier.py:66:        raw = await client.chat_json(
src\ati_evn/document_rules/llm_classifier.py:64:        raw = await client.chat_json(
src\ati_evn/exposure_rules/vuln_matcher.py:122:        raw = await client.chat_json(
src\ati_evn/ingestion/extractor.py:90:        raw = await client.chat_json(
src\ati_evn/llm/cpe_inferrer.py:139:        response = await client.chat_json(SYSTEM_PROMPT, user_prompt)
src\ati_evn/reports/narrative.py:93:        text = await client.chat_text(
```

**Recommended fix:** For call sites without an inline timeout kwarg, add asyncio.wait_for(..., timeout=60) around scheduled/background paths. Interactive/user-triggered commands can rely on the user cancelling.

### [LOW] E.3: 12 client file(s) without a @retry decorator
External API clients should retry transient network errors.

**Evidence:**
```
src/ati_evn/enrichment_v2/adapters/abuseipdb.py
src/ati_evn/enrichment_v2/adapters/leakix.py
src/ati_evn/enrichment_v2/adapters/otx.py
src/ati_evn/enrichment_v2/adapters/pulsedive.py
src/ati_evn/enrichment_v2/adapters/virustotal.py
src/ati_evn/external/attribution.py
src/ati_evn/external/brand_abuse_ingest.py
src/ati_evn/external/document_ingest.py
src/ati_evn/external/exposure_ingest.py
src/ati_evn/external/grayhat_weekly.py
src/ati_evn/external/urlscan_weekly.py
src/ati_evn/external/weekly_scan.py
```

**Recommended fix:** Add a tenacity @retry decorator on the fetch functions, where not already handled by an httpx retry transport.

### [INFO] E.4: Transaction rollback check (informational)
SQLAlchemy's async_session() context manager rolls back automatically on an exception exiting the `async with` block -- no explicit rollback call is needed as long as every write goes through `async with async_session() as session:`. This audit does not attempt to verify every call site mechanically; spot-checked call sites in this codebase consistently follow that pattern.

## F. Backfill

_No issues found — category clean._

