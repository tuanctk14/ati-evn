# ATI-EVN Audit Backlog (14B deferred issues)

Deferred to future work / thesis Limitations chapter.

- [FIXED] **Post-backlog manual retest (Phase 2)**: `scan_document_leak` agent tool could exceed the agent turn's 60s TIMEOUT_SECONDS (same bug class as the earlier scan_brand_abuse fix)
  Found on "Scan tài liệu rò rỉ từ khóa EVN" -- the turn timed out on both the function-calling attempt AND
  the ReAct fallback attempt (log: `Function-calling timeout on attempt 2`), taking 181 seconds total before
  finally erroring out to the analyst as "Xin lỗi, agent bị timeout". Root cause: `agent/tools/scan_document_leak.py`
  ran GrayHatWarfare search + LLM relevance classification for every candidate file synchronously inside the
  tool call -- with ~50 files and 2-6s per LLM classifier call, this routinely exceeds the 60s turn budget.
  This was flagged as a known gap when `scan_brand_abuse` got the same fix earlier in this session (see the
  `[RESOLVED] Slice 16B retest / Post-16B` entry below: "scan_ghwarfare/scan_censys were not converted in
  this pass"), and has now materialized on retest. Fixed by applying the exact same pattern already proven
  for `scan_brand_abuse.py`: split into `_run_scan()` (the actual work) + `_run_and_notify()` (runs the scan
  then `bot.send_message()`s a formatted result), and the tool handler now fires `_run_and_notify()` as a
  background `asyncio.Task` (kept in a module-level `_background_tasks` set so it can't be GC'd mid-run) and
  returns `{"status": "queued"}` immediately when `_bot`/`_chat_id` context is present (already auto-forwarded
  by `register_action_tool`'s `accepts_bot_context=True`), falling back to the original synchronous behavior
  when no bot context exists (CLI/test harness). `scan_censys` was NOT converted in this pass -- it's a
  single-IP Censys API call with no per-item LLM classification loop, so it's unlikely to hit the same
  timeout, but should get the same treatment if it's ever observed to. Verified live on Bot 2 after restart:
  re-running the exact same question that previously timed out at 181s now completes the initiating turn in
  6.9s ("scan queued"), with the completion notification ("📄 Document leak scan hoàn tất...") arriving
  automatically ~4 minutes later with correct file/indicator counts (50 files, 40 new, 16 indicators).

- [FIXED] **Post-backlog manual retest (Phase 2)**: free-text agent sent a completely empty answer ("⚠️ (Câu trả lời rỗng...)")
  Found on "Chỉ báo nào cần điều tra gấp nhất cho EVN?" -- a complex turn with several prior tool calls
  already in context (long `messages` list). `agent/loop/function_calling.py`'s per-step call to
  `chat_with_tools(..., max_tokens=2048)` got cut off mid-generation (log showed `completion_tok=2048`,
  landing exactly on the cap) before the model emitted either real `content` or a complete `tool_calls`
  array, so both came back empty. The loop's `if not tool_calls: return content, trace` treated that as a
  valid final answer with no empty-check, so `run_agent()` returned `""`, which
  `telegram/commands/agent_handler.py`'s `_send_markdown()` correctly detected as empty AFTER markdown-strip
  and showed the "câu trả lời rỗng" fallback -- but the root cause was upstream, not the Markdown sanitizer
  added earlier this session (confirmed via log: `original: ''` was already empty before any stripping).
  Fixed by adding an empty-content-and-no-tool_calls guard: when both are empty, treat it as a truncated
  response and route through the existing `_force_final_answer()` path (drops `tools=[]`, asks explicitly
  for a concise final summary) instead of returning the blank string. Verified live on Bot 2 after restart:
  re-running the exact same question no longer produces an empty answer (this particular retry actually
  hit the ReAct fallback due to a 60s timeout on a different step, unrelated to this fix, and ReAct answered
  successfully) -- confirmed via log grep that "Agent answer became empty" did not fire again.

- [FIXED] **Post-backlog manual retest**: `/add_ioc` reported matcher stats for the WRONG detections (whole NEW batch, not just the one just added)
  Found during Phase 1 manual retest (2026-07-31): `/add_ioc --type=domain --value=test-manual-check.example.com
  --severity=LOW` (a throwaway test IOC) replied "Matcher: 440 matched, 109 finding(s) created" -- wildly
  disproportionate for one LOW-severity test domain. Root cause: both `telegram/commands/add_ioc.py:99` and
  `agent/tools/add_ioc.py:93` called `route_detections(session, only_new=True)` after inserting the new
  Detection, instead of scoping the matcher pass to just that row. `only_new=True` matches ALL
  `Detection.status == NEW` rows in the DB, so it also swept up an unrelated batch of ~1500 NVD CVE
  detections inserted moments earlier by the fetcher (not yet processed by the hourly `run_detection_once`
  job) and reported their match/finding counts back to the analyst as if they came from the one IOC just
  added -- a materially misleading number for an analyst deciding how urgently to react. Confirmed via
  `SELECT ... FROM findings WHERE first_seen > now() - interval '10 minutes'` that all 109 "new" findings
  were `cve_id` findings from the NVD batch, none related to the test domain. Other call sites got this
  right already: `route_detections()` has a `detection_ids: list[int] | None` param specifically for this
  ("scopes the pass to exactly those rows"), and both `ingestion/confirm.py:162` and
  `telegram/commands/restore_ioc.py:60` already use it. Fixed both `add_ioc.py`'s to pass
  `detection_ids=[detection_id]` instead of `only_new=True`, matching the existing correct pattern. Verified
  live on Bot 2 after restart: `/add_ioc --type=domain --value=test-manual-check-2.example.com --severity=LOW`
  now correctly replies "Matcher: 0 matched, 0 finding(s) created" (a throwaway test domain matches nothing),
  no longer polluted by the unrelated NVD batch.

- [BUG] **Post-backlog manual retest**: `/playbook <CVE-ID>` can fail with "Could not extract valid JSON from text"
  Found during the post-E.1/E.3 manual retest (2026-07-31), NOT a regression from those changes --
  `telegram/commands/playbook.py`'s `_get_or_generate()` calls `LLMClient.chat_json(..., max_tokens=4096)`
  asking for a full NIST 800-61 playbook (5 sections, Vietnamese narrative + commands) as a JSON string value.
  For a CVE with rich context (e.g. CVE-2026-47295 on a SQL Server asset), the model's `markdown` field can
  get truncated mid-sentence before the closing `"}/` of the JSON object, so all 3 tiers of
  `llm/json_extract.py`'s `_extract_json_any()` fail (direct parse, fence-strip, brace-balance) since the
  JSON itself is incomplete -- not a formatting slip the fallback tiers can recover from. Pre-existing issue,
  unrelated to `chat_json`'s retry/logging changes in this session. Fix approach: raise `max_tokens` for this
  specific call (playbook content is long by design) and/or ask the model to emit the 5 sections as separate
  string fields instead of one giant markdown blob, reducing the chance any single field overruns the budget.

- [INFRA, not a code bug] **Post-backlog manual retest**: LeakIX provider unreachable on this host (`ConnectError`, firewall)
  Every `/enrich_ip` call during the 2026-07-31 retest shows `leakix: unknown score=0 (ConnectError: )`.
  Confirmed via a direct `httpx.get("https://leakix.net/host/...")` probe outside the app: same `ConnectError`
  with root cause `BrokenResourceError` -- user confirmed this host's firewall blocks LeakIX. Not a code
  defect: the new `@retry` (E.3) correctly retried 3x before giving up, and the new `logger.warning(...)`
  (E.1) correctly surfaced the failure instead of silently swallowing it (previously this failure mode had
  NO log line at all -- this is actually the E.1 fix doing its job, making a pre-existing silent failure
  visible). `str(ConnectError(...))` being empty is normal httpx behavior for a bare connection-reset with
  no OS-level errno text. No action needed in code; LeakIX will keep failing gracefully (falls back to
  "unknown" in the aggregate) as long as the firewall rule stands.

- [RESOLVED] **Slice 16B retest / Post-16B**: scan_brand_abuse could exceed the agent turn's 60s TIMEOUT_SECONDS
  Originally: "Scan brand abuse cho Vietnam Electricity" via free-text timed out with no tool-call trace -- the LLM response + urlscan.io API call + up to 8 internal LLM classifier calls together exceeded `asyncio.wait_for(..., timeout=TIMEOUT_SECONDS)` in `agent/loop/runner.py`, which wraps the WHOLE turn, not just the tool call. Fixed by threading Telegram `bot`/`chat_id` context through the agent loop (`SessionState._bot`/`_chat_id`, set by `agent_handler.py`, forwarded through `function_calling.py`/`react.py` into `TOOL_REGISTRY[...].handler(...)`, and a new `accepts_bot_context` flag on `register_tool`/`register_action_tool` that forwards them to a tool's `_bot`/`_chat_id` params) -- the same mechanism `_session_id` already used. `scan_brand_abuse` now fires the scan as a background `asyncio.Task` when Telegram context is present, returns `{"status": "queued"}` immediately so the turn completes well under budget, and sends a follow-up Telegram message via `bot.send_message()` when the scan finishes, mirroring `rescan.trigger_rescan_background`'s pattern for `/add_asset`. Falls back to the original synchronous behavior when no bot context is available (e.g. a CLI/test harness calling the tool directly). Verified end-to-end via real Bot 2: the initiating turn completed in ~10s ("scan queued"), and the completion notification ("🎭 Brand abuse scan hoàn tất...") arrived automatically ~45s later with correct sighting/finding counts. `scan_ghwarfare`/`scan_censys` were not converted in this pass (same fix would apply if they're observed hitting the same timeout).

- [RESOLVED] **Post-16B**: brand_abuse/document_leak/exposure ingest pipelines mislabeled ThreatIndicator creation as "findings_created"
  Discovered when the background-scan notification (added in the fix above) reported "3 finding mới" to the analyst for a `scan_brand_abuse` run, despite no new `Finding` row existing -- post slice 15A, brand abuse (and document leak, and the exposure rule-match/service/config path) create `ThreatIndicator` rows, not `Finding` rows, but the stats dict key from before that split was never renamed. Renamed `stats["findings_created"]` -> `stats["indicators_created"]` at the two ingest sources (`external/brand_abuse_ingest.py`, `external/document_ingest.py`) and cascaded through their callers: `external/grayhat_weekly.py`, `external/urlscan_weekly.py` (weekly scheduler wrappers), `agent/tools/scan_brand_abuse.py`, `agent/tools/scan_document_leak.py` (agent tools), and `telegram/commands/scan_ghwarfare.py`/`scan_urlscan.py` (slash-commands' "Findings created:" display line -> "Indicators created:"). Also found the same issue one level deeper in `exposure_rules/finding_creator.py`'s `process_exposures()`: its `service_findings`/`config_findings` stats fields also create `ThreatIndicator` rows (only `vuln_findings` creates a real `Finding`) -- left those field names as-is (public stats contract, used by other callers) but documented it in the function's docstring, and fixed the one caller that mis-summed all three into a single "findings_created" total (`external/weekly_scan.py`) to split it correctly into `findings_created` (vuln_findings only) and `indicators_created` (service+config findings). Verified end-to-end: the same scan that previously reported "3 finding mới" now correctly reports "2 indicator mới".

- [RESOLVED] **A.2**: soft-deleted customer(s) with active findings/assets leaking into reports
  `reports/data_gatherer.py`'s Section 1 ("Findings breakdown", `gather_global_report`) and Section 2 ("Vulnerabilities") queries had no customer-status filter, so a soft-deleted customer's still-open Finding rows (e.g. TEST_CORP, a soft-deleted test customer with 1 open Finding) surfaced in global report totals and per-customer breakdowns. Added `Finding.customer_id.in_(select(Customer.id).where(only_live_customer()))` to both queries -- `search_findings` (the agent tool) already had this filter, only the report data-gatherer was missing it. `gather_customer_report` (single-customer report, customer_id passed explicitly by the caller) was left unchanged -- if an analyst deliberately requests a report for a soft-deleted customer by id, that's an intentional historical-lookup case, not the "leaks into aggregate reports" bug this item was about. Verified: a 365-day global report window no longer includes TEST_CORP in `findings.by_customer`.

- [RESOLVED / re-scoped] **E.2**: 15 LLM call site(s) without an explicit timeout wrap
  Re-investigated: `LLMClient.chat_json`/`chat_text`/`chat_with_tools` each already have their own default `timeout` parameter (60s/30s/30s respectively) -- a call site omitting `timeout=` still has a real httpx-level timeout, just the method's default rather than a per-call override. So "without an explicit timeout wrap" was a less severe finding than the original phrasing implied (no risk of an unbounded hang). Of the 15, verified 3 already pass an explicit override (`ingestion/extractor.py` timeout=90.0, `reports/narrative.py`'s remediation call timeout=60.0, `agent/loop/function_calling.py`'s main step timeout=30.0). Of the remaining, fixed the two most report-relevant ones: `reports/narrative.py`'s Executive Summary (`generate_narrative`) and per-customer narrative (`generate_customer_narrative`) calls now explicitly pass timeout=60.0 (previously relying on chat_text's 30s default), matching the value already used for the remediation call in the same file -- these are the narrative calls repeatedly observed timing out against a slow/degraded LLM provider during manual testing. The other ~9 call sites (brand/document rule classifiers, exposure vuln matcher, CPE inferrer, sigma generator, playbook, weekly-report summary, summarize_customer, the ReAct loop and function-calling's forced-final-answer path) were left on their method defaults -- each already has a real timeout, just not spelled out per-call, and none of them were observed hitting it during this session's testing.

- [LOW] **B.1**: 2 file(s) with duplicate import statements
  Duplicate import statements clutter files.

- [LOW] **B.3**: renderer.py has 2 similar path builders
  `_output_paths` and `_customer_output_paths` share nearly identical logic (day-folder + timestamped filename). Could be unified with a prefix parameter.

- [LOW] **B.4**: 58 unused imports across codebase
  Dead imports increase cognitive load, no runtime impact.

- [LOW] **C.1**: load_config() uses lru_cache — YAML edits need a process restart
  Editing enrichment_config.yaml (e.g. provider weights) does not take effect until the Bot process restarts, since load_config() caches the parsed result for the life of the process.

- [RESOLVED] **E.1**: 76 bare/broad except clauses (no re-raise)
  Re-investigated with `ruff check --select BLE001`: 44 remained at start of this pass (some had already been narrowed/removed incidentally by earlier slice work). Split into two patterns: (1) ~15 sites that already return the error to the caller via `tool_error()`/return dict/Telegram reply -- not truly silent, just missing a server-side log line for operational visibility -- fixed by adding `logger.warning(...)` before the return, in `agent/tools/{action_enrich_ip,add_ioc,force_fetch_feed,ingest_article,rescan_finding,scan_brand_abuse,scan_censys,scan_document_leak}.py`, `enrichment_v2/adapters/{abuseipdb,leakix,otx,pulsedive,virustotal}.py`, and `telegram/commands/{download_report,generate_report}.py`; (2) ~5 sites that are genuine best-effort cleanup/optional-enrichment code where swallowing is the correct behavior (e.g. `except Exception: pass` when deleting a "thinking" placeholder message, or when a best-effort notify-on-error itself fails) -- left the logic unchanged, only added a one-line comment explaining why swallowing is intentional, in `telegram/audit.py`, `telegram/commands/{agent_handler,force_fetch}.py`, `fetchers/ioc/threatfox.py`, `match/domain_utils.py`. Verified: all touched files parse + import cleanly, and both bots ran a full restart with live fetcher/enrichment/LLM traffic and zero new tracebacks in `logs/bot1_stderr.log` / `logs/bot2_stderr.log`.

- [RESOLVED] **E.3**: 12 client file(s) without a @retry decorator
  Found 13 files calling httpx directly with no `@retry` (4 files in `external/*_client.py` already had it from earlier work). Centralized the fix at `fetchers/base.py`: added a shared `_retried_request()` (wraps `client.request()` with `tenacity.retry` on `httpx.RequestError`, 3 attempts, exponential backoff, reraise=True) plus `self._get()`/`self._post()` convenience methods on `IOCFetcher`, and switched all 6 subclasses (`fetchers/ioc/{threatfox,urlhaus,malwarebazaar,feodo}.py`, `fetchers/cve/{nvd,nvd_single}.py`) to call through them instead of `client.get/post` directly -- one fix, six fetchers covered. For the other 6 files, each call site wraps its own client creation inside a broad `except Exception`, so retry had to wrap the single HTTP call, not the whole `fetch()`: extracted a small `_get()`/`_post()` (or `_fetch_*`) helper per file in `enrichment_v2/adapters/{abuseipdb,leakix,otx,pulsedive,virustotal}.py`, `enrichment_v2/{epss_client,kev_client}.py`, `ingestion/fetcher.py`. `llm/client.py` got a tighter retry (2 attempts, short backoff, extracted `_post()` reused by `chat_json`/`chat_text`/`chat_with_tools`) since it sits inside the agent turn's overall timeout budget and must not itself risk compounding a slow-provider hang. Verified: all touched files import cleanly, and a full bot restart showed successful retried-through calls to abuseipdb/virustotal/otx/pulsedive/leakix/NVD/threatfox/urlhaus/malwarebazaar with no new errors.

- [LOW] **ReAct fallback leaks raw "Thought:" text as the final answer**
  `agent/loop/react.py:124-129`: when a step's LLM response has neither a
  parseable `Final Answer:` nor a valid `Action:`/`Action Input:` pair
  (e.g. the model's output was truncated mid-thought, observed during
  LLM provider degradation -- 429/500 errors -- that also triggers the
  ReAct fallback in the first place), the code falls through to
  `return raw.strip()[:2000], trace`, sending the raw text -- including
  a leading "Thought: ..." fragment -- to the analyst verbatim instead
  of a clean answer or a "please retry" message. Low severity (no data
  loss, cosmetic only, and rare -- requires both a function-calling
  failure that triggers ReAct AND a subsequent malformed ReAct
  response), but confusing when it does surface. Fix approach: strip a
  leading `Thought:.*?(?=\n|$)` line before returning at this fallback
  path, or route it through the same "agent gap loi" retry message used
  for exceptions instead of showing raw model output.

- [RESOLVED] **Manual test S4.4 / Slice 16A**: slash-command results were invisible to the agent's session history
  Originally: `SessionState.history` was only appended by `agent_handler.py` (free-text path); slash-commands never touched it, so temporal-anaphora references ("CVE moi ingest") to a `/confirm_ingest` result issued moments earlier couldn't resolve. Fixed in slice 16A via an *additive* design (not a `history` replacement, to avoid regressing `function_calling.py`'s message-building loop and the S3.3/S4.4 reference-resolution fixes that depend on it): a new `SessionState.command_log_recent` field (capped at 20 entries) populated by `register_command_tool_call()`, called explicitly from priority command handlers (`/confirm_ingest`, `/reject_ingest`, `/close`, `/mark_fp`, `/reopen`, `/acknowledge_indicator`, `/note_indicator`, `/generate_report`, `/add_customer`, `/add_asset`, `/add_ioc`) via `@log_command`. Persisted in a new `agent_sessions.command_log_recent` JSONB column (backed up before the manual `ALTER TABLE`, since the project has no Alembic/migration framework -- see `backups/`), using an update-in-place write path for command-log saves specifically (free-text's original append-only insert-per-turn behavior is unchanged). Injected into the agent's prompt via `render_context_prefix`. Verified end-to-end: `/ingest` -> `/confirm_ingest` -> "CVE moi ingest co match asset khong?" now resolves to the exact CVE IDs from the confirm step instead of a broad time-window query. Remaining commands outside the priority list (~30 of 41) still only get minimal tracking (command name, no tool-call detail) -- sufficient for read-only commands per the original design, but could be extended if a future test surfaces a gap there.

