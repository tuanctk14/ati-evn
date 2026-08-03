# ATI-EVN Audit Backlog (14B deferred issues)

Deferred to future work / thesis Limitations chapter.

- [FIXED] **Thesis manual retest (follow-up on Nhóm 6)**: force_regen=True flip-flopped twice, plus two more chat_json() failure modes found via `/rule --regen`
  Follow-up after the previous `generate_sigma_rule` fix: user clarified "sinh Sigma rule" SHOULD map to
  force_regen=True (matching `/rule --regen`, not `/rule`'s default) -- the earlier revert went too far.
  Restored the force_regen=True-on-"sinh"/"tao" prompt rule, now correctly scoped as "look up" (tim/tra) ->
  force_regen=False vs "generate" (sinh/tao) -> force_regen=True, matching /rule vs /rule --regen exactly.

  While re-verifying via `/rule CVE-2025-68686 --regen` directly, hit two more `chat_json()` failure modes,
  neither covered by the existing empty-content retry (commit ac862af):
  (1) HTTP 400 `"Upstream request failed: [400] DFLASH speculative decoding does not support
  grammar-constrained decoding yet."` -- 9Router load-balances across backends and at least one ("DFLASH")
  rejects `response_format={"type":"json_object"}` outright instead of failing over transparently. Fixed by
  retrying once specifically on this signature (matching "grammar-constrained decoding" in the 400 body,
  not HTTP 400 in general -- a real bad request shouldn't be blindly retried) -- a retry typically lands on a
  different, compatible backend.
  (2) `JSONExtractError: Could not extract valid JSON from text` with content NOT empty this time --
  `completion_tokens` landed exactly on `max_tokens` (4096) with a partial JSON fragment (a string value cut
  off mid-word), which the existing `if not content` check didn't catch since content wasn't empty, just
  truncated. Found in `rules/sigma_generator.py`'s AI-rule-generation call (a 6th independent call site for
  this general truncation problem, after /playbook, generate_report, brand_rules, document_rules
  classifiers). Fixed by wrapping `extract_json_dict()` in try/except and retrying once with doubled
  `max_tokens` when parsing fails AND `completion_tokens >= max_tokens` (the truncation signature) --
  complements rather than replaces the empty-content retry, both share the same one-retry-only guard.

  Verified via CLI (`scripts/test_tool.py generate_sigma_rule --args='{"cve_id":"CVE-2025-68686",
  "force_regen":true}'`): completes successfully in 36.3s with `source: "ai_generated"`, a full Sigma YAML
  rule, and analyst notes -- no HTTP 400, no JSON truncation error.

- [FIXED] **Thesis manual retest (Nhóm 6)**: two issues found on "Sinh Sigma rule cho nó" continuing an entity-memory test chain
  (1) The agent resolved "nó" to the wrong CVE: the conversation's Nhóm 6 chain asked about 5 different
  topics (Fortinet, EVNNPC's worst CVE, cross-customer findings, GENCO1's asset, top IOC) before this
  question, and `session.state.last_cve_id` -- which only tracks a single most-recently-touched CVE, gets
  silently overwritten by every intervening question -- pointed at a CVE from question 2, not question 1's
  Fortinet/CVE-2025-68686 that "nó" was actually meant to continue. Not a code bug (session behaves exactly
  as designed, tracking one "last" value), but a real-world failure mode worth guarding against: added a
  prompt rule warning the model not to blindly trust `last_cve_id` when multiple different CVEs were
  mentioned recently, and to re-read its own conversation history to determine which one "nó" continues, or
  ask if genuinely ambiguous. (2) No agent tool existed to look up/generate a Sigma rule at all --
  `rules/orchestrator.py`'s `get_rule_for_cve()` (the same 3-tier logic `/rule` uses: direct CVE-tagged
  community rule -> ATT&CK-overlap community rule -> AI-generated) was only reachable via the `/rule`
  slash-command, so the agent incorrectly told the analyst "I have no tool to generate Sigma rules." Added
  `agent/tools/generate_sigma_rule.py` wrapping `get_rule_for_cve()` directly (read-only + LLM-compute, no DB
  writes -- registered non-destructive like `search_sigma_rules`). First attempt over-corrected: added a
  prompt rule making the model set `force_regen=True` whenever the analyst's Vietnamese phrasing used
  "sinh"/"tao" ("generate"/"create"), reasoning that word choice signaled wanting a fresh AI rule -- but
  live retest showed this made the tool's output diverge from `/rule`'s own default behavior (which never
  force-regens), producing a generic AI rule instead of the same well-matched community_behavioral rule
  `/rule` returns for ordinary requests. Reverted: default is `force_regen=False` always (matching `/rule`
  exactly), only set `force_regen=True` when the analyst explicitly says the existing/community rule isn't a
  good match and asks for a different one specifically. Verified live on Bot 2 (re-ran the full Nhóm 6
  question chain): "nó" now correctly resolves to CVE-2025-68686/Finding #222 (Fortinet, question 1's
  topic), and `generate_sigma_rule(cve_id=CVE-2025-68686)` now returns the exact same "Cisco Discovery"
  community_behavioral rule (confidence 0.5, same 4 alternates) as `/rule CVE-2025-68686`.

- [FIXED] **Thesis manual retest (Nhóm 5.3)**: no aggregate tool for "most common ATT&CK technique", agent has to sample-and-guess
  Found on "Kỹ thuật ATT&CK nào phổ biến nhất trong tháng?" -- the agent answered "T1190" based on manually
  inspecting 3 sample findings out of 199 total (it explicitly disclosed this limitation: "cần /export nếu
  muốn thống kê chính xác tuyệt đối"), but the real answer (confirmed via direct SQL in
  `test_reports/C9_report_generation.md`'s Nhóm test 9 data) is **T1203 (35 occurrences)**, not T1190 (30
  occurrences, actually 5th place) -- the agent's sampled-based guess was simply wrong because no tool exists
  to compute a true technique-frequency aggregate across all findings. `search_findings`/`get_finding_detail`
  return technique IDs per-finding but there's no `search_findings`-adjacent tool that GROUPs/COUNTs
  technique occurrences server-side; the agent's only options are pulling individual findings and reasoning
  over a small sample (as it did here), or `generate_report`, which DOES compute this aggregate correctly
  internally (see `C9_report_generation.md`'s "Top 5 ATT&CK techniques" section) but wasn't the tool the
  agent reached for on this particular phrasing. Fixed by adding a new tool, `agent/tools/top_attack_techniques.py`
  (`top_attack_techniques(since_days=30, customer=None, limit=5)`), reusing the exact same
  `jsonb_array_elements`-based SQL `telegram/commands/export.py`'s weekly-report generator already relies on
  for its "Top 5 ATT&CK techniques" section -- same aggregation logic, exposed as a directly-callable,
  customer-filterable tool instead of only living inside report generation. Also added a tool-selection
  heuristic rule steering "kỹ thuật nào phổ biến nhất / most common technique" questions toward this new
  tool instead of ad-hoc `get_finding_detail` sampling, with the T1190-vs-T1203 mistake cited as the
  concrete example of why sampling is unreliable. Verified via CLI: `top_attack_techniques(since_days=30)`
  returns T1190=72, T1078=51, T1203=46, T1055=45, T1548=41 (consistent with `generate_report`'s own
  30-day aggregate), and the customer filter (`customer="EVNHANOI"`) correctly narrows the count.

- [FIXED, prompt-layer] **Thesis manual retest (Nhóm 5.3)**: "Chiến dịch tấn công nào phát hiện trong tuần này?" incorrectly answered "không có campaign nào" when 2 confirmed campaigns existed
  Found via Bot 2 Telegram: the agent called `search_campaigns(since_days=7)` (no `status` arg), got 0
  results, and concluded no campaigns existed in the last 7 days -- but `agent/tools/search_campaigns.py`
  defaults `status: str = "candidate"` when omitted (matching its own JSON schema description, "Default:
  candidate" -- not a code bug, working as documented), so the call silently only searched
  pending-review campaigns. Reproduced via `scripts/test_agent.py`: calling
  `search_campaigns(since_days=7, status="confirmed")` explicitly returns 2 real campaigns (#10, #11, both
  confirmed with 3 HIGH findings each) that the analyst-facing answer had completely missed. This is a
  materially wrong answer for a SOC tool -- "no attack campaign" when 2 confirmed ones exist is the kind of
  false negative that matters. Root cause is an LLM tool-usage gap (not realizing a general "any campaign"
  question needs multiple status values queried), so fixed at the prompt layer per the project's
  established pattern: added an explicit rule to the "Tool selection heuristics" section telling the model
  that a general campaign question (no explicit "pending"/"chưa duyệt" wording) must query at least
  `status="candidate"` AND `status="confirmed"` and merge results, not rely on the single default call.
  Verified via `scripts/test_agent.py` (reproduces the exact failure) that explicit multi-status calls
  surface the real campaigns; live Bot 2 re-verification pending (needs bot restart to pick up the prompt
  change).

- [FIXED] **Thesis manual retest (Nhóm 5.2)**: LLM hallucinated a plausible-but-nonexistent `is_internet_facing` filter param on `search_asset`
  Found on "Có tài sản nào của EVNNPC bị lộ ra Internet không?" -- the agent correctly reasoned it needed an
  internet-facing filter and guessed the parameter name `is_internet_facing` (matching the real
  `CustomerAsset.is_internet_facing` DB column, which the tool already returns in its output), but that
  parameter didn't exist in `search_asset`'s schema. The tool call failed
  (`search_asset() got an unexpected keyword argument 'is_internet_facing'`), and the agent recovered
  gracefully by re-calling without the filter and reasoning over the unfiltered results itself -- the final
  answer was still correct, just via 3 tool calls (1 failed) instead of 1. Since the field already exists on
  the model and is already exposed read-only in the tool's output, added it as a real filter parameter
  instead of just accepting the graceful-recovery path: `search_asset` now accepts an optional
  `is_internet_facing: bool` and applies it as a WHERE clause. Verified: same question via Bot 2 now
  completes in 1 tool call (6.8s, down from 21.6s/3 calls), same correct 4-asset result.

- [FIXED] **Thesis manual retest (Nhóm 5.1)**: function-calling loop didn't round-trip `reasoning_content`, breaking every subsequent LLM call once the provider entered "thinking mode"
  Found on "Tổng hợp Finding theo đơn vị trong tháng này" via Bot 2 Telegram: the turn's function-calling
  attempt failed with `HTTP 400: "The reasoning_content in the thinking mode must be passed back to the
  API"`, which then exhausted the ReAct fallback's 60s timeout too, ending in the generic
  "Agent không tạo được câu trả lời hợp lệ" message. Root cause: `agent/loop/function_calling.py`'s
  assistant-message-history builder only copied `content`/`tool_calls` from the model's response into the
  next turn's message history -- when the provider (9Router/DeepSeek) runs a step in "thinking mode" it
  includes a `reasoning_content` field in that response, and (per the error text) requires it to be echoed
  back verbatim in the next request's message history, not treated as optional/informational metadata. Since
  the code silently dropped it, the very next `chat_with_tools()` call in the same turn was rejected outright
  by the provider. Fixed by capturing `msg.get("reasoning_content")` and including it in the assistant
  message appended to history whenever present. Verified: re-ran the exact question that triggered this via
  `scripts/test_agent.py` -- completed successfully (7 tool calls, token cap correctly triggered and handled,
  full substantive answer) with no HTTP 400. Note: since "thinking mode" appears to be provider-side and not
  directly controllable, this fix addresses the confirmed root cause but can't be proven to eliminate every
  future occurrence -- worth re-checking if a similar 400 resurfaces.

- [FIXED] **Thesis test data collection**: `LLMClient.chat_json()` could return fully empty `content` when the completion was cut off, observed independently at 4 call sites
  Found repeatedly while collecting Chương 3 test data: `/playbook` (`JSONExtractError: Could not extract
  valid JSON from text: ''`), `generate_report`'s Executive Summary (same error, log showed
  `completion_tokens` landing exactly on `max_tokens`), and both `brand_rules`/`document_rules` LLM
  classifiers during `scan_brand_abuse`/`scan_document_leak` (`test_reports/D2_external_monitoring.md`).
  Same root cause each time: the provider (9Router) sometimes returns `content=""` in JSON mode instead of a
  truncated-but-present string when generation is cut off mid-structure -- previously `chat_json()` passed
  this straight to `extract_json_dict("")`, which always fails (no JSON to extract from an empty string), so
  every one of the 4 callers had to build its own ad-hoc fallback (raise, log-and-skip, or show
  "(LLM summary lỗi: ...)" inline). Fixed at the shared root instead of patching each caller separately:
  `chat_json()` now detects empty `content` and retries ONCE with `max_tokens` doubled (capped at 16000),
  via a new keyword-only `_retry_on_empty` flag that prevents the retry itself from looping. All 4 callers
  get the fix for free with no code changes on their side. Verified: re-running `generate_report` (the
  clearest repro) now produces a full multi-paragraph Executive Summary instead of the
  "(LLM summary lỗi: ...)" fallback text, in 19.4s (faster than the prior failing run).

- [FIXED] **Thesis test data collection (Nhóm test 10)**: `_force_final_answer()` could itself return empty content, same failure class as the earlier empty-answer fix but at a different call site
  Found running a deliberately over-broad question ("mọi Finding của mọi đơn vị EVN... cho mỗi Finding
  ATT&CK, Sigma rule, playbook và IP làm giàu") via `scripts/test_agent.py` to test the token-cap limit for
  Chương 3 test data. `agent/loop/function_calling.py`'s token-cap path correctly triggered
  `_force_final_answer()`, but that helper's own forced-final-answer LLM call could ALSO come back with empty
  `content` (no completion, or cut off) -- and unlike the main loop's `if not tool_calls:` branch (fixed
  earlier this session, commit 0170763), `_force_final_answer()` had no empty-content guard of its own, so
  both of its callers (token-cap path and max_steps path) would pass an empty string straight through to the
  analyst as a blank Telegram message. Fixed by adding the same guard directly inside
  `_force_final_answer()`: when its own forced-answer call returns empty/whitespace-only content, return an
  explicit Vietnamese fallback message ("câu hỏi này cần quá nhiều bước... vui lòng chia nhỏ câu hỏi") instead
  of the blank string, covering both call sites in one fix. Verified: re-running the exact question that
  triggered this now returns a substantive answer (partial Finding list + explicit note about the scope
  limitation) instead of an empty one.

- [FIXED] **Post-backlog manual retest (Phase 2)**: legacy_finding_postfilter's rewrite text read as raw system syntax embedded mid-sentence
  Found on "Trong danh sách trên, indicator nào chưa acknowledge?" -- Finding #29 and ThreatIndicator #29
  happen to share the same numeric id (independent auto-increment sequences per the slice 15A split), and the
  LLM suggested `/acknowledge_indicator 29 --note=...` for what was actually Finding #29 (a CVE test-campaign
  row, not a ThreatIndicator). `agent/loop/legacy_finding_postfilter.py`'s Direction-2 guard correctly
  detected and blocked the invalid suggestion (this defense-in-depth mechanism worked as designed -- the
  real backend guard in `acknowledge_indicator`'s own lookup would have rejected it anyway), but the
  replacement text it substituted in --
  `[/acknowledge_indicator không áp dụng cho Finding #29 -- đây là CVE finding, dùng /close hoặc /mark_fp thay thế]`
  -- is bracketed pseudo-syntax, not a sentence, and got embedded inline mid-answer next to the "Gợi ý:" line,
  reading as a raw system note leaking into analyst-facing text rather than a warning phrased for a human.
  Fixed by rewriting `_replace_ti_cmd()`'s return string into plain Vietnamese prose: "#{fid} là Finding
  (CVE), không phải Threat Indicator, nên /{cmd} không áp dụng -- dùng /close hoặc /mark_fp {fid} thay thế" --
  same information, reads as a sentence when inlined. Left the detection/blocking logic and Direction-1
  rewrite (Finding -> real ThreatIndicator id via `migrated_to_ti_id`) unchanged -- those already worked
  correctly. Chose the text-only fix over adding a system-prompt rule (user's explicit choice when asked) --
  postfilter remains the safety net regardless of whether the LLM learns to avoid the wrong suggestion.

  Follow-up found on the same retest: the `[legacy-finding postfilter: ...]` trace line shown to the analyst
  after this fix was itself buggy in two ways. (1) `agent_handler.py` unconditionally formatted every entry
  in `legacy_stats["rewritten"]` as `{orig}->/acknowledge_indicator {tid}`, but that list was shared between
  Direction 1 (a real rewrite TO `/acknowledge_indicator {ti_id}`) and Direction 2 (a BLOCK, no rewrite
  target -- `tid` was actually just the original Finding id), so a Direction-2 block rendered in the trace as
  if the postfilter had rewritten the suggestion to `/acknowledge_indicator 29` -- the exact command it had
  just blocked. (2) the regex `_TI_CMD_RE` matches `(?:\s+\S.*)?` (the rest of the line) so `m.group(0)` used
  as the "orig" text included the LLM's entire trailing sentence, making the trace line very long. Fixed:
  `postfilter_legacy_finding_actions()` now returns two separate lists, `rewritten` (Direction 1) and
  `blocked` (Direction 2), and both `_replace_finding_cmd`/`_replace_ti_cmd` build their `orig` string from
  just `/{cmd} {fid}` (the actual matched command) instead of the full regex match. `agent_handler.py` now
  renders each list with its own correctly-labeled trace line ("... rewrote: ..." vs "... blocked: ...").
  Verified with a unit test (mocked DB) that `blocked` now holds `("/acknowledge_indicator 29", 29)` -- a
  short, correctly-scoped original command string, not the whole trailing sentence.

- [FIXED, prompt-layer] **Post-backlog manual retest (Phase 2)**: confirmed=True loop -- agent re-showed PENDING_CONFIRMATION instead of executing after analyst confirmed in a NEW turn
  Found on "Ingest văn bản ... CVE-2026-88888": after the analyst confirmed a `ingest_article` PENDING_CONFIRMATION
  and the tool correctly rejected a mismatched confirmed=True call in that same turn (existing, working safety
  net -- see "no matching prior PENDING_CONFIRMATION" handling in `agent/tools/_action_base.py`), the analyst
  replied "Xác nhận" again in a brand-new message. Instead of re-calling `ingest_article(..., confirmed=True)`
  to actually execute, the LLM called it again WITHOUT confirmed=True, re-creating a fresh PENDING_CONFIRMATION
  and asking the analyst to confirm the same thing a second time -- a loop that would never progress if the
  analyst kept saying "xác nhận" the same way. The backend confirmation registry itself was not at fault (this
  is the same NLU/reasoning gap class documented under the project's "layer selection principle": the model
  correctly avoided retrying automatically within the SAME turn per an earlier prompt rule, but didn't
  generalize that "analyst confirming across turn boundaries" still means "re-call with confirmed=True", not
  "re-show the summary"). Fixed at the prompt layer (system prompt's "CRITICAL RULES for action tools"
  section) with an explicit rule: when the analyst's current message is itself a confirmation and a prior turn
  already showed PENDING_CONFIRMATION for a specific tool, this turn must re-call that tool WITH
  confirmed=True, not without it. Chose prompt over code here because "which of several possible pending
  actions across turns does 'xác nhận' refer to" is a reference-resolution/reasoning task, matching this
  project's established pattern of using prompt fixes for NLU tasks and code fixes for hard behavioral
  discipline (e.g. the empty-answer and command-hallucination postfilters). Verified live on Bot 2 after
  restart: a fresh ingest_article request -> "Xác nhận" now completes in exactly one confirm round-trip (tool
  called with confirmed=True on the very next turn, ingestion session created), no repeated
  PENDING_CONFIRMATION loop. Unlike the nested-bullet case earlier this session, the prompt-only fix held
  here -- if a future regression surfaces (loop reappears), fall back to a code-layer signal: e.g. gate the
  SessionState command_log/entity summary to explicitly surface "there is 1 pending confirmation for tool X"
  when one exists, so the model has a harder-to-miss structured signal instead of inferring it from prose
  history.

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

- [FIXED] **Post-backlog manual retest**: `/playbook <CVE-ID>` can fail with "Could not extract valid JSON from text"
  Found during the post-E.1/E.3 manual retest (2026-07-31), NOT a regression from those changes --
  `telegram/commands/playbook.py`'s `_get_or_generate()` calls `LLMClient.chat_json(..., max_tokens=4096)`
  asking for a full NIST 800-61 playbook (5 sections, Vietnamese narrative + commands) as a JSON string value.
  For a CVE with rich context (e.g. CVE-2026-47295 on a SQL Server asset), the model's `markdown` field can
  get truncated mid-sentence before the closing `"}/` of the JSON object, so all 3 tiers of
  `llm/json_extract.py`'s `_extract_json_any()` fail (direct parse, fence-strip, brace-balance) since the
  JSON itself is incomplete -- not a formatting slip the fallback tiers can recover from. Pre-existing issue,
  unrelated to `chat_json`'s retry/logging changes in this session. First attempt: raised `max_tokens` from
  4096 to 6144 -- retested with CVE-2026-47295 (the original repro, no cache present) and it STILL failed,
  this time with `text: ''` (completely empty content, `completion_tokens=6144` exactly on the cap) instead
  of a truncated-but-present JSON string -- the 9Router provider apparently returns empty `content` rather
  than partial text when JSON-mode generation is cut off mid-structure. Root cause was the prompt asking for
  too much content (5 sections x 3-5 detailed action items with commands), not just an undersized budget.
  Fixed by also tightening `PLAYBOOK_SYSTEM`: reduced each section to 2-4 concise action items, added an
  explicit ~1800-word total budget across all 5 sections, and reframed it as "a quick-reference playbook for
  an analyst mid-incident, not an exhaustive runbook." Verified live on Bot 2 with a fresh (uncached)
  CVE-2026-47295 generation: completed successfully, all 5 sections present with concrete Vietnamese content
  + SQL/command snippets.

  Follow-up found on the same retest: the generated playbook is sent via `message.answer(f"{header}\n\n
  {markdown}")` with no `parse_mode` and no sanitization, so the LLM's `## 1. Identification` headings
  rendered as literal `##` characters in Telegram -- the same class of bug fixed for the free-text agent
  path earlier this session, but `playbook.py`'s inline-send path never got wired to
  `sanitize_telegram_markdown()`. Fixed: the inline-message branch (< 3500 chars) now runs the markdown
  through `sanitize_telegram_markdown()` and sends with `parse_mode="Markdown"` (falling back to plain text
  on `TelegramBadRequest`, same pattern as `agent_handler.py`'s `_send_markdown`) -- the `.md` file-download
  branch (>= 3500 chars) is deliberately left un-sanitized, since a real Markdown reader opening that file
  should see the original `##` headings, not the Telegram-safe rewrite. Verified live: headings now render
  as `*bold*` section labels instead of literal `##`. Known minor side effect: the same snake_case-underscore
  fix from earlier this session (which turns `risk_score` into `risk score` so Telegram doesn't mangle it)
  also touches SQL/command identifiers embedded in playbook text (e.g. `xp_cmdshell` -> `xp cmdshell`,
  `create_date` -> `create date`) -- an accepted tradeoff for readable prose, and the untouched `.md` file
  download remains the source of truth for copy-pasting exact commands.

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

- [RESOLVED] **B.1**: 2 file(s) with duplicate import statements
  `external/censys_client.py`: `import asyncio` was repeated as a local import inside both `search_ip()` and
  `search_cidr()` instead of once at module top-level -- no circular-import reason for the local scoping,
  purely redundant. `telegram/commands/query.py`: `from ati_evn.telegram.formatter.common import fmt_dt` was
  similarly repeated as a local import inside two different handler functions (the stats and alert-list
  commands). Neither module has any risk of a circular import with the other (verified: both import cleanly
  after hoisting). Hoisted both to their file's top-level import block, removed the two duplicate local
  imports in each file. Verified: both files parse and import cleanly.

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

- [RESOLVED] **ReAct fallback leaks raw "Thought:" text as the final answer**
  `agent/loop/react.py`: when a step's LLM response has neither a parseable `Final Answer:` nor a valid
  `Action:`/`Action Input:` pair (e.g. truncated mid-thought during LLM provider degradation, which is also
  what triggers the ReAct fallback in the first place), the code used to fall through to
  `return raw.strip()[:2000], trace`, sending the raw text -- including a leading "Thought: ..." fragment --
  to the analyst verbatim. Fixed with `_THOUGHT_PREFIX_RE` + `_clean_malformed_response()`: strips a leading
  `Thought:...` line and falls back to an explicit "⚠️ Agent không tạo được câu trả lời hợp lệ..." retry
  notice if nothing meaningful remains after stripping, used at both fallback sites (token-cap-reached path
  and no-action-found path). Confirmed present and correctly wired in the current codebase (this fix had
  already landed earlier in this session but the backlog entry was never updated to reflect it).

- [RESOLVED] **Manual test S4.4 / Slice 16A**: slash-command results were invisible to the agent's session history
  Originally: `SessionState.history` was only appended by `agent_handler.py` (free-text path); slash-commands never touched it, so temporal-anaphora references ("CVE moi ingest") to a `/confirm_ingest` result issued moments earlier couldn't resolve. Fixed in slice 16A via an *additive* design (not a `history` replacement, to avoid regressing `function_calling.py`'s message-building loop and the S3.3/S4.4 reference-resolution fixes that depend on it): a new `SessionState.command_log_recent` field (capped at 20 entries) populated by `register_command_tool_call()`, called explicitly from priority command handlers (`/confirm_ingest`, `/reject_ingest`, `/close`, `/mark_fp`, `/reopen`, `/acknowledge_indicator`, `/note_indicator`, `/generate_report`, `/add_customer`, `/add_asset`, `/add_ioc`) via `@log_command`. Persisted in a new `agent_sessions.command_log_recent` JSONB column (backed up before the manual `ALTER TABLE`, since the project has no Alembic/migration framework -- see `backups/`), using an update-in-place write path for command-log saves specifically (free-text's original append-only insert-per-turn behavior is unchanged). Injected into the agent's prompt via `render_context_prefix`. Verified end-to-end: `/ingest` -> `/confirm_ingest` -> "CVE moi ingest co match asset khong?" now resolves to the exact CVE IDs from the confirm step instead of a broad time-window query. Remaining commands outside the priority list (~30 of 41) still only get minimal tracking (command name, no tool-call detail) -- sufficient for read-only commands per the original design, but could be extended if a future test surfaces a gap there.

