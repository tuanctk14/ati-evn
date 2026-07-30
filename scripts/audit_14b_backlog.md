# ATI-EVN Audit Backlog (14B deferred issues)

Deferred to future work / thesis Limitations chapter.

- [LOW] **Slice 16B retest**: scan_brand_abuse (and likely scan_ghwarfare/scan_censys) can exceed the agent turn's 60s TIMEOUT_SECONDS
  Discovered while assessing Item 3/Problem-1: "Scan brand abuse cho Vietnam Electricity" via free-text timed out with no tool-call trace at all -- the LLM response + urlscan.io API call + up to 8 internal LLM classifier calls (per the scan itself) together exceeded `asyncio.wait_for(..., timeout=TIMEOUT_SECONDS)` in `agent/loop/runner.py`, which wraps the WHOLE turn, not just the tool call. Not an LLM provider outage (confirmed by testing an unrelated query immediately after, which succeeded in 6s) and not a Problem-1/scope bug -- a genuine slow-tool-vs-turn-timeout mismatch. User-suggested fix direction: run `scan_brand_abuse` (and similar external-scan tools) in the background and report back via Telegram once done, the same pattern `trigger_rescan_background` already uses for `/add_asset`. Deferred as an architectural change (background execution + async result delivery for agent-invoked tools) outside slice 16B's schema-clarity scope.

- [MEDIUM] **A.2**: 1 soft-deleted customer(s) with active findings/assets
  Soft-deleted customers still have OPEN/ACKED findings or live (non-deleted) assets. This data still surfaces in global reports/queries that don't filter by customer status.

- [MEDIUM] **E.2**: 15 LLM call site(s) without an explicit timeout wrap
  An LLM call that hangs can block the scheduler or agent loop. Note: the agent function-calling loop already passes timeout=30.0 into client.chat_with_tools directly at the call site (see agent/loop/fu

- [LOW] **B.1**: 2 file(s) with duplicate import statements
  Duplicate import statements clutter files.

- [LOW] **B.3**: renderer.py has 2 similar path builders
  `_output_paths` and `_customer_output_paths` share nearly identical logic (day-folder + timestamped filename). Could be unified with a prefix parameter.

- [LOW] **B.4**: 58 unused imports across codebase
  Dead imports increase cognitive load, no runtime impact.

- [LOW] **C.1**: load_config() uses lru_cache — YAML edits need a process restart
  Editing enrichment_config.yaml (e.g. provider weights) does not take effect until the Bot process restarts, since load_config() caches the parsed result for the life of the process.

- [LOW] **E.1**: 76 bare/broad except clauses (no re-raise)
  Silent exception swallowing risks hiding bugs -- this pattern was the root cause of several earlier silent-bug fixes in this project's fetcher code (see commit history: 'fix silent HTTP-error swallowi

- [LOW] **E.3**: 12 client file(s) without a @retry decorator
  External API clients should retry transient network errors.

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

