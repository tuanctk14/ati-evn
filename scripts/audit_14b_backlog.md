# ATI-EVN Audit Backlog (14B deferred issues)

Deferred to future work / thesis Limitations chapter.

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

