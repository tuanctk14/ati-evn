# Slice 16A audit report — spec vs. reality (Phase 0, per spec's "STOP and report" clause)

Per the spec's instruction ("If Phase 0 audit reveals command handler
pattern varies wildly... STOP and report"), this documents 4 places
where the spec's assumptions diverge from the actual codebase, before
any Phase 1+ code is written.

## T0 — Command handler audit (spec step 1)

```
grep -l "log_command" src/ati_evn/telegram/commands/*.py | wc -l
```
Result: **41** (of 43 files; the 2 without it are `__init__.py` and
`agent_handler.py`, which is expected — `agent_handler.py` is the
free-text path, not a slash-command).

This part of the spec's assumption holds — coverage is consistent
(41/41 real command files use `@log_command`).

## Drift 1 — SessionState is DB-persisted, append-only, not in-memory

Spec's Non-goals says: *"No schema change to existing DB (session
state in-memory)."* This is incorrect for the current system.

`src/ati_evn/agent/session/state.py`:
- `load_or_create(user_id)` reads the most recent non-expired
  `AgentSession` row (30-min TTL) from the DB.
- `save(state)` **inserts a new `AgentSession` row every call**
  (append-only, not an update) — `conversation_history` (JSON) and
  `state` (JSON) are the two persisted fields.

Implication: if `register_command_tool_call` + an equivalent `save()`
call were added after all 41 command handlers as the spec proposes,
every slash-command invocation would insert a new `AgentSession` row.
At current usage patterns (dozens of commands per test session) this
is a meaningful, unbounded row-count increase with no documented
retention/cleanup for `AgentSession` beyond the 30-min TTL used at
*read* time (old rows are never deleted, just ignored once expired).

## Drift 2 — no `agent/session/history.py` file exists

Spec's "Read first" list cites `src/ati_evn/agent/session/history.py`
as an *existing* file with an *existing* `append_history` to extend.
Neither exists. `append_history(role, content)` is a **method on the
`SessionState` dataclass itself** (`state.py:48`), not a free function
in a separate module, and there is no module-level session registry
(`_sessions: dict[str, SessionState]`) as the spec's `T2` snippet
assumes — sessions are loaded/saved per-call via DB round-trips
(`load_or_create` / `save`), not held in a process-lifetime dict.

## Drift 3 — `@log_command` cannot currently capture response text

The spec's `T3` assumes `@log_command` already reads the command's
final response, and proposes monkey-patching `message.answer`/
`message.reply` to add capture. Investigating why that patch is
needed reveals a more fundamental problem: the *current*
`log_command` decorator (`telegram/audit.py:27-28`) reads
`result.get("summary")` **only if the wrapped handler returns a
dict** — but:

```
grep -c "return {" src/ati_evn/telegram/commands/*.py | grep -v ":0"
```
Result: only **2 of 41** files (`export.py`, `playbook.py`) ever
`return {...}`. Every other command handler (including every one
tested manually this session — `/close`, `/confirm_ingest`,
`/acknowledge_indicator`, etc.) ends with `await message.answer(text)`
and returns `None` implicitly. So `command_log.result_summary` is
already `None` for ~95% of commands today, and the spec's proposed
monkey-patch is the right *direction* (capture at the `message.answer`
call site) but the `T3` code sample (a `captured_responses` list
alongside separately-wrapped `capture_answer`/`capture_reply`
closures) does not match how aiogram's per-message `Message` object
is used elsewhere in the codebase and needs to be re-verified against
a real handler's control flow (e.g. handlers that call
`message.answer` more than once, as several telegram/commands/*.py
files do for multi-part responses) before committing to that pattern.

## Drift 4 — history format change breaks `function_calling.py`, with concrete regression risk

`agent/loop/function_calling.py:43-44`:
```python
for h in session_state.history[-10:]:
    messages.append({"role": h["role"], "content": h["content"]})
```
This does dict-key access (`h["role"]`, `h["content"]`) on each
history entry to build the OpenAI-format `messages` list sent to the
LLM every turn. The spec's `T1` replaces `history: list[dict]` with
`history: deque[InteractionTurn]` (a plain object, no `__getitem__`).
**This line would raise `TypeError` on the very next free-text turn**
after the change, since `InteractionTurn` has no dict-style indexing
implemented in the spec's sample code.

Cross-checked against the two most safety-relevant fixes from this
session's manual test phase to see if they're at risk:

- **N.2 (confirmation-recovery on terse "OK")**: lives entirely in
  `agent/tools/_action_base.py`'s `_pending_confirmations` module-level
  dict, keyed by `(session_id, tool_name, args_hash)`. This is
  **independent of `SessionState.history`** — no regression risk from
  this slice.
- **S3.3/S4.4 (discourse & temporal reference resolution)**: this
  *does* depend on both `SessionState.entity_summary()` (a `state`
  dict summary, separate from `history`) **and** the raw
  `messages` list built from `history` (the LLM re-reads its own
  prior turns verbatim to resolve "customer đó" per the SYSTEM_PROMPT
  rule added for S3.3). Changing `history`'s shape without also
  updating `function_calling.py`'s message-building loop would silently
  drop all free-text conversation context (or crash outright, per the
  above), regressing S3.3/S4.4's reference resolution behavior that
  was just fixed and verified this session.

## Recommendation

The spec's Phase 3 (`T5`/`T6`) already implicitly acknowledges
`function_calling.py` needs updating ("Update ... to use new API") but
the provided sample doesn't show the message-building loop being
migrated, and Phase 4's acceptance criteria (`step 10`, regression
smoke test) would only catch a crash, not a silent context-loss
regression in reference resolution specifically.

Given: (a) the persistence-cost implication of Drift 1 is undocumented
and unbounded, (b) Drift 3 means the response-capture mechanism needs
to be re-derived rather than lifted from the spec's sample, and (c)
Drift 4 has a concrete, verified regression path through this
session's just-fixed S3.3/S4.4 behavior — proceeding with the spec's
Phase 1-3 as literally written is not safe. A revised design should:

1. Keep `SessionState.history` in its current `list[dict[role,
   content]]` shape for the free-text/LLM-message path, and add the
   structured `InteractionTurn` data as a **separate field**
   (e.g. `SessionState.command_log: list[dict]`) rather than replacing
   `history` outright -- avoids touching `function_calling.py`'s
   message-building loop at all.
2. Feed `command_log` into the agent via `render_context_prefix` /
   `entity_summary()`-style text injection (already how session
   context reaches the prompt today), not by mixing it into the
   `messages` list sent to the LLM API.
3. Address the `save()` row-growth question explicitly (e.g. update
   the existing `AgentSession` row within the same TTL window instead
   of always inserting) before adding 41 new write call sites.
4. Re-derive the response-capture approach against a handler that
   calls `message.answer` multiple times, to confirm the monkey-patch
   captures all of them correctly.

Awaiting user confirmation on this revised approach before writing any
Phase 1+ code.
