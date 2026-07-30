"""Session state management.

Structured state fields (all optional, updated by tool calls):
  last_customer_id, last_customer_name
  last_cve_id
  last_finding_id
  last_asset_id
  last_ioc_value, last_ioc_type
  last_result_ids       — list of finding_id from most recent list
  last_filters          — dict of filters last used

Conversation history: list of {role, content, timestamp} for LLM context.
Capped at 20 turns (10 user + 10 assistant) to bound token cost.

command_log_recent (slice 16A): list of {command_name, args_summary,
tool_calls, timestamp} for slash-commands issued in this session --
kept separate from `history` (which is free-text-only and feeds the
LLM `messages` list verbatim in agent/loop/function_calling.py) so
that adding slash-command visibility doesn't require touching the
message-building contract other code already depends on. Injected into
the prompt as text via entity_summary()-style rendering instead.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select

from ati_evn.db.models import AgentSession
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.agent.session")

SESSION_TTL_MINUTES = 30
HISTORY_MAX_TURNS = 20
COMMAND_LOG_MAX_ENTRIES = 20


@dataclass
class SessionState:
    """In-memory view of a session's state + history."""
    user_id: int
    state: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)
    command_log_recent: list[dict[str, Any]] = field(default_factory=list)
    # True once this state has been loaded from (or already saved as) an
    # existing DB row within the TTL window -- lets `save()` update that
    # row in place for slash-command-only saves instead of always
    # inserting a new one, since a command can run this loop many times
    # per minute (every one of 41 command handlers may call it) where a
    # free-text turn runs it once.
    _existing_row_id: int | None = None
    # Runtime-only (never persisted to AgentSession -- set fresh by
    # agent_handler.py on every free-text turn): lets long-running agent
    # tools (e.g. scan_brand_abuse) fire a background task and notify the
    # analyst via Telegram when done, the same pattern
    # rescan.trigger_rescan_background already uses for /add_asset,
    # instead of blocking the whole turn's TIMEOUT_SECONDS budget.
    _bot: Any = None
    _chat_id: int | None = None

    def update_entity(self, **kwargs) -> None:
        """Update structured entities. Example:
            s.update_entity(last_customer_name="NPC", last_cve_id="CVE-X")
        """
        for key, val in kwargs.items():
            if val is not None:
                self.state[key] = val

    def append_history(self, role: str, content: str) -> None:
        self.history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if len(self.history) > HISTORY_MAX_TURNS:
            self.history = self.history[-HISTORY_MAX_TURNS:]

    def append_command_log(
        self, command_name: str, args_summary: str,
        tool_calls: list[dict[str, Any]] | None = None,
    ) -> None:
        """Record a slash-command invocation for temporal-anaphora
        resolution ("CVE moi ingest", etc. -- see SYSTEM_PROMPT's
        TEMPORAL ANAPHORIC REFERENCES section). Oldest entry evicted
        once COMMAND_LOG_MAX_ENTRIES is exceeded."""
        self.command_log_recent.append({
            "command_name": command_name,
            "args_summary": (args_summary or "")[:200],
            "tool_calls": tool_calls or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if len(self.command_log_recent) > COMMAND_LOG_MAX_ENTRIES:
            self.command_log_recent = self.command_log_recent[-COMMAND_LOG_MAX_ENTRIES:]

    def command_log_summary(self, max_entries: int = 10) -> str:
        """Compact text for injecting recent slash-command actions into
        the agent's prompt (see render_context_prefix)."""
        recent = self.command_log_recent[-max_entries:]
        if not recent:
            return ""
        lines = []
        for entry in recent:
            ts = entry.get("timestamp", "")[11:19]  # HH:MM:SS
            line = f"[{ts}] /{entry['command_name']}"
            if entry.get("args_summary"):
                line += f" {entry['args_summary']}"
            for tc in entry.get("tool_calls") or []:
                out = tc.get("output_summary", "")[:150]
                line += f"\n    -> {tc.get('tool_name', '?')}: {out}"
                ids = tc.get("entity_ids") or []
                if ids:
                    line += f" (IDs: {ids})"
            lines.append(line)
        return "Recent slash-commands in this session:\n" + "\n".join(lines)

    def entity_summary(self) -> str:
        """Compact text for injecting into LLM system prompt as
        'you recently discussed:' context."""
        if not self.state:
            return ""
        parts = []
        if self.state.get("last_customer_name"):
            parts.append(f"customer={self.state['last_customer_name']}")
        if self.state.get("last_cve_id"):
            parts.append(f"CVE={self.state['last_cve_id']}")
        if self.state.get("last_finding_id"):
            parts.append(f"finding_id={self.state['last_finding_id']}")
        if self.state.get("last_asset_id"):
            parts.append(f"asset_id={self.state['last_asset_id']}")
        if self.state.get("last_ioc_value"):
            parts.append(f"IOC={self.state['last_ioc_value']}")
        return "Recent context: " + ", ".join(parts) if parts else ""


async def load_or_create(user_id: int) -> SessionState:
    """Load active session for user, or create new. Enforces TTL:
    if last session is expired, treat as new."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=SESSION_TTL_MINUTES)
    async with async_session() as session:
        row = await session.execute(
            select(AgentSession)
            .where(AgentSession.telegram_user_id == user_id,
                   AgentSession.last_active >= cutoff)
            .order_by(AgentSession.last_active.desc())
            .limit(1)
        )
        existing = row.scalar_one_or_none()
        if existing:
            return SessionState(
                user_id=user_id,
                state=dict(existing.state or {}),
                history=list(existing.conversation_history or []),
                command_log_recent=list(existing.command_log_recent or []),
                _existing_row_id=existing.id,
            )
        return SessionState(user_id=user_id)


async def save(state: SessionState, *, is_command_log_update: bool = False) -> None:
    """Persist state + history.

    Default (is_command_log_update=False, the free-text path's only
    call site in agent/loop/runner.py): UNCHANGED append-only insert,
    same as before slice 16A -- preserves the per-turn row history this
    path was already verified against during the manual test phase.

    is_command_log_update=True (slice 16A, used by @log_command):
    updates the most recent non-expired row in place instead of
    inserting. Slash-commands call save() far more often than free-text
    turns (every one of 41 command handlers, vs. once per agent turn),
    and always inserting would make agent_sessions grow unboundedly
    from command-log writes alone. Falls back to a normal insert if
    there's no existing row within the TTL window (state._existing_row_id
    unset, or that row has since expired/been superseded).
    """
    async with async_session() as session:
        if is_command_log_update and state._existing_row_id is not None:
            existing = await session.get(AgentSession, state._existing_row_id)
            if existing is not None:
                existing.state = dict(state.state)
                existing.command_log_recent = list(state.command_log_recent)
                existing.last_active = datetime.now(timezone.utc)
                await session.commit()
                return

        new_row = AgentSession(
            telegram_user_id=state.user_id,
            state=dict(state.state),
            conversation_history=list(state.history),
            command_log_recent=list(state.command_log_recent),
            last_active=datetime.now(timezone.utc),
        )
        session.add(new_row)
        await session.commit()
        state._existing_row_id = new_row.id


async def clear_for_user(user_id: int) -> int:
    """Delete all sessions for a user (e.g. /reset command later).
    Return count deleted."""
    async with async_session() as session:
        result = await session.execute(
            delete(AgentSession).where(
                AgentSession.telegram_user_id == user_id
            )
        )
        await session.commit()
        return result.rowcount or 0
