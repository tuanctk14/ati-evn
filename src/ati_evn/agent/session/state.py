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


@dataclass
class SessionState:
    """In-memory view of a session's state + history."""
    user_id: int
    state: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)

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
            )
        return SessionState(user_id=user_id)


async def save(state: SessionState) -> None:
    """Persist state + history. Creates a new AgentSession row each
    time (append-only). Reads always take the freshest non-expired row."""
    async with async_session() as session:
        new_row = AgentSession(
            telegram_user_id=state.user_id,
            state=dict(state.state),
            conversation_history=list(state.history),
            last_active=datetime.now(timezone.utc),
        )
        session.add(new_row)
        await session.commit()


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
