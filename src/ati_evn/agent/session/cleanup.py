"""TTL cleanup — remove expired agent_sessions rows.

Runs on apscheduler tick from Bot 2 process (registered in 5B.3C).
Standalone-runnable via scripts/cleanup_sessions.py.
"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from ati_evn.agent.session.state import SESSION_TTL_MINUTES
from ati_evn.db.models import AgentSession
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.agent.cleanup")


async def cleanup_expired_sessions() -> int:
    """Delete rows where last_active < now - TTL. Return count."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=SESSION_TTL_MINUTES)
    async with async_session() as session:
        result = await session.execute(
            delete(AgentSession).where(AgentSession.last_active < cutoff)
        )
        await session.commit()
        n = result.rowcount or 0
        if n:
            logger.info("Cleaned up %d expired agent_sessions", n)
        return n
