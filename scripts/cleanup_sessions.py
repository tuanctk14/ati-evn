"""Manual cleanup — apscheduler will run this in Bot 2 process at 5B.3C.
Provided now for standalone verification.
"""
import asyncio
import sys

from ati_evn.agent.session.cleanup import cleanup_expired_sessions


async def main():
    n = await cleanup_expired_sessions()
    print(f"Cleaned up {n} expired agent_sessions")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
