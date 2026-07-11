"""Create the ATI-EVN schema on the configured Postgres instance.

Idempotent: Base.metadata.create_all only creates tables that don't already
exist, so rerunning this script is a safe no-op.

Usage:
    docker compose up -d postgres
    python scripts/init_db.py
"""
from __future__ import annotations

import asyncio
import sys

from sqlalchemy import func, select, text

from ati_evn.db import Base, engine
from ati_evn.db.session import AsyncSessionLocal


async def main() -> int:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    table_names = sorted(Base.metadata.tables.keys())
    print(f"Created {len(table_names)} tables:")

    async with AsyncSessionLocal() as session:
        for name in table_names:
            table = Base.metadata.tables[name]
            result = await session.execute(select(func.count()).select_from(table))
            count = result.scalar_one()
            print(f"  {name:25s} rows={count}")

    await engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
