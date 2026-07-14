"""Bot 2 analyst command bot — standalone process."""
from __future__ import annotations

import asyncio
import sys

from ati_evn.telegram.bot_analyst import run_forever

if __name__ == "__main__":
    sys.exit(asyncio.run(run_forever()))
