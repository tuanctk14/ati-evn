"""Bot 1 alert dispatcher — standalone process, systemd-friendly."""
from __future__ import annotations

import asyncio
import sys

from ati_evn.telegram.bot_alert import run_forever

if __name__ == "__main__":
    sys.exit(asyncio.run(run_forever()))
