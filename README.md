# ATI-EVN — Agentic Threat Intelligence for EVN

Backend-only CTI system for EVN corporate + subsidiaries. Auto-fetches IOC + CVE
intel, matches against EVN asset inventory (IT + SCADA/ICS), delivers alerts and
agentic analyst chat via Telegram.

## Status

**Slice 1 (current)** — foundation:
- Project skeleton
- Config (pydantic-settings)
- DB schema (8 tables)
- Fetcher abstract + `RawIOC` contract
- ThreatFox fetcher (with the abuse.ch `Auth-Key` fix)
- Smoke test
- **Severity scoring engine** — ported from CyberGuard, 8/8 benchmark accuracy
  against real incidents (Log4Shell, EternalBlue, Heartbleed, Struts/Equifax,
  PrintNightmare, etc.). See `tests/smoke/test_severity_benchmark.py`.
- **MITRE ATT&CK Enterprise dataset** (697 techniques, ~884KB) with lookup +
  keyword search + sub-technique fallback. See
  `src/ati_evn/fetchers/attribution/mitre.py`.

Next slices: more fetchers → ingest pipeline → match engine → LLM CPE inference
→ Telegram bot → agentic chat.

## Setup

```bash
git clone <this-repo> ati-evn
cd ati-evn
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
# Fill in .env if any values missing
```

## Smoke-test the ThreatFox fetcher

Verifies your `ABUSE_CH_AUTH_KEY` is valid and abuse.ch is reachable. No DB required.

```bash
python scripts/smoke_threatfox.py
```

Expected: prints ~500–5000 IOCs from the last 24 hours, grouped by type/severity/malware family.

## Verify the severity scorer

Runs the risk-scoring engine against 8 real-world incidents. Fast, offline, no keys required.

```bash
python tests/smoke/test_severity_benchmark.py
```

Expected: `8/8 (100% accuracy)`.

## Layout

See top-level directory tree. Backend-only, no dashboard. Telegram is the sole analyst interface.
