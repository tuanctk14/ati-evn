# ATI-EVN — Agentic Threat Intelligence for EVN

Threat intelligence platform for Vietnam Electricity (EVN) and its 13
subsidiaries (GENCOs, Power Corporations, NPT). Auto-fetches CVE/IOC
intel from public feeds, matches findings against EVN's asset
inventory (IT + SCADA/ICS), scans for external exposure (brand abuse,
document leaks, open services), and gives analysts two ways in:
automated Telegram alerts and a free-text AI agent for ad-hoc
investigation — all through Telegram, no separate dashboard.

## Architecture

Two Telegram bots share one PostgreSQL database:

- **Bot 1 — Alert dispatcher** (`scripts/run_alert_bot.py`): polls the
  alert queue every 5s and pushes new/batched alerts to the team chat.
  No analyst interaction — one-way notification.
- **Bot 2 — Analyst command bot** (`scripts/run_analyst_bot.py`): the
  main interface. ~40 slash-commands for querying and acting on
  findings/assets/customers/campaigns/indicators, plus a free-text
  mode where an LLM agent (function-calling with a ReAct fallback)
  picks tools, asks for confirmation before anything destructive, and
  answers in Vietnamese. Also runs the fetcher scheduler, weekly scan
  jobs, and campaign/backfill background jobs via APScheduler.

Behind them:

- **Fetchers** (`fetchers/`) — NVD, ThreatFox, MalwareBazaar, URLhaus,
  Feodo Tracker. Each retries transient network errors and reports via
  `FeedRunHistory`.
- **Ingest + match pipeline** (`ingest/`, `match/`) — normalizes raw
  IOCs, matches them against `CustomerAsset` records (CPE-aware for
  CVEs), creates `Finding` rows, and routes qualifying ones to the
  alert queue.
- **Post-slice-15A entity split**: `Finding` is CVE-only (full
  lifecycle: close/mark_fp/reopen/silence). Everything else — raw IOC,
  brand abuse, exposed documents, exposure rule matches — is a
  `ThreatIndicator` (read-only + acknowledge/note, no close/reopen).
- **External monitoring** (`external/`) — Censys (open services),
  GrayHatWarfare (exposed documents in public buckets), urlscan.io
  (brand abuse / typosquat / phishing), each behind a 3-stage pipeline
  (rule engine → optional typosquat/whitelist check → LLM relevance
  classifier) and weekly-scheduled.
- **IP/domain enrichment** (`enrichment_v2/`) — 5-provider aggregate
  (AbuseIPDB, VirusTotal, OTX, Pulsedive, LeakIX) with a scoring engine
  that computes risk/confidence/coverage and provider consensus;
  backfills automatically every 15 minutes.
- **Reports** (`reports/`) — CyRadar-style HTML+PDF global/customer
  reports (Jinja2 + wkhtmltopdf), with an LLM-generated executive
  summary and remediation section.
- **Rules/enrichment content** (`rules/`, `brand_rules/`,
  `document_rules/`, `exposure_rules/`) — Sigma rule matching/
  generation, NIST 800-61 incident-response playbooks, and the
  classifier rule engines behind the external-monitoring pipelines.
- **Campaign detection** (`campaigns/`) — clusters related findings
  into candidate attack campaigns for analyst confirm/reject.

## Setup

```bash
git clone <this-repo> ati-evn
cd ati-evn
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
# Fill in .env — see below for what's required vs optional
docker compose up -d                 # starts Postgres (ati-evn-postgres)
```

Required in `.env` to run anything: Postgres credentials (defaults
match `docker-compose.yml`), `OPENAI_API_KEY` (LLM provider, used by
the agent, CPE inference, and report narratives), and
`ABUSE_CH_AUTH_KEY` (free key at https://auth.abuse.ch/ — covers
ThreatFox, MalwareBazaar, URLhaus, Feodo). Everything else
(`NVD_API_KEY`, `CENSYS_API_KEY`, `URLSCAN_API_KEY`,
`GRAYHATWARFARE_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`,
`OTX_API_KEY`, `PULSEDIVE_API_KEY`, `LEAKIX_API_KEY`, ...) is optional
— each fetcher/provider/scanner degrades to "skipped, missing key"
rather than failing when its key is absent. Telegram bots need
`TELEGRAM_ALERT_BOT_TOKEN` + `TELEGRAM_ANALYST_BOT_TOKEN` (two
separate bots via @BotFather) and `TELEGRAM_ALLOWED_USER_IDS` (the
analyst allowlist).

## Running

Windows convenience scripts (start both bots in the background,
logging to `logs/`):

```bat
start.bat
stop.bat
```

Or run components directly:

```bash
python scripts/run_alert_bot.py       # Bot 1
python scripts/run_analyst_bot.py     # Bot 2 (also runs the scheduler)
python scripts/run_fetchers.py        # one-off manual fetch, all feeds
python scripts/run_matcher.py         # one-off manual matcher pass
python scripts/run_campaign_detection.py
python scripts/run_ttl_worker.py      # expire stale detections/sessions
```

## Verify the severity scorer

Runs the risk-scoring engine against 8 real-world incidents. Fast,
offline, no keys required.

```bash
python tests/smoke/test_severity_benchmark.py
```

Expected: `8/8 (100% accuracy)`.

## Project docs

- `KNOWN_LIMITATIONS.md` — features scoped out due to upstream API
  constraints (e.g. LeakCheck credential monitoring).
- `scripts/audit_14b_backlog.md` — running log of audit findings,
  fixes, and deferred low-priority issues.

## Layout

```
src/ati_evn/
  agent/          LLM agent loop (function-calling + ReAct fallback),
                   ~55 tools (query + destructive-with-confirmation)
  telegram/       Bot 1 + Bot 2, ~40 slash-commands, formatters
  fetchers/       NVD, ThreatFox, MalwareBazaar, URLhaus, Feodo
  ingest/         Raw IOC normalization + CVE ingest pipeline
  match/          Asset matching, customer routing, finding creation
  enrichment_v2/  Multi-provider IP enrichment + scoring
  external/       Censys, GrayHatWarfare, urlscan.io clients + pipelines
  rules/          Sigma rule matching/generation, playbooks
  brand_rules/    Brand-abuse classifier rule engine
  document_rules/ Exposed-document classifier rule engine
  exposure_rules/ Exposure-to-finding rule engine
  campaigns/      Attack campaign clustering/detection
  reports/        HTML+PDF report generation (global + per-customer)
  alerts/         Alert queue + Bot 1 dispatch logic
  rescan/         Background rescan (asset/finding re-enrichment)
  db/             SQLAlchemy models, session, query helpers
  llm/            LLM client (9Router/DeepSeek), JSON extraction
scripts/          Entry points (run_*.py) + audit/decision logs
tests/            Smoke tests
```

Backend-only, no web dashboard — Telegram is the sole analyst
interface, by design.
