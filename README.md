# ATI-EVN

**Agentic Threat Intelligence for Vietnam Electricity (EVN)**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![PostgreSQL](https://img.shields.io/badge/postgres-16-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

A threat intelligence platform for Vietnam Electricity (EVN) and its
13 subsidiaries (GENCOs, Power Corporations, NPT). It auto-fetches
CVE/IOC intel from public feeds, matches findings against EVN's asset
inventory (IT + SCADA/ICS), scans for external exposure (brand abuse,
document leaks, open services), and gives analysts two ways in:
automated alerts and a free-text AI agent for ad-hoc investigation —
all through Telegram, with no separate web dashboard.

---

## Table of contents

- [Why](#why)
- [Features](#features)
- [Architecture](#architecture)
- [Data model](#data-model)
- [Getting started](#getting-started)
- [Running](#running)
- [Using the bots](#using-the-bots)
- [Tech stack](#tech-stack)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Known limitations](#known-limitations)

---

## Why

Electric utility SOCs need CVE/IOC monitoring scoped to their own
asset inventory — not a generic feed — and they need it somewhere
analysts already are. ATI-EVN correlates public threat feeds against a
maintained EVN asset database (IT servers, network devices, SCADA/ICS
where relevant), classifies external-exposure signals (brand
impersonation, leaked documents, open services) through rule +
LLM-classifier pipelines to cut noise, and puts the whole workflow —
alerts, investigation, remediation reporting — inside Telegram, where
a Vietnamese-speaking analyst can act on it directly instead of
switching to a separate console.

## Features

| Area | What it does |
|---|---|
| **CVE/IOC ingestion** | Pulls from NVD, ThreatFox, MalwareBazaar, URLhaus, Feodo Tracker on independent schedules; retries transient failures; LLM-assisted CPE/CWE inference when a feed's metadata is incomplete. |
| **Asset matching** | Matches CVEs against `CustomerAsset` records by vendor/product/version (CPE range–aware), IOCs by IP/domain/hash, and routes qualifying matches to an alert queue. |
| **External monitoring** | Censys (open services), GrayHatWarfare (exposed documents in public buckets), urlscan.io (brand abuse / typosquat / phishing) — each behind a rule-engine → classifier pipeline, run weekly and on demand. |
| **IP/domain enrichment** | 5-provider aggregate (AbuseIPDB, VirusTotal, OTX, Pulsedive, LeakIX) with a scoring engine for risk/confidence/coverage/consensus; auto-backfills every 15 minutes. |
| **Campaign detection** | Clusters related findings (shared technique, tight time window, multiple assets) into candidate attack campaigns for analyst confirm/reject. |
| **AI analyst agent** | Free-text Vietnamese Q&A over the whole dataset — function-calling with a ReAct fallback, ~55 tools, asks for explicit confirmation before any destructive action. |
| **Reporting** | CyRadar-style HTML+PDF reports (global or per-customer) with an LLM-generated executive summary and prioritized remediation list. |
| **Sigma rules & playbooks** | Matches/generates Sigma detection rules per CVE; generates NIST 800-61 incident-response playbooks on demand, cached per (CVE, network segment). |
| **Telegram-native** | Two bots — one-way alert dispatch, and a full analyst command surface (~40 slash-commands) plus the AI agent — no dashboard to stand up or maintain. |

## Architecture

Two Telegram bots share one PostgreSQL database and the same codebase:

```
                      ┌─────────────────────┐
   Public feeds  ───▶ │   Fetchers (5)       │
  (NVD, ThreatFox,    │   + scheduler        │
   MalwareBazaar,     └──────────┬───────────┘
   URLhaus, Feodo)                │
                                   ▼
                       ┌──────────────────────┐
                       │  Ingest + Match       │──▶ Finding /
                       │  (CPE-aware routing)  │    ThreatIndicator
                       └──────────┬────────────┘
                                   │
                                   ▼
                       ┌──────────────────────┐        ┌───────────────┐
                       │     Alert Queue        │──────▶│ Bot 1: Alert  │
                       └──────────────────────┘        │  dispatcher   │
                                                          └───────────────┘
   External scans  ───▶ Censys / GrayHatWarfare / urlscan.io
   (weekly + on demand)        (rule engine → LLM classifier)
                                   │
                                   ▼
                          PostgreSQL (single DB)
                                   │
                                   ▼
                       ┌──────────────────────┐
                       │ Bot 2: Analyst        │  ~40 slash-commands
                       │  command bot          │  + free-text AI agent
                       │  (+ APScheduler)       │  (function-calling → ReAct)
                       └──────────────────────┘
```

- **Bot 1 — Alert dispatcher** (`scripts/run_alert_bot.py`): polls the
  alert queue every 5s and pushes new/batched alerts to the team chat.
  No analyst interaction — one-way notification.
- **Bot 2 — Analyst command bot** (`scripts/run_analyst_bot.py`): the
  main interface. Slash-commands for querying and acting on
  findings/assets/customers/campaigns/indicators, plus a free-text
  mode where an LLM agent picks tools, asks for confirmation before
  anything destructive, and answers in Vietnamese. Also drives the
  fetcher scheduler and all weekly/background jobs via APScheduler.

**Entity model note (post slice-15A split):** `Finding` is CVE-only,
with a full lifecycle (`/close`, `/mark_fp`, `/reopen`, `/silence`).
Everything else — raw IOC, brand abuse, exposed documents, exposure
rule matches — is a `ThreatIndicator`: read-only plus
acknowledge/note, no close/reopen/false-positive concept, since these
are ephemeral external signals rather than a vulnerability tracked
against an asset.

## Data model

Backed by PostgreSQL, no ORM migration framework (schema changes are
manual `ALTER TABLE`, backed up first — see `backups/`). Key tables:

- `customers`, `customer_assets` — the EVN org tree + asset inventory
  matching runs against.
- `detections` — raw normalized IOC rows from fetchers/manual input.
- `findings` — CVE matches against an asset, with full lifecycle.
- `threat_indicators` — non-CVE signals (raw IOC, brand abuse, exposed
  document, exposure).
- `campaigns` / `campaign_findings` — clustered attack campaigns.
- `alert_queue` — dispatch state for Bot 1.
- `agent_sessions` — per-analyst conversation state for the AI agent
  (entity memory, command log, TTL-expired).
- `reports` — generated HTML/PDF report metadata + file paths.
- `playbook_cache` — generated incident-response playbooks, cached by
  `(cve_id, network_segment)`.

## Getting started

**Prerequisites:** Python 3.11+, Docker (for Postgres), a Telegram
account to create two bots via [@BotFather](https://t.me/BotFather).

```bash
git clone <this-repo> ati-evn
cd ati-evn
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
docker compose up -d                 # starts Postgres (ati-evn-postgres)
```

### Configuration

| Variable | Required? | Purpose |
|---|---|---|
| `POSTGRES_*` | Yes | Defaults match `docker-compose.yml`, no changes needed for local dev. |
| `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `LLM_MODEL` | Yes | LLM provider (agent, CPE inference, report narratives, playbooks). Configured for 9Router/DeepSeek by default. |
| `ABUSE_CH_AUTH_KEY` | Yes | Single key covers ThreatFox, MalwareBazaar, URLhaus, Feodo — free at [auth.abuse.ch](https://auth.abuse.ch/). |
| `TELEGRAM_ALERT_BOT_TOKEN`, `TELEGRAM_ANALYST_BOT_TOKEN` | Yes | Two separate bots via @BotFather — one for alerts, one for analyst commands. |
| `TELEGRAM_ALLOWED_USER_IDS` | Yes | Comma-separated analyst allowlist (Telegram user IDs). |
| `NVD_API_KEY` | Optional | Raises NVD rate limit from 5 to 50 req/30s. |
| `CENSYS_API_KEY`, `URLSCAN_API_KEY`, `GRAYHATWARFARE_API_KEY` | Optional | External-monitoring scans; each skips cleanly if its key is absent. |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `PULSEDIVE_API_KEY`, `LEAKIX_API_KEY` | Optional | IP-enrichment providers; the aggregate degrades gracefully with fewer providers. |

Every optional integration is designed to **degrade, not fail** —
missing a key means that one fetcher/provider/scanner reports
"skipped" instead of the process crashing.

## Running

**Windows** (starts both bots in the background, logs to `logs/`):

```bat
start.bat
stop.bat
```

**Directly:**

```bash
python scripts/run_alert_bot.py       # Bot 1
python scripts/run_analyst_bot.py     # Bot 2 (also runs the scheduler)
python scripts/run_fetchers.py        # one-off manual fetch, all feeds
python scripts/run_matcher.py         # one-off manual matcher pass
python scripts/run_campaign_detection.py
python scripts/run_ttl_worker.py      # expire stale detections/sessions
```

## Using the bots

**Bot 1** requires no interaction — it dispatches alerts to
`TELEGRAM_ALERT_CHAT_ID` as findings qualify.

**Bot 2** takes either slash-commands or free-text, in the same chat:

```
/stats                              → dashboard overview
/finding 219                        → CVE finding detail + ATT&CK context
/enrich_ip 8.8.8.8 --full           → 5-provider IP enrichment
/scan_urlscan --keyword=EVN         → brand-abuse scan (long-running scans run
                                       in the background, results posted when done)
/generate_report --window=7d        → inline markdown summary
/playbook CVE-2026-47295            → NIST 800-61 response playbook

Tóm tắt tình hình bảo mật cho EVN   → free-text, routed through the AI agent
```

Destructive actions (`/add_ioc`, `/close`, `trigger_report_generation`,
...) always show an impact summary and wait for explicit analyst
confirmation before executing — both from slash-commands and when the
AI agent decides to call the same tool.

## Tech stack

- **Language:** Python 3.11+, fully async (`asyncio`)
- **Bot framework:** [aiogram](https://docs.aiogram.dev/) 3.x
- **Database:** PostgreSQL 16 via SQLAlchemy 2.0 (async) + asyncpg
- **HTTP:** httpx, with `tenacity` retry on transient network errors
- **Scheduling:** APScheduler
- **LLM:** OpenAI-compatible client (configured for 9Router/DeepSeek),
  function-calling + ReAct agent loop
- **Rules:** pySigma (Sigma detection rules), sentence-transformers
  (ATT&CK technique embedding lookup)
- **Reports:** Jinja2 (HTML) + wkhtmltopdf (PDF)

## Testing

```bash
python tests/smoke/test_severity_benchmark.py   # 8 real-world incidents, offline, no keys
pytest tests/unit/                                # unit tests
```

Severity-scorer smoke test expected output: `8/8 (100% accuracy)`.

## Project layout

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
tests/            Smoke + unit tests
```

Backend-only, no web dashboard — Telegram is the sole analyst
interface, by design.

## Known limitations

See [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) for features scoped
out due to upstream API constraints (e.g. credential-leak monitoring
requiring a commercial LeakCheck tier). Ongoing audit findings and
fixes are tracked in
[`scripts/audit_14b_backlog.md`](scripts/audit_14b_backlog.md).
