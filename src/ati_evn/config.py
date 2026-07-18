"""Runtime configuration loaded from .env.

Single source of truth. Any code that needs a key or URL reads from `settings`.
No os.getenv scattered around the codebase.
"""
from __future__ import annotations

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ─────────────────────────────────────────────────────────────
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "ati_evn"
    postgres_password: str = "ati_evn"
    postgres_db: str = "ati_evn"

    @property
    def database_url_async(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url_sync(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── LLM Provider: 9Router (DeepSeek) — sole LLM provider for this project ─
    openai_api_key: str = ""
    openai_base_url: str = "https://api.codexhub.click/v1"
    llm_model: str = "deepseek-v4-flash"
    llm_provider: str = "9router"
    llm_cpe_min_confidence: float = 0.6
    llm_max_concurrent: int = 5

    # ── ATT&CK enrichment (slice 4.5) ────────────────────────────────────────
    attack_bert_model: str = "basel/ATTACK-BERT"
    attack_bert_device: str = "cpu"
    smet_embeddings_cache: str = "./src/ati_evn/data/technique_embeddings.npz"

    # ── Sigma rules (slice 4.7) ──────────────────────────────────────────────
    sigma_repo_dir: str = "./data/sigmahq"
    sigma_rule_min_score: int = 0   # for filtering community results

    # ── CVE feeds ────────────────────────────────────────────────────────────
    nvd_api_key: str = ""
    vulners_api_key: str = ""

    # ── abuse.ch (single key for ThreatFox/MalwareBazaar/URLhaus/Feodo) ──────
    abuse_ch_auth_key: str = ""

    # ── Other IOC feeds ──────────────────────────────────────────────────────
    otx_api_key: str = ""
    urlscan_api_key: str = ""
    pulsedive_api_key: str = ""
    github_token: str = ""
    leakcheck_api_key: str = ""

    # ── Attack surface discovery ─────────────────────────────────────────────
    censys_api_key: str = ""
    censys_default_asn: str = "149069"   # EVNICT
    censys_max_hosts_per_scan: int = 100
    leakix_api_key: str = ""
    grayhatwarfare_api_key: str = ""

    # ── Enrichment ───────────────────────────────────────────────────────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ── Telegram ─────────────────────────────────────────────────────────────
    telegram_bot_token: str = ""
    telegram_alert_chat_id: str = ""
    telegram_allowed_user_ids: str = ""  # comma-separated ints

    # ── Telegram Bot 1 (Alert Notifier) — slice 5A ────────────────────────────
    telegram_alert_bot_token: str = ""
    telegram_analyst_bot_username: str = ""  # for "@<bot>" command hints in alerts

    # Dispatch behavior
    alert_dedupe_window_minutes: int = 5
    alert_batch_trigger_count: int = 3    # >=3 findings same customer → batch
    alert_batch_window_seconds: int = 60
    alert_retry_max_attempts: int = 5
    alert_retry_backoff_seconds: int = 300  # 5-min fixed interval per spec

    @property
    def telegram_allowed_ids(self) -> set[int]:
        if not self.telegram_allowed_user_ids:
            return set()
        return {int(x.strip()) for x in self.telegram_allowed_user_ids.split(",") if x.strip()}

    # ── Telegram Bot 2 (Analyst Command) — slice 5B.1 ─────────────────────────
    telegram_analyst_bot_token: str = ""
    telegram_analyst_chat: str = ""   # cross-bot reference; .env uses TELEGRAM_ANALYST_CHAT

    @property
    def allowed_user_ids_set(self) -> set[int]:
        if not self.telegram_allowed_user_ids:
            return set()
        return {int(x.strip()) for x in self.telegram_allowed_user_ids.split(",")
                if x.strip().isdigit()}

    # ── Runtime ──────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    user_agent: str = "ATI-EVN/0.1 (+security-research)"
    http_timeout_seconds: int = 30


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
