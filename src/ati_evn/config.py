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
    leakix_api_key: str = ""
    grayhatwarfare_api_key: str = ""

    # ── Enrichment ───────────────────────────────────────────────────────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ── Telegram ─────────────────────────────────────────────────────────────
    telegram_bot_token: str = ""
    telegram_alert_chat_id: str = ""
    telegram_allowed_user_ids: str = ""  # comma-separated ints

    @property
    def telegram_allowed_ids(self) -> set[int]:
        if not self.telegram_allowed_user_ids:
            return set()
        return {int(x.strip()) for x in self.telegram_allowed_user_ids.split(",") if x.strip()}

    # ── Runtime ──────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    user_agent: str = "ATI-EVN/0.1 (+security-research)"
    http_timeout_seconds: int = 30


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
