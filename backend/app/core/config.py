from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # API Keys
    vt_api_key: str = ""
    google_safe_browsing_key: str = ""
    abuseipdb_key: str = ""

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Database
    database_url: str = "postgresql+asyncpg://phishguard:phishguard_secret@localhost:5432/phishguard"

    # App
    debug: bool = False
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:5173"]

    # Rate limiting
    rate_limit_per_minute: int = 60
    rate_limit_per_day: int = 1000

    # Playwright
    playwright_timeout_ms: int = 15000
    enable_playwright: bool = True

    # Tranco
    tranco_file_path: str = "data/tranco_top1m.csv"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
