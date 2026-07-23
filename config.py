"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_path: Path
    admin_username: str
    admin_password: str | None
    jwt_secret: str
    jwt_expire_minutes: int
    encryption_key: str
    telegram_bot_token: str | None
    mini_app_url: str | None
    relay_public_url: str | None
    scan_tick_seconds: int
    request_timeout_seconds: int
    notify_existing_on_first_sync: bool
    allow_insecure_endpoints: bool
    local_web_only: bool
    web_setup_expire_seconds: int

    @property
    def cookie_secure(self) -> bool:
        return self.app_env.lower() not in {"dev", "development", "test"}

    def fernet(self) -> Fernet:
        try:
            return Fernet(self.encryption_key.encode())
        except Exception as exc:  # pragma: no cover - error path is startup-only
            raise RuntimeError("ENCRYPTION_KEY must be a valid Fernet key") from exc


def load_settings() -> Settings:
    """Load settings and fail early for secrets that protect stored credentials."""
    encryption_key = os.getenv("ENCRYPTION_KEY", "")
    jwt_secret = os.getenv("JWT_SECRET", "")
    if not encryption_key:
        raise RuntimeError("ENCRYPTION_KEY is required; run scripts/bootstrap.py first.")
    if not jwt_secret:
        raise RuntimeError("JWT_SECRET is required; run scripts/bootstrap.py first.")

    database_value = os.getenv("DATABASE_PATH", "data/db.sqlite3")
    database_path = Path(database_value)
    if not database_path.is_absolute():
        database_path = BASE_DIR / database_path

    return Settings(
        app_env=os.getenv("APP_ENV", "development"),
        database_path=database_path,
        admin_username=os.getenv("ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("ADMIN_PASSWORD") or None,
        jwt_secret=jwt_secret,
        jwt_expire_minutes=int(os.getenv("JWT_EXPIRE_MINUTES", "720")),
        encryption_key=encryption_key,
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN") or None,
        mini_app_url=os.getenv("MINI_APP_URL") or None,
        relay_public_url=os.getenv("RELAY_PUBLIC_URL") or None,
        scan_tick_seconds=max(15, int(os.getenv("SCAN_TICK_SECONDS", "30"))),
        request_timeout_seconds=max(5, int(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))),
        notify_existing_on_first_sync=_as_bool(
            os.getenv("NOTIFY_EXISTING_ON_FIRST_SYNC"), default=False
        ),
        allow_insecure_endpoints=_as_bool(
            os.getenv("ALLOW_INSECURE_ENDPOINTS"), default=False
        ),
        local_web_only=_as_bool(os.getenv("LOCAL_WEB_ONLY"), default=True),
        web_setup_expire_seconds=max(60, int(os.getenv("WEB_SETUP_EXPIRE_SECONDS", "600"))),
    )
