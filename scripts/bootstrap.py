"""Create a local .env with an initial one-user account and strong secrets."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


PROJECT_DIR = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a secure .env for Target Monitor")
    parser.add_argument("--force", action="store_true", help="replace an existing .env")
    arguments = parser.parse_args()
    destination = PROJECT_DIR / ".env"
    if destination.exists() and not arguments.force:
        raise SystemExit(f"{destination} already exists; refusing to overwrite it (use --force to replace it).")

    username = input("Admin username [admin]: ").strip() or "admin"
    password = getpass.getpass("Admin password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Use an admin password of at least 12 characters.")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    content = "\n".join(
        (
            "APP_ENV=development",
            f"ADMIN_USERNAME={json.dumps(username)}",
            f"ADMIN_PASSWORD={json.dumps(password)}",
            f"JWT_SECRET={json.dumps(secrets.token_urlsafe(48))}",
            f"ENCRYPTION_KEY={json.dumps(Fernet.generate_key().decode())}",
            "DATABASE_PATH=data/db.sqlite3",
            "JWT_EXPIRE_MINUTES=720",
            "SCAN_TICK_SECONDS=30",
            "REQUEST_TIMEOUT_SECONDS=20",
            "NOTIFY_EXISTING_ON_FIRST_SYNC=false",
            "ALLOW_INSECURE_ENDPOINTS=false",
            "LOCAL_WEB_ONLY=true",
            "WEB_SETUP_EXPIRE_SECONDS=600",
            "TELEGRAM_BOT_TOKEN=",
            "MINI_APP_URL=",
            "RELAY_PUBLIC_URL=",
            "",
        )
    )
    destination.write_text(content, encoding="utf-8")
    os.chmod(destination, 0o600)
    print(f"Created {destination}. Add Telegram values if needed, then start the server.")


if __name__ == "__main__":
    main()
