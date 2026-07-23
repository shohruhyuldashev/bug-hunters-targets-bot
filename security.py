"""Password, JWT, CSRF, and encrypted-secret helpers."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
from cryptography.fernet import Fernet
from jose import JWTError, jwt


JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def issue_access_token(username: str, secret: str, expires_minutes: int) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=expires_minutes),
        "type": "access",
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def read_access_token(token: str, secret: str) -> str | None:
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None
    if payload.get("type") != "access" or not isinstance(payload.get("sub"), str):
        return None
    return payload["sub"]


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def encrypt_secret(fernet: Fernet, value: str) -> str:
    return fernet.encrypt(value.encode()).decode()


def decrypt_secret(fernet: Fernet, value: str) -> str:
    return fernet.decrypt(value.encode()).decode()
