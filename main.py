"""FastAPI web panel for the target monitor."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import time
from contextlib import asynccontextmanager
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bot import TelegramNotifier
from config import BASE_DIR, Settings, load_settings
from database import Database
from realtime import EventHub
from scanner import ScanError, TargetScanner
from scheduler import MonitorScheduler
from security import (
    encrypt_secret,
    issue_access_token,
    new_csrf_token,
    read_access_token,
    verify_password,
)


settings: Settings = load_settings()
database = Database(settings.database_path)
event_hub = EventHub()
notifier = TelegramNotifier(database, settings)
scanner = TargetScanner(database, settings, notifier, event_hub)
monitor_scheduler = MonitorScheduler(scanner, settings)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class PlatformCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: str = "hackerone"
    endpoint: str = Field(min_length=8, max_length=1000)
    details_endpoint: str | None = Field(default=None, max_length=1000)
    program_name: str = Field(min_length=1, max_length=160)
    credential_identifier: str | None = Field(default=None, max_length=255)
    credential_token: str | None = Field(default=None, max_length=2000)
    poll_interval_seconds: int = Field(default=60, ge=60, le=86_400)
    public_broadcast: bool = False

    @field_validator("name", "program_name", "credential_identifier", "credential_token")
    @classmethod
    def strip_strings(cls, value: str | None) -> str | None:
        return value.strip() if isinstance(value, str) else value

    @field_validator("kind")
    @classmethod
    def only_hackerone_for_now(cls, value: str) -> str:
        if value != "hackerone":
            raise ValueError("Only hackerone is currently enabled")
        return value

    @model_validator(mode="after")
    def credentials_are_pair(self) -> "PlatformCreate":
        if bool(self.credential_identifier) != bool(self.credential_token):
            raise ValueError("HackerOne requires both API token identifier and token")
        return self


def validate_endpoint(endpoint: str) -> str:
    candidate = endpoint.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="Endpoint must be an absolute HTTP(S) URL without embedded credentials")
    if parsed.scheme != "https" and not settings.allow_insecure_endpoints:
        raise HTTPException(status_code=422, detail="Only HTTPS endpoints are allowed (set ALLOW_INSECURE_ENDPOINTS=true for local development)")
    return candidate


class LoginRateLimiter:
    def __init__(self) -> None:
        self.attempts: dict[str, list[float]] = {}

    def allowed(self, address: str) -> bool:
        now = time.monotonic()
        recent = [stamp for stamp in self.attempts.get(address, []) if now - stamp < 60]
        self.attempts[address] = recent
        return len(recent) < 5

    def failed(self, address: str) -> None:
        self.attempts.setdefault(address, []).append(time.monotonic())

    def clear(self, address: str) -> None:
        self.attempts.pop(address, None)


login_limiter = LoginRateLimiter()


class RelayRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    setup_code: str = Field(min_length=20, max_length=200)


class RelayEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=12, max_length=100)
    event_id: str = Field(min_length=16, max_length=200)
    program: str = Field(min_length=1, max_length=160)
    identifier: str = Field(min_length=1, max_length=1000)
    asset_type: str = Field(min_length=1, max_length=100)
    observed_at: str = Field(min_length=1, max_length=80)


class RelayProgramSync(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=12, max_length=100)
    program: str = Field(min_length=1, max_length=160)
    platform: str = Field(default="HackerOne", min_length=1, max_length=80)
    scope_count: int = Field(ge=0, le=100_000)
    asset_types: dict[str, int] = Field(default_factory=dict)
    resolved_reports: int | None = Field(default=None, ge=0)
    minimum_bounty: str | None = Field(default=None, max_length=80)
    average_bounty: str | None = Field(default=None, max_length=80)
    maximum_bounty: str | None = Field(default=None, max_length=80)
    currency: str | None = Field(default=None, max_length=20)
    program_updated_at: str | None = Field(default=None, max_length=80)

    @field_validator("asset_types")
    @classmethod
    def validate_asset_types(cls, value: dict[str, int]) -> dict[str, int]:
        if len(value) > 50 or any(not key or len(key) > 80 or count < 0 for key, count in value.items()):
            raise ValueError("Invalid asset type summary")
        return value


class RelayTargetItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identifier: str = Field(min_length=1, max_length=1000)
    asset_type: str = Field(default="Other", min_length=1, max_length=100)
    source_url: str | None = Field(default=None, max_length=2000)


class RelayTargetsSync(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=12, max_length=100)
    program: str = Field(min_length=1, max_length=160)
    platform: str = Field(default="HackerOne", min_length=1, max_length=80)
    targets: list[RelayTargetItem] = Field(default_factory=list)

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, value: list) -> list:
        if len(value) > 100_000:
            raise ValueError("Too many targets in one sync")
        return value


class UserConnectionCreate(BaseModel):
    agent_id: str = Field(min_length=12, max_length=100)
    platform: str = Field(min_length=1, max_length=50)
    program_name: str = Field(min_length=1, max_length=160)
    endpoint: str = Field(min_length=8, max_length=1000)
    details_endpoint: str | None = Field(default=None, max_length=1000)
    credential_identifier: str | None = Field(default=None, max_length=255)
    credential_token: str | None = Field(default=None, max_length=2000)
    poll_interval_seconds: int = Field(default=300, ge=60, le=86_400)

    @field_validator("platform", "program_name", "endpoint")
    @classmethod
    def strip_str(cls, value: str) -> str:
        return value.strip()


def is_internal_address(address: str | None) -> bool:
    if not address:
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def source_address(request: Request) -> str | None:
    """Honor forwarded client IP only when the request arrived from loopback."""
    direct = request.client.host if request.client else None
    try:
        direct_is_loopback = bool(direct and ipaddress.ip_address(direct).is_loopback)
    except ValueError:
        direct_is_loopback = False
    if direct_is_loopback:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return direct


async def current_user(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else None
    token = token or request.cookies.get("access_token")
    username = read_access_token(token or "", settings.jwt_secret)
    if not username or database.verify_user(username) is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return username


async def csrf_protected(request: Request, _: Annotated[str, Depends(current_user)]) -> None:
    expected = request.cookies.get("csrf_token", "")
    provided = request.headers.get("X-CSRF-Token", "")
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize(settings.admin_username, settings.admin_password)
    await notifier.start()
    monitor_scheduler.start()
    initial_scan = asyncio.create_task(scanner.scan_due())
    try:
        yield
    finally:
        initial_scan.cancel()
        monitor_scheduler.stop()
        await notifier.stop()


app = FastAPI(title="Target Monitor", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.mount("/miniapp", StaticFiles(directory=BASE_DIR / "miniapp", html=True), name="miniapp")


@app.middleware("http")
async def local_owner_console_only(request: Request, call_next):
    """Keep owner routes on a private network; only key-free Mini App relay is public."""
    public_path = request.url.path.startswith("/miniapp") or request.url.path.startswith("/relay/")
    client_address = source_address(request)
    if settings.local_web_only and not public_path and not is_internal_address(client_address):
        return JSONResponse(status_code=403, content={"detail": "Owner console is available only on the local network"})
    return await call_next(request)


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, str]:
    address = request.client.host if request.client else "unknown"
    if not login_limiter.allowed(address):
        raise HTTPException(status_code=429, detail="Too many login attempts; try again in one minute")
    user = database.verify_user(payload.username)
    if user is None or not verify_password(payload.password, user["password_hash"]):
        login_limiter.failed(address)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    login_limiter.clear(address)
    csrf_token = new_csrf_token()
    access_token = issue_access_token(user["username"], settings.jwt_secret, settings.jwt_expire_minutes)
    cookie_common = {"max_age": settings.jwt_expire_minutes * 60, "secure": settings.cookie_secure, "samesite": "lax", "path": "/"}
    response.set_cookie("access_token", access_token, httponly=True, **cookie_common)
    response.set_cookie("csrf_token", csrf_token, httponly=False, **cookie_common)
    return {"username": user["username"], "csrf_token": csrf_token}


@app.post("/api/auth/logout", dependencies=[Depends(csrf_protected)])
async def logout(response: Response) -> dict[str, bool]:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("csrf_token", path="/")
    return {"ok": True}


@app.get("/api/dashboard")
async def dashboard(_: Annotated[str, Depends(current_user)]) -> dict[str, object]:
    return {
        "stats": database.stats(),
        "events": database.latest_events(20),
        "platforms": database.list_platforms(),
    }


@app.get("/api/platforms")
async def list_platforms(_: Annotated[str, Depends(current_user)]) -> list[dict[str, object]]:
    return database.list_platforms()


@app.post("/api/platforms", status_code=201, dependencies=[Depends(csrf_protected)])
async def add_platform(payload: PlatformCreate) -> dict[str, object]:
    endpoint = validate_endpoint(payload.endpoint)
    details_endpoint = validate_endpoint(payload.details_endpoint) if payload.details_endpoint else None
    encrypted_credentials = None
    if payload.credential_identifier and payload.credential_token:
        plain_credentials = json.dumps({"identifier": payload.credential_identifier, "token": payload.credential_token})
        encrypted_credentials = encrypt_secret(settings.fernet(), plain_credentials)
    try:
        platform = database.create_platform(
            name=payload.name,
            kind=payload.kind,
            endpoint=endpoint,
            details_endpoint=details_endpoint,
            program_name=payload.program_name,
            encrypted_credentials=encrypted_credentials,
            poll_interval_seconds=payload.poll_interval_seconds,
            public_broadcast=payload.public_broadcast,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return platform


@app.post("/api/platforms/{platform_id}/scan", dependencies=[Depends(csrf_protected)])
async def scan_now(platform_id: int) -> dict[str, object]:
    try:
        return await scanner.scan_platform(platform_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ScanError as exc:
        raise HTTPException(status_code=502, detail=f"Scope fetch failed: {exc}") from exc


@app.get("/api/events")
async def events(
    _: Annotated[str, Depends(current_user)], limit: int = 20
) -> list[dict[str, object]]:
    return database.latest_events(limit)


@app.get("/api/assets")
async def assets(
    _: Annotated[str, Depends(current_user)],
    asset_type: str | None = None,
    program: str | None = None,
    limit: int = 100,
) -> list[dict[str, object]]:
    return database.assets(asset_type=asset_type, program=program, limit=limit)


@app.post("/relay/register")
async def register_relay_agent(payload: RelayRegistration) -> dict[str, str]:
    """Exchange a one-time bot-issued setup code for a client-agent relay credential.

    This endpoint intentionally has no field that can contain a platform API key.
    """
    chat_id = database.consume_web_setup_session(payload.setup_code)
    if chat_id is None or not settings.relay_public_url:
        raise HTTPException(status_code=401, detail="Invalid or expired setup link")
    agent_id, agent_secret = database.create_relay_agent(chat_id)
    return {"agent_id": agent_id, "agent_secret": agent_secret, "relay_url": settings.relay_public_url}


def relay_secret(request: Request) -> str:
    secret = request.headers.get("X-Agent-Secret", "")
    if not secret or len(secret) > 200:
        raise HTTPException(status_code=401, detail="Missing agent credential")
    return secret


@app.post("/relay/events")
async def relay_event(payload: RelayEvent, agent_secret: Annotated[str, Depends(relay_secret)]) -> dict[str, bool]:
    owner_chat_id = database.accept_relay_event(payload.agent_id, agent_secret, payload.event_id)
    if owner_chat_id is None:
        raise HTTPException(status_code=401, detail="Invalid agent credential")
    if owner_chat_id == "":
        return {"accepted": True, "duplicate": True}
    delivered = await notifier.send_client_target(
        owner_chat_id,
        {
            "program": payload.program,
            "identifier": payload.identifier,
            "asset_type": payload.asset_type,
            "observed_at": payload.observed_at,
        },
    )
    if not delivered:
        database.release_relay_event(payload.agent_id, payload.event_id)
        raise HTTPException(status_code=503, detail="Telegram delivery is unavailable; retry this event")
    return {"accepted": True, "duplicate": False}


@app.post("/relay/programs")
async def relay_program_sync(
    payload: RelayProgramSync, agent_secret: Annotated[str, Depends(relay_secret)]
) -> dict[str, bool]:
    owner_chat_id = database.relay_agent_owner(payload.agent_id, agent_secret)
    if owner_chat_id is None:
        raise HTTPException(status_code=401, detail="Invalid agent credential")
    # Whitelisted metadata only: API credentials and source URLs have no route here.
    database.save_relay_program(owner_chat_id, payload.program, payload.model_dump(exclude={"agent_id"}))
    return {"accepted": True}


@app.post("/relay/targets")
async def relay_targets_sync(
    payload: RelayTargetsSync, agent_secret: Annotated[str, Depends(relay_secret)]
) -> dict[str, bool]:
    """Bulk sync of all targets for a program — used for /program target list in the bot."""
    owner_chat_id = database.relay_agent_owner(payload.agent_id, agent_secret)
    if owner_chat_id is None:
        raise HTTPException(status_code=401, detail="Invalid agent credential")
    targets = [t.model_dump() for t in payload.targets]
    database.save_relay_targets(owner_chat_id, payload.program, targets)
    return {"accepted": True, "saved": len(targets)}


# ── Server-side User Connections API (Mini App Direct Setup) ─────────────────

@app.get("/api/user/connections")
async def get_user_connections(
    agent_id: str, agent_secret: Annotated[str, Depends(relay_secret)]
) -> list[dict[str, Any]]:
    owner_chat_id = database.relay_agent_owner(agent_id, agent_secret)
    if owner_chat_id is None:
        raise HTTPException(status_code=401, detail="Invalid session credential")
    return database.get_user_connections(owner_chat_id)


@app.post("/api/user/connections")
async def create_user_connection(
    payload: UserConnectionCreate, agent_secret: Annotated[str, Depends(relay_secret)]
) -> dict[str, Any]:
    owner_chat_id = database.relay_agent_owner(payload.agent_id, agent_secret)
    if owner_chat_id is None:
        raise HTTPException(status_code=401, detail="Invalid session credential")

    endpoint = validate_endpoint(payload.endpoint)
    details_endpoint = validate_endpoint(payload.details_endpoint) if payload.details_endpoint else None

    # Encrypt token securely using Fernet
    encrypted_token = None
    if payload.credential_token:
        encrypted_token = encrypt_secret(settings.fernet(), payload.credential_token)

    conn_id = database.save_user_connection(
        owner_chat_id=owner_chat_id,
        platform=payload.platform,
        program_name=payload.program_name,
        endpoint=endpoint,
        details_endpoint=details_endpoint,
        credential_identifier=payload.credential_identifier,
        encrypted_token=encrypted_token,
        poll_interval_seconds=payload.poll_interval_seconds,
    )

    # Immediately trigger initial scan in background task
    user_conn = {
        "id": conn_id,
        "owner_chat_id": owner_chat_id,
        "platform": payload.platform,
        "program_name": payload.program_name,
        "endpoint": endpoint,
        "details_endpoint": details_endpoint,
        "credential_identifier": payload.credential_identifier,
        "encrypted_token": encrypted_token,
    }
    asyncio.create_task(scanner.scan_user_connection(user_conn))

    return {"accepted": True, "id": conn_id}


@app.delete("/api/user/connections/{connection_id}")
async def delete_user_connection(
    connection_id: str, agent_id: str, agent_secret: Annotated[str, Depends(relay_secret)]
) -> dict[str, bool]:
    owner_chat_id = database.relay_agent_owner(agent_id, agent_secret)
    if owner_chat_id is None:
        raise HTTPException(status_code=401, detail="Invalid session credential")

    deleted = database.delete_user_connection(owner_chat_id, connection_id)
    return {"deleted": deleted}


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    if settings.local_web_only and not is_internal_address(websocket.client.host if websocket.client else None):
        await websocket.close(code=1008)
        return
    origin = websocket.headers.get("origin")
    if origin:
        origin_host = urlsplit(origin).netloc
        request_host = websocket.headers.get("host", "")
        if origin_host != request_host:
            await websocket.close(code=1008)
            return
    token = websocket.cookies.get("access_token", "")
    username = read_access_token(token, settings.jwt_secret)
    if not username or database.verify_user(username) is None:
        await websocket.close(code=1008)
        return
    await event_hub.connect(websocket)
    try:
        while True:
            # The UI need not send messages; waiting here lets us observe disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await event_hub.disconnect(websocket)
