"""SQLite persistence for the single-user target monitor."""

from __future__ import annotations

import json
import hashlib
import secrets
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from compare import deduplicate_assets
from models import TargetAsset
from security import hash_password


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self, admin_username: str, admin_password: str | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connection() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS bot_users (
                    chat_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS platforms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL CHECK (kind IN ('hackerone')),
                    endpoint TEXT NOT NULL,
                    details_endpoint TEXT,
                    program_name TEXT NOT NULL,
                    encrypted_credentials TEXT,
                    public_broadcast INTEGER NOT NULL DEFAULT 0 CHECK (public_broadcast IN (0, 1)),
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                    poll_interval_seconds INTEGER NOT NULL DEFAULT 300 CHECK (poll_interval_seconds >= 60),
                    created_at TEXT NOT NULL,
                    last_polled_at TEXT,
                    initialized_at TEXT,
                    last_error TEXT
                );

                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform_id INTEGER NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
                    program TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    source_url TEXT,
                    canonical_key TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                    UNIQUE(platform_id, canonical_key)
                );

                CREATE INDEX IF NOT EXISTS idx_assets_active ON assets(is_active, last_seen_at DESC);
                CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program COLLATE NOCASE);

                CREATE TABLE IF NOT EXISTS target_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL CHECK (event_type IN ('added', 'reintroduced')),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_created_at ON target_events(created_at DESC);

                CREATE TABLE IF NOT EXISTS program_details (
                    platform_id INTEGER PRIMARY KEY REFERENCES platforms(id) ON DELETE CASCADE,
                    details_json TEXT NOT NULL,
                    last_refreshed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS web_setup_sessions (
                    code_hash TEXT PRIMARY KEY,
                    chat_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS relay_agents (
                    id TEXT PRIMARY KEY,
                    owner_chat_id TEXT NOT NULL,
                    secret_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
                );

                CREATE TABLE IF NOT EXISTS relay_event_ids (
                    agent_id TEXT NOT NULL REFERENCES relay_agents(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (agent_id, event_id)
                );

                CREATE TABLE IF NOT EXISTS relay_programs (
                    owner_chat_id TEXT NOT NULL,
                    program_key TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    last_refreshed_at TEXT NOT NULL,
                    PRIMARY KEY (owner_chat_id, program_key)
                );

                CREATE TABLE IF NOT EXISTS relay_targets (
                    owner_chat_id TEXT NOT NULL,
                    program_key TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    asset_type TEXT NOT NULL DEFAULT 'Other',
                    source_url TEXT,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    details_json TEXT,
                    PRIMARY KEY (owner_chat_id, program_key, identifier, asset_type)
                );
                CREATE INDEX IF NOT EXISTS idx_relay_targets_prog
                    ON relay_targets(owner_chat_id, program_key, asset_type);
                """
            )
            # Migration
            try:
                connection.execute("ALTER TABLE relay_targets ADD COLUMN details_json TEXT")
            except sqlite3.OperationalError:
                pass

            # Data migration: normalize ALL existing asset_type values using the shared normalizer.
            # This fixes duplicates like 'SOURCE_CODE'/'SourceCode'/'Source Code', etc.
            try:
                from adapters import normalize_asset_type
                rows = connection.execute("SELECT DISTINCT asset_type FROM relay_targets").fetchall()
                for row in rows:
                    old_val = row[0]
                    new_val = normalize_asset_type(old_val)
                    if old_val != new_val:
                        connection.execute(
                            "UPDATE OR IGNORE relay_targets SET asset_type = ? WHERE asset_type = ?",
                            (new_val, old_val)
                        )
                        connection.execute(
                            "DELETE FROM relay_targets WHERE asset_type = ?",
                            (old_val,)
                        )
            except Exception:
                pass

            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_connections (
                    id TEXT PRIMARY KEY,
                    owner_chat_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    program_name TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    details_endpoint TEXT,
                    credential_identifier TEXT,
                    encrypted_token TEXT,
                    poll_interval_seconds INTEGER NOT NULL DEFAULT 300,
                    last_scanned_at TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_user_conn_owner ON user_connections(owner_chat_id);
                """
            )
            self._ensure_column(connection, "platforms", "details_endpoint", "TEXT")
            self._ensure_column(
                connection,
                "platforms",
                "public_broadcast",
                "INTEGER NOT NULL DEFAULT 0 CHECK (public_broadcast IN (0, 1))",
            )
            existing = connection.execute("SELECT id FROM users WHERE id = 1").fetchone()
            if existing is None:
                if not admin_password:
                    raise RuntimeError(
                        "ADMIN_PASSWORD is required for the initial single-user account. "
                        "Run scripts/bootstrap.py first."
                    )
                connection.execute(
                    "INSERT INTO users (id, username, password_hash, created_at) VALUES (1, ?, ?, ?)",
                    (admin_username, hash_password(admin_password), utc_now()),
                )

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def verify_user(self, username: str) -> sqlite3.Row | None:
        with self._lock, self._connection() as connection:
            return connection.execute(
                "SELECT id, username, password_hash FROM users WHERE id = 1 AND username = ?", (username,)
            ).fetchone()

    def register_bot_user(self, chat_id: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO bot_users (chat_id, created_at) VALUES (?, ?)",
                (chat_id, utc_now()),
            )
            
    def get_all_bot_users(self) -> list[str]:
        with self._lock, self._connection() as connection:
            rows = connection.execute("SELECT chat_id FROM bot_users").fetchall()
            return [r["chat_id"] for r in rows]

    def create_platform(
        self,
        *,
        name: str,
        kind: str,
        endpoint: str,
        details_endpoint: str | None,
        program_name: str,
        encrypted_credentials: str | None,
        poll_interval_seconds: int,
        public_broadcast: bool,
    ) -> dict[str, Any]:
        created_at = utc_now()
        with self._lock, self._connection() as connection:
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO platforms (
                        name, kind, endpoint, details_endpoint, program_name, encrypted_credentials,
                        poll_interval_seconds, public_broadcast, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        kind,
                        endpoint,
                        details_endpoint,
                        program_name,
                        encrypted_credentials,
                        poll_interval_seconds,
                        int(public_broadcast),
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A platform connection with this name already exists") from exc
            platform_id = int(cursor.lastrowid)
        return self.get_platform(platform_id)

    def list_platforms(self) -> list[dict[str, Any]]:
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, name, kind, endpoint, details_endpoint, program_name, enabled, public_broadcast, poll_interval_seconds,
                       created_at, last_polled_at, initialized_at, last_error,
                       encrypted_credentials IS NOT NULL AS has_credentials
                FROM platforms ORDER BY name COLLATE NOCASE
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_platform(self, platform_id: int) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                """
                SELECT id, name, kind, endpoint, details_endpoint, program_name, enabled, public_broadcast, poll_interval_seconds,
                       created_at, last_polled_at, initialized_at, last_error,
                       encrypted_credentials IS NOT NULL AS has_credentials
                FROM platforms WHERE id = ?
                """,
                (platform_id,),
            ).fetchone()
        if row is None:
            raise KeyError("Platform connection not found")
        return dict(row)

    def get_platform_for_scan(self, platform_id: int) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            row = connection.execute("SELECT * FROM platforms WHERE id = ?", (platform_id,)).fetchone()
        if row is None:
            raise KeyError("Platform connection not found")
        return dict(row)

    def due_platforms(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        due: list[dict[str, Any]] = []
        with self._lock, self._connection() as connection:
            rows = connection.execute("SELECT * FROM platforms WHERE enabled = 1").fetchall()
        for row in rows:
            platform = dict(row)
            last = platform["last_polled_at"]
            if not last:
                due.append(platform)
                continue
            try:
                last_polled = datetime.fromisoformat(last)
            except ValueError:
                due.append(platform)
                continue
            if (now - last_polled).total_seconds() >= platform["poll_interval_seconds"]:
                due.append(platform)
        return due

    def record_scan_error(self, platform_id: int, message: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE platforms SET last_polled_at = ?, last_error = ? WHERE id = ?",
                (utc_now(), message[:500], platform_id),
            )

    def save_scan(self, platform_id: int, assets: list[TargetAsset]) -> tuple[bool, list[dict[str, Any]]]:
        """Persist a successful non-empty snapshot and return changed target events."""
        if not assets:
            raise ValueError("Refusing to replace a scope snapshot with zero parsed assets")

        seen_at = utc_now()
        with self._lock, self._connection() as connection:
            platform = connection.execute(
                "SELECT initialized_at FROM platforms WHERE id = ?", (platform_id,)
            ).fetchone()
            if platform is None:
                raise KeyError("Platform connection not found")
            is_first_snapshot = platform["initialized_at"] is None

            current_rows = connection.execute(
                "SELECT * FROM assets WHERE platform_id = ?", (platform_id,)
            ).fetchall()
            current = {row["canonical_key"]: row for row in current_rows}
            seen_keys: set[str] = set()
            events: list[dict[str, Any]] = []

            for asset in deduplicate_assets(assets).values():
                key = asset.key
                seen_keys.add(key)
                previous = current.get(key)
                if previous is None:
                    cursor = connection.execute(
                        """
                        INSERT INTO assets (
                            platform_id, program, identifier, asset_type, source_url, canonical_key,
                            first_seen_at, last_seen_at, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                        """,
                        (
                            platform_id,
                            asset.program,
                            asset.identifier,
                            asset.asset_type,
                            asset.source_url,
                            key,
                            seen_at,
                            seen_at,
                        ),
                    )
                    asset_id = int(cursor.lastrowid)
                    event_type = "added"
                else:
                    asset_id = int(previous["id"])
                    event_type = "reintroduced" if not previous["is_active"] else ""
                    connection.execute(
                        """
                        UPDATE assets SET program = ?, identifier = ?, asset_type = ?, source_url = ?,
                            last_seen_at = ?, is_active = 1 WHERE id = ?
                        """,
                        (asset.program, asset.identifier, asset.asset_type, asset.source_url, seen_at, asset_id),
                    )

                if event_type:
                    cursor = connection.execute(
                        "INSERT INTO target_events (asset_id, event_type, created_at) VALUES (?, ?, ?)",
                        (asset_id, event_type, seen_at),
                    )
                    events.append(
                        {
                            "id": int(cursor.lastrowid),
                            "event_type": event_type,
                            "created_at": seen_at,
                            "platform_id": platform_id,
                            "asset_id": asset_id,
                            "program": asset.program,
                            "identifier": asset.identifier,
                            "asset_type": asset.asset_type,
                            "source_url": asset.source_url,
                        }
                    )

            for key, previous in current.items():
                if key not in seen_keys and previous["is_active"]:
                    connection.execute("UPDATE assets SET is_active = 0 WHERE id = ?", (previous["id"],))

            connection.execute(
                """
                UPDATE platforms SET last_polled_at = ?, initialized_at = COALESCE(initialized_at, ?),
                    last_error = NULL WHERE id = ?
                """,
                (seen_at, seen_at, platform_id),
            )
        return is_first_snapshot, events

    def latest_events(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT e.id, e.event_type, e.created_at, a.program, a.identifier, a.asset_type,
                       a.source_url, p.name AS platform
                FROM target_events AS e
                JOIN assets AS a ON a.id = e.asset_id
                JOIN platforms AS p ON p.id = a.platform_id
                ORDER BY e.created_at DESC LIMIT ?
                """,
                (min(max(limit, 1), 100),),
            ).fetchall()
        return [dict(row) for row in rows]

    def assets(self, *, asset_type: str | None = None, program: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        conditions = ["a.is_active = 1"]
        params: list[Any] = []
        if asset_type:
            conditions.append("a.asset_type = ? COLLATE NOCASE")
            params.append(asset_type)
        if program:
            conditions.append("a.program LIKE ? COLLATE NOCASE")
            params.append(f"%{program}%")
        params.append(min(max(limit, 1), 500))
        where = " AND ".join(conditions)
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT a.id, a.program, a.identifier, a.asset_type, a.source_url,
                       a.first_seen_at, a.last_seen_at, p.name AS platform
                FROM assets AS a JOIN platforms AS p ON p.id = a.platform_id
                WHERE {where} ORDER BY a.first_seen_at DESC LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def today_count(self) -> int:
        today = datetime.now(UTC).date().isoformat()
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM target_events WHERE substr(created_at, 1, 10) = ?", (today,)
            ).fetchone()
        return int(row["count"])

    def stats(self) -> dict[str, int]:
        with self._lock, self._connection() as connection:
            active = connection.execute("SELECT COUNT(*) AS count FROM assets WHERE is_active = 1").fetchone()
            platforms = connection.execute("SELECT COUNT(*) AS count FROM platforms WHERE enabled = 1").fetchone()
        return {"active_targets": int(active["count"]), "enabled_platforms": int(platforms["count"]), "today": self.today_count()}

    @staticmethod
    def _token_hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def create_web_setup_session(self, chat_id: str, expires_seconds: int) -> str:
        """Create a one-time code that links a Mini App to an already-open bot chat.

        The code carries no API credential and is stored only as a hash.
        """
        code = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        expires_at = (now + timedelta(seconds=expires_seconds)).isoformat()
        with self._lock, self._connection() as connection:
            connection.execute("DELETE FROM web_setup_sessions WHERE expires_at < ?", (now.isoformat(),))
            connection.execute(
                "INSERT INTO web_setup_sessions (code_hash, chat_id, expires_at) VALUES (?, ?, ?)",
                (self._token_hash(code), chat_id, expires_at),
            )
        return code

    def consume_web_setup_session(self, code: str) -> str | None:
        now = utc_now()
        code_hash = self._token_hash(code)
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT chat_id, expires_at, consumed_at FROM web_setup_sessions WHERE code_hash = ?", (code_hash,)
            ).fetchone()
            if row is None or row["consumed_at"] is not None or row["expires_at"] < now:
                return None
            connection.execute("UPDATE web_setup_sessions SET consumed_at = ? WHERE code_hash = ?", (now, code_hash))
            return str(row["chat_id"])

    def create_relay_agent(self, owner_chat_id: str) -> tuple[str, str]:
        """Create credentials for a client-owned polling agent, never for an API key."""
        agent_id = secrets.token_urlsafe(18)
        agent_secret = secrets.token_urlsafe(36)
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO relay_agents (id, owner_chat_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
                (agent_id, owner_chat_id, self._token_hash(agent_secret), utc_now()),
            )
        return agent_id, agent_secret

    def accept_relay_event(self, agent_id: str, agent_secret: str, event_id: str) -> str | None:
        """Authenticate an agent and atomically de-duplicate its outgoing event."""
        with self._lock, self._connection() as connection:
            agent = connection.execute(
                "SELECT owner_chat_id, secret_hash, enabled FROM relay_agents WHERE id = ?", (agent_id,)
            ).fetchone()
            if agent is None or not agent["enabled"]:
                return None
            if not secrets.compare_digest(agent["secret_hash"], self._token_hash(agent_secret)):
                return None
            try:
                connection.execute(
                    "INSERT INTO relay_event_ids (agent_id, event_id, created_at) VALUES (?, ?, ?)",
                    (agent_id, event_id, utc_now()),
                )
            except sqlite3.IntegrityError:
                return ""
            connection.execute("UPDATE relay_agents SET last_seen_at = ? WHERE id = ?", (utc_now(), agent_id))
            return str(agent["owner_chat_id"])

    def relay_agent_owner(self, agent_id: str, agent_secret: str) -> str | None:
        with self._lock, self._connection() as connection:
            agent = connection.execute(
                "SELECT owner_chat_id, secret_hash, enabled FROM relay_agents WHERE id = ?", (agent_id,)
            ).fetchone()
            if agent is None or not agent["enabled"]:
                return None
            if not secrets.compare_digest(agent["secret_hash"], self._token_hash(agent_secret)):
                return None
            connection.execute("UPDATE relay_agents SET last_seen_at = ? WHERE id = ?", (utc_now(), agent_id))
            return str(agent["owner_chat_id"])

    def release_relay_event(self, agent_id: str, event_id: str) -> None:
        """Allow a local agent to retry when Telegram delivery was unavailable."""
        with self._lock, self._connection() as connection:
            connection.execute(
                "DELETE FROM relay_event_ids WHERE agent_id = ? AND event_id = ?", (agent_id, event_id)
            )

    def save_relay_program(self, owner_chat_id: str, program_name: str, details: dict[str, Any]) -> None:
        key = program_name.strip().casefold()
        if not key:
            raise ValueError("Program name is required")
        stored = json.dumps(details, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO relay_programs (owner_chat_id, program_key, details_json, last_refreshed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(owner_chat_id, program_key) DO UPDATE SET
                    details_json = excluded.details_json, last_refreshed_at = excluded.last_refreshed_at
                """,
                (owner_chat_id, key, stored, utc_now()),
            )

    def relay_program(self, owner_chat_id: str, program_name: str) -> dict[str, Any] | None:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                """
                SELECT details_json, last_refreshed_at FROM relay_programs
                WHERE owner_chat_id = ? AND program_key = ?
                """,
                (owner_chat_id, program_name.strip().casefold()),
            ).fetchone()
        if row is None:
            return None
        details = json.loads(row["details_json"])
        details["last_refreshed_at"] = row["last_refreshed_at"]
        return details

    def relay_programs(self, owner_chat_id: str, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT details_json, last_refreshed_at FROM relay_programs
                WHERE owner_chat_id = ? ORDER BY last_refreshed_at DESC LIMIT ?
                """,
                (owner_chat_id, max(limit, 1)),
            ).fetchall()
        programs: list[dict[str, Any]] = []
        for row in rows:
            details = json.loads(row["details_json"])
            details["last_refreshed_at"] = row["last_refreshed_at"]
            programs.append(details)
        return programs

    # ── Relay Targets (bulk target list for /program command) ──────────────────

    def save_relay_targets(self, owner_chat_id: str, program_name: str, targets: list[dict[str, Any]]) -> None:
        """Replace the stored target snapshot for a program (called by client agent bulk sync)."""
        key = program_name.strip().casefold()
        if not key:
            raise ValueError("Program name is required")
        now = utc_now()
        with self._lock, self._connection() as connection:
            # Replace entire snapshot atomically
            connection.execute(
                "DELETE FROM relay_targets WHERE owner_chat_id = ? AND program_key = ?",
                (owner_chat_id, key),
            )
            for target in targets:
                identifier = (target.get("identifier") or "").strip()
                from adapters import normalize_asset_type
                asset_type = normalize_asset_type((target.get("asset_type") or "Other").strip())
                if not identifier:
                    continue
                # Store extra details in JSON
                details = {
                    "coverage": target.get("coverage"),
                    "max_severity": target.get("max_severity"),
                    "bounty_eligible": target.get("bounty_eligible"),
                    "updated_at": target.get("updated_at"),
                    "resolved_reports": target.get("resolved_reports"),
                }
                details_json = json.dumps(details)
                
                connection.execute(
                    """
                    INSERT INTO relay_targets
                        (owner_chat_id, program_key, identifier, asset_type, source_url, first_seen_at, last_seen_at, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (owner_chat_id, key, identifier, asset_type or "Other",
                     target.get("source_url"), now, now, details_json),
                )

    def get_all_relay_target_keys(self, owner_chat_id: str, program_name: str) -> set[str]:
        """Return a set of all target keys for a given program to efficiently detect new assets."""
        key = program_name.strip().casefold()
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                "SELECT identifier, asset_type FROM relay_targets WHERE owner_chat_id = ? AND program_key = ?",
                (owner_chat_id, key),
            ).fetchall()

        from adapters import normalize_asset_type
        keys = set()
        for r in rows:
            raw_type = r['asset_type'].strip()
            mapped_type = normalize_asset_type(raw_type)
            keys.add(f"{r['identifier'].strip().casefold()}|{mapped_type.casefold()}")

        return keys

    def search_relay_targets(
        self,
        owner_chat_id: str,
        query: str,
        offset: int = 0,
        limit: int = 10,
    ) -> tuple[list[dict[str, Any]], int]:
        """Search all targets for a user using LIKE %query% (case-insensitive)."""
        safe_limit = min(max(int(limit), 1), 100)
        safe_offset = max(int(offset), 0)
        
        # Replace explicit wildcards * with SQL % and wrap with %
        sql_query = f"%{query.replace('*', '%')}%"
        
        conditions = "owner_chat_id = ? AND identifier LIKE ?"
        params = [owner_chat_id, sql_query]
        
        with self._lock, self._connection() as connection:
            count_row = connection.execute(
                f"SELECT COUNT(*) AS n FROM relay_targets WHERE {conditions}", params
            ).fetchone()
            total = int(count_row["n"])
            
            rows = connection.execute(
                f"""
                SELECT program_name, identifier, asset_type, source_url, first_seen_at, details_json
                FROM relay_targets 
                WHERE {conditions}
                ORDER BY identifier ASC
                LIMIT ? OFFSET ?
                """,
                params + [safe_limit, safe_offset]
            ).fetchall()
            
            out = []
            for r in rows:
                d = dict(r)
                if d.get("details_json"):
                    try:
                        d.update(json.loads(d["details_json"]))
                    except Exception:
                        pass
                out.append(d)
            return out, total

    def get_relay_targets(
        self,
        owner_chat_id: str,
        program_name: str | None = None,
        *,
        asset_type: str | None = None,
        offset: int = 0,
        limit: int = 10,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return paginated targets and total count for a program (or all if None)."""
        conditions = ["owner_chat_id = ?"]
        params: list[Any] = [owner_chat_id]
        if program_name:
            key = program_name.strip().casefold()
            conditions.append("program_key = ?")
            params.append(key)
        if asset_type:
            conditions.append("asset_type = ? COLLATE NOCASE")
            params.append(asset_type)
        where = " AND ".join(conditions)
        safe_limit = min(max(int(limit), 1), 100000)
        safe_offset = max(int(offset), 0)
        with self._lock, self._connection() as connection:
            count_row = connection.execute(
                f"SELECT COUNT(*) AS n FROM relay_targets WHERE {where}", params
            ).fetchone()
            total = int(count_row["n"])
            rows = connection.execute(
                f"""
                SELECT t.program_key, t.identifier, t.asset_type, t.source_url, t.first_seen_at, t.details_json,
                       (SELECT p.details_json FROM relay_programs p WHERE p.owner_chat_id = t.owner_chat_id AND p.program_key = t.program_key LIMIT 1) as p_details_json
                FROM relay_targets t WHERE {where.replace('owner_chat_id', 't.owner_chat_id').replace('program_key', 't.program_key').replace('asset_type', 't.asset_type')}
                ORDER BY t.asset_type COLLATE NOCASE, t.identifier COLLATE NOCASE
                LIMIT ? OFFSET ?
                """,
                params + [safe_limit, safe_offset],
            ).fetchall()
            
        results = []
        for row in rows:
            d = dict(row)
            
            # Try to get the properly cased program name
            d["program_name"] = d.get("program_key", "Unknown")
            if d.get("p_details_json"):
                try:
                    p_details = json.loads(d.pop("p_details_json"))
                    if "program" in p_details:
                        d["program_name"] = p_details["program"]
                except Exception:
                    pass
            elif "p_details_json" in d:
                del d["p_details_json"]
            
            if d.get("details_json"):
                details = json.loads(d["details_json"])
                d.update(details)
            results.append(d)
            
        return results, total

    def get_relay_target_asset_types(self, owner_chat_id: str, program_name: str | None = None) -> list[str]:
        """Return distinct asset types present for a program (or all programs if None)."""
        with self._lock, self._connection() as connection:
            if program_name:
                key = program_name.strip().casefold()
                rows = connection.execute(
                    """
                    SELECT DISTINCT asset_type FROM relay_targets
                    WHERE owner_chat_id = ? AND program_key = ?
                    ORDER BY asset_type COLLATE NOCASE
                    """,
                    (owner_chat_id, key),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT DISTINCT asset_type FROM relay_targets
                    WHERE owner_chat_id = ?
                    ORDER BY asset_type COLLATE NOCASE
                    """,
                    (owner_chat_id,),
                ).fetchall()
        return [row["asset_type"] for row in rows]

    # ── User Connections (Server-side 24/7 Scanning) ──────────────────────────

    def save_user_connection(
        self,
        owner_chat_id: str,
        platform: str,
        program_name: str,
        endpoint: str,
        details_endpoint: str | None,
        credential_identifier: str | None,
        encrypted_token: str | None,
        poll_interval_seconds: int = 300,
    ) -> str:
        """Save a user's program connection with encrypted API token for server-side 24/7 scanning."""
        conn_id = secrets.token_urlsafe(16)
        now = utc_now()
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO user_connections
                    (id, owner_chat_id, platform, program_name, endpoint, details_endpoint,
                     credential_identifier, encrypted_token, poll_interval_seconds, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    conn_id,
                    owner_chat_id,
                    platform,
                    program_name.strip(),
                    endpoint.strip(),
                    details_endpoint.strip() if details_endpoint else None,
                    credential_identifier.strip() if credential_identifier else None,
                    encrypted_token,
                    max(60, min(poll_interval_seconds, 86400)),
                    now,
                ),
            )
        return conn_id

    def get_user_connections(self, owner_chat_id: str) -> list[dict[str, Any]]:
        """Return user connections (excluding sensitive tokens)."""
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, platform, program_name, endpoint, details_endpoint,
                       credential_identifier, poll_interval_seconds, last_scanned_at, created_at
                FROM user_connections
                WHERE owner_chat_id = ? AND enabled = 1
                ORDER BY created_at DESC
                """,
                (owner_chat_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_user_connections_with_tokens(self, owner_chat_id: str) -> list[dict[str, Any]]:
        """Return user connections including sensitive encrypted tokens."""
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, platform, program_name, endpoint, details_endpoint,
                       credential_identifier, encrypted_token, poll_interval_seconds, last_scanned_at, created_at
                FROM user_connections
                WHERE owner_chat_id = ? AND enabled = 1
                ORDER BY created_at DESC
                """,
                (owner_chat_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_user_connection(self, owner_chat_id: str, connection_id: str) -> bool:
        """Delete a user connection."""
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM user_connections WHERE owner_chat_id = ? AND id = ?",
                (owner_chat_id, connection_id),
            )
            return cursor.rowcount > 0

    def due_user_connections(self) -> list[dict[str, Any]]:
        """Return user connections that are due for scanning."""
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, owner_chat_id, platform, program_name, endpoint, details_endpoint,
                       credential_identifier, encrypted_token, poll_interval_seconds, last_scanned_at
                FROM user_connections
                WHERE enabled = 1
                  AND (
                    last_scanned_at IS NULL
                    OR strftime('%s', 'now') - strftime('%s', last_scanned_at) >= poll_interval_seconds
                  )
                ORDER BY last_scanned_at ASC
                LIMIT 20
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def update_user_connection_scan_time(self, connection_id: str) -> None:
        """Record scan completion time for a user connection."""
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE user_connections SET last_scanned_at = ? WHERE id = ?",
                (utc_now(), connection_id),
            )
