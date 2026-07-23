"""Client-owned target monitor agent — multi-platform edition.

Run this on the user's own PC/VPS/Raspberry Pi. Platform credentials are read
only from the local JSON configuration and are never included in relay calls.

Supported platforms: HackerOne, Intigriti, YesWeHack, Bugcrowd
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from bs4 import BeautifulSoup


LOG = logging.getLogger("target-monitor-agent")


@dataclass(frozen=True)
class Asset:
    identifier: str
    asset_type: str

    @property
    def key(self) -> str:
        return f"{self.identifier.strip().casefold()}|{self.asset_type.strip().casefold()}"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _walk(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


# ── Platform-specific parsers ─────────────────────────────────────────────────

def _first(obj: dict, *keys: str) -> Any:
    for k in keys:
        v = obj.get(k)
        if v not in (None, "", []):
            return v
    return None


def parse_hackerone(payload: Any) -> list[Asset]:
    """HackerOne structured_scope JSON or HTML."""
    if isinstance(payload, str):
        return _parse_html(payload)
    found: dict[str, Asset] = {}
    for item in _walk(payload):
        data = item.get("attributes") if isinstance(item.get("attributes"), dict) else item
        identifier = data.get("asset_identifier")
        if not isinstance(identifier, str) or not identifier.strip():
            continue
        asset_type = str(
            data.get("asset_type") or data.get("asset_type_name") or data.get("type") or "Other"
        ).strip()
        asset = Asset(identifier.strip(), asset_type or "Other")
        found[asset.key] = asset
    return list(found.values())


def parse_intigriti(payload: Any) -> list[Asset]:
    """Intigriti v2 API: {content: [{endpoint, type, tier}]}"""
    if isinstance(payload, str):
        return _parse_html(payload)
    found: dict[str, Asset] = {}

    # Support both {"content": [...]} and flat list
    items: list = []
    if isinstance(payload, dict):
        items = payload.get("content") or payload.get("items") or payload.get("data") or []
    elif isinstance(payload, list):
        items = payload

    for item in items:
        if not isinstance(item, dict):
            continue
        tier = str(item.get("tier") or item.get("inScope") or "").lower()
        if tier in {"out_of_scope", "outofscope", "out_scope", "false"}:
            continue
        identifier = (item.get("endpoint") or item.get("target") or "").strip()
        if not identifier:
            continue
        raw_type = item.get("type") or item.get("assetType") or "Other"
        asset_type = _map_intigriti_type(str(raw_type))
        asset = Asset(identifier, asset_type)
        found[asset.key] = asset
    return list(found.values())


def _map_intigriti_type(raw: str) -> str:
    m = {
        "url": "URL", "web": "URL", "wildcard": "Wildcard", "domain": "Wildcard",
        "cidr": "CIDR", "ip": "CIDR", "android": "Android: Play Store",
        "ios": "Apple: App Store", "apple": "Apple: App Store",
        "mobile": "Mobile", "executable": "Other: Executable",
        "hardware": "Hardware/IoT", "other": "Other",
    }
    key = raw.lower().replace("_", "").replace("-", "").replace(" ", "")
    for pattern, mapped in m.items():
        if pattern in key:
            return mapped
    return raw or "Other"


def parse_yeswehack(payload: Any) -> list[Asset]:
    """YesWeHack API: {items: [{scope, scope_type}]}"""
    if isinstance(payload, str):
        return _parse_html(payload)
    found: dict[str, Asset] = {}

    items: list = []
    if isinstance(payload, dict):
        items = payload.get("items") or payload.get("scopes") or payload.get("data") or []
    elif isinstance(payload, list):
        items = payload

    for item in items:
        if not isinstance(item, dict):
            continue
        identifier = (item.get("scope") or item.get("target") or item.get("endpoint") or "").strip()
        if not identifier:
            continue
        raw_type = item.get("scope_type") or item.get("type") or "Other"
        asset_type = _map_yeswehack_type(str(raw_type))
        asset = Asset(identifier, asset_type)
        found[asset.key] = asset
    return list(found.values())


def _map_yeswehack_type(raw: str) -> str:
    m = {
        "web_application": "URL", "web-application": "URL", "webapp": "URL",
        "url": "URL", "wildcard": "Wildcard", "domain": "Wildcard",
        "mobile_application": "Mobile", "mobile-application": "Mobile",
        "android": "Android: Play Store", "ios": "Apple: App Store",
        "apple": "Apple: App Store", "ip": "CIDR", "cidr": "CIDR",
        "api": "URL", "other": "Other",
    }
    key = raw.lower().replace("-", "_")
    return m.get(key) or raw or "Other"


def parse_bugcrowd(payload: Any) -> list[Asset]:
    """Bugcrowd: {target_groups: [{name, targets: [{name, category}]}]} or flat list."""
    if isinstance(payload, str):
        return _parse_html(payload)
    found: dict[str, Asset] = {}

    if isinstance(payload, dict):
        groups = payload.get("target_groups") or payload.get("groups")
        if groups and isinstance(groups, list):
            for group in groups:
                name = str(group.get("name") or "").lower()
                if any(w in name for w in ("out of scope", "out_of_scope", "excluded")):
                    continue
                for t in group.get("targets") or []:
                    asset = _bugcrowd_item(t)
                    if asset:
                        found[asset.key] = asset
            return list(found.values())
        # Flat targets
        items = payload.get("targets") or payload.get("data") or []
    else:
        items = payload if isinstance(payload, list) else []

    for item in items:
        asset = _bugcrowd_item(item)
        if asset:
            found[asset.key] = asset
    return list(found.values())


def _bugcrowd_item(item: Any) -> Asset | None:
    if not isinstance(item, dict):
        return None
    identifier = (item.get("name") or item.get("target") or item.get("uri") or "").strip()
    if not identifier:
        return None
    raw_type = item.get("category") or item.get("type") or "Other"
    m = {
        "website": "URL", "web": "URL", "url": "URL", "api": "URL",
        "wildcard": "Wildcard", "android": "Android: Play Store",
        "ios": "Apple: App Store", "apple": "Apple: App Store",
        "mobile": "Mobile", "ip": "CIDR", "cidr": "CIDR",
        "hardware": "Hardware/IoT", "other": "Other",
    }
    key = str(raw_type).lower().replace(" ", "").replace("_", "").replace("-", "")
    asset_type = next((v for k, v in m.items() if k in key), raw_type or "Other")
    return Asset(identifier, asset_type)


def _parse_html(html: str) -> list[Asset]:
    """Generic HTML parser for any platform's public program page."""
    soup = BeautifulSoup(html, "html.parser")
    found: dict[str, Asset] = {}
    for node in soup.select("[data-asset-identifier]"):
        identifier = (node.get("data-asset-identifier") or "").strip()
        if identifier:
            asset = Asset(identifier, (node.get("data-asset-type") or "Other").strip())
            found[asset.key] = asset
    for table in soup.find_all("table"):
        headers = [cell.get_text(" ", strip=True).casefold() for cell in table.find_all("th")]
        id_idx = next(
            (i for i, h in enumerate(headers) if any(w in h for w in ("asset", "scope", "target", "domain", "url"))),
            None,
        )
        if id_idx is None:
            continue
        type_idx = next((i for i, h in enumerate(headers) if "type" in h), None)
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) <= id_idx:
                continue
            identifier = cells[id_idx].get_text(" ", strip=True)
            if not identifier:
                continue
            asset_type = cells[type_idx].get_text(" ", strip=True) if type_idx and len(cells) > type_idx else "Other"
            asset = Asset(identifier, asset_type or "Other")
            found[asset.key] = asset
    return list(found.values())


# Platform dispatch table
_PLATFORM_PARSERS = {
    "hackerone": parse_hackerone,
    "h1": parse_hackerone,
    "intigriti": parse_intigriti,
    "yeswehack": parse_yeswehack,
    "ywh": parse_yeswehack,
    "bugcrowd": parse_bugcrowd,
    "bc": parse_bugcrowd,
}


def parse_assets_for_platform(platform: str, payload: Any) -> list[Asset]:
    key = platform.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
    parser = _PLATFORM_PARSERS.get(key, parse_hackerone)
    return parser(payload)


# ── Metadata parser (HackerOne focused) ───────────────────────────────────────

def first_metadata_value(payload: Any, names: tuple[str, ...]) -> Any:
    for item in _walk(payload):
        data = item.get("attributes") if isinstance(item.get("attributes"), dict) else item
        for name in names:
            value = data.get(name)
            if value not in (None, "", []):
                return value
    return None


def parse_metadata(payload: Any) -> dict[str, Any]:
    if isinstance(payload, str):
        return {}

    def string(*names: str) -> str | None:
        value = first_metadata_value(payload, names)
        return str(value) if value not in (None, "") else None

    def number(*names: str) -> int | None:
        value = first_metadata_value(payload, names)
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    return {
        "resolved_reports": number("resolved_reports", "resolved_reports_count", "number_of_resolved_reports"),
        "minimum_bounty": string("minimum_bounty", "min_bounty"),
        "average_bounty": string("average_bounty", "avg_bounty"),
        "maximum_bounty": string("maximum_bounty", "max_bounty"),
        "currency": string("currency", "bounty_currency"),
        "program_updated_at": string("program_updated_at", "last_program_updated_at"),
    }


# ── Agent ─────────────────────────────────────────────────────────────────────

class Agent:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.config = json.loads(config_path.read_text(encoding="utf-8"))
        self.relay = self.config["relay"]
        self.connections = self.config["connections"]
        self.state_path = config_path.with_suffix(config_path.suffix + ".state.json")
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"connections": {}}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raise RuntimeError(f"Invalid local state file: {self.state_path}")

    def _save_state(self) -> None:
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.state, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, self.state_path)
        try:
            os.chmod(self.state_path, 0o600)
        except OSError:
            pass

    async def fetch_source(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        auth: aiohttp.BasicAuth | None,
        token: str | None,
        program: str,
    ) -> Any:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise RuntimeError(f"{program}: endpoint must be an HTTPS URL without embedded credentials")

        headers: dict[str, str] = {}
        if token and not auth:
            # Bearer token (Intigriti, YesWeHack)
            headers["Authorization"] = f"Bearer {token}"

        async with session.get(endpoint, auth=auth, headers=headers, allow_redirects=False) as response:
            if response.status >= 400:
                raise RuntimeError(f"{program}: source returned HTTP {response.status}")
            content_type = response.headers.get("Content-Type", "").lower()
            if "json" in content_type:
                return await response.json(content_type=None)
            if "html" in content_type:
                return await response.text()
            raise RuntimeError(f"{program}: source must return JSON or HTML")

    async def fetch_snapshot(
        self, session: aiohttp.ClientSession, connection: dict[str, Any]
    ) -> tuple[list[Asset], dict[str, Any]]:
        endpoint = connection["endpoint"]
        program = connection["program"]
        platform = connection.get("platform", "hackerone").lower()
        identifier = connection.get("identifier") or ""
        token = connection.get("token") or ""

        # Auth strategy per platform:
        # HackerOne → HTTP Basic (identifier + token)
        # Intigriti / YesWeHack → Bearer token
        # Bugcrowd → Token header or none for public
        if identifier and token and platform in ("hackerone", "h1"):
            auth = aiohttp.BasicAuth(identifier, token)
            bearer_token = None
        else:
            auth = None
            bearer_token = token or None

        payload = await self.fetch_source(session, endpoint, auth, bearer_token, program)
        assets = parse_assets_for_platform(platform, payload)
        if not assets:
            raise RuntimeError(f"{program}: zero assets parsed; preserving prior local snapshot")

        details_endpoint = connection.get("details_endpoint") or endpoint
        details_payload = (
            payload if details_endpoint == endpoint
            else await self.fetch_source(session, details_endpoint, auth, bearer_token, program)
        )
        return assets, parse_metadata(details_payload)

    async def relay_post(self, session: aiohttp.ClientSession, path: str, data: dict[str, Any]) -> bool:
        url = self.relay["relay_url"].rstrip("/") + path
        headers = {
            "X-Agent-Secret": self.relay["agent_secret"],
            "Content-Type": "application/json",
        }
        async with session.post(
            url, headers=headers, json={"agent_id": self.relay["agent_id"], **data}
        ) as response:
            if response.status >= 400:
                LOG.warning("Relay rejected %s: HTTP %s", path, response.status)
                return False
        return True

    async def sync_connection(self, session: aiohttp.ClientSession, connection: dict[str, Any]) -> None:
        connection_id = connection["id"]
        program = connection["program"]
        platform = connection.get("platform", "HackerOne")

        assets, metadata = await self.fetch_snapshot(session, connection)
        connection_state = self.state.setdefault("connections", {}).setdefault(connection_id, {})
        prior_keys = set(connection_state.get("asset_keys", []))
        current = {asset.key: asset for asset in assets}
        is_first_snapshot = "asset_keys" not in connection_state
        pending: list[dict[str, str]] = connection_state.setdefault("pending", [])

        # Detect new targets
        if not is_first_snapshot:
            for key, asset in current.items():
                if key not in prior_keys:
                    pending.append(
                        {
                            "event_id": secrets.token_urlsafe(24),
                            "program": program,
                            "platform": platform,
                            "identifier": asset.identifier,
                            "asset_type": asset.asset_type,
                            "observed_at": utc_now(),
                        }
                    )

        connection_state["asset_keys"] = sorted(current)
        connection_state["last_success_at"] = utc_now()
        self._save_state()

        # 1. Send program summary
        summary = {
            "program": program,
            "platform": platform,
            "scope_count": len(current),
            "asset_types": dict(Counter(asset.asset_type for asset in assets)),
            **metadata,
        }
        await self.relay_post(session, "/programs", summary)

        # 2. Bulk sync full target list (for /program command in bot)
        target_list = [
            {"identifier": a.identifier, "asset_type": a.asset_type}
            for a in assets
        ]
        await self.relay_post(session, "/targets", {"program": program, "platform": platform, "targets": target_list})

        # 3. Send pending new-target notifications
        still_pending: list[dict[str, str]] = []
        for event in pending:
            if not await self.relay_post(session, "/events", event):
                still_pending.append(event)
        connection_state["pending"] = still_pending
        self._save_state()

        if is_first_snapshot:
            LOG.info("%s [%s] baseline saved: %s targets — no notifications", program, platform, len(current))
        else:
            new_count = len(pending) - len(still_pending)
            LOG.info("%s [%s] synced: %s targets, %s new notification(s)", program, platform, len(current), new_count)

    async def run(self) -> None:
        timeout = aiohttp.ClientTimeout(total=30)
        last_run: dict[str, float] = {}
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "target-monitor-client-agent/2.0"},
        ) as session:
            while True:
                now = asyncio.get_running_loop().time()
                for connection in self.connections:
                    interval = max(60, int(connection.get("interval", 300)))
                    if now - last_run.get(connection["id"], 0) < interval:
                        continue
                    last_run[connection["id"]] = now
                    try:
                        await self.sync_connection(session, connection)
                    except Exception as exc:
                        LOG.warning("[%s] %s", connection.get("program", "?"), exc)
                await asyncio.sleep(5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-platform Target Monitor Agent")
    parser.add_argument("--config", required=True, type=Path, help="JSON config from Telegram Mini App")
    args = parser.parse_args()
    if not args.config.exists():
        raise SystemExit(f"Config not found: {args.config}")
    if os.name != "nt" and args.config.stat().st_mode & 0o077:
        LOG.warning("Config permissions are broad. Recommended: chmod 600 %s", args.config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(Agent(args.config).run())


if __name__ == "__main__":
    main()
