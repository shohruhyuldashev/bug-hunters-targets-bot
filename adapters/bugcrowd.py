"""Bugcrowd scope adapter.

Accepts either:
  - Public JSON endpoint: https://bugcrowd.com/{slug}/target_groups.json
  - Or configured HTTPS endpoint returning Bugcrowd-style JSON or HTML scope

Bugcrowd does not require authentication for public programs.
For private programs, pass an API token as credential_token.
"""

from __future__ import annotations

from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from models import TargetAsset


class BugcrowdAdapter:
    def __init__(
        self,
        *,
        endpoint: str,
        program_name: str,
        credential_identifier: str | None,
        credential_token: str | None,
        timeout_seconds: int,
    ) -> None:
        self.endpoint = endpoint
        self.program_name = program_name
        self.token = credential_token
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    @classmethod
    async def fetch_all_programs(
        cls,
        credential_identifier: str | None,
        credential_token: str | None,
        timeout_seconds: int = 30,
    ) -> list[dict[str, str]]:
        """Fetch all Bugcrowd programs accessible by the researcher.
        Uses the public Bugcrowd programs listing endpoint with optional API token.
        Returns a list of dicts with 'handle' and 'name'.
        """
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "h1-target-monitor/1.0",
        }
        if credential_token:
            headers["Authorization"] = f"Token {credential_token}"

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        programs = []
        url: str | None = "https://bugcrowd.com/programs.json"

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            while url:
                async with session.get(url, allow_redirects=True) as response:
                    if response.status in {401, 403}:
                        raise PermissionError("Bugcrowd rejected the configured API credentials")
                    if response.status >= 400:
                        break  # Silently stop — endpoint may not exist or require auth
                    content_type = response.headers.get("Content-Type", "").lower()
                    if "json" not in content_type:
                        break

                    import json as _json
                    data = await response.json(content_type=None)

                    # programs.json returns {"programs": [{...}]} or flat list
                    items = data if isinstance(data, list) else (data.get("programs") or data.get("data") or [])
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        slug = item.get("program_url", "").lstrip("/") or item.get("code") or item.get("slug")
                        name = item.get("name") or item.get("program_name") or slug
                        if slug:
                            programs.append({"handle": slug, "name": name or slug})

                    # Pagination
                    links = data.get("links", {}) if isinstance(data, dict) else {}
                    meta = data.get("meta", {}) if isinstance(data, dict) else {}
                    next_url = links.get("next") or meta.get("next_url")
                    url = next_url if next_url and next_url != url else None

        return programs

    async def fetch_assets(self) -> list[TargetAsset]:
        headers: dict[str, str] = {
            "Accept": "application/json, text/html",
            "User-Agent": "h1-target-monitor/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Token {self.token}"

        async with aiohttp.ClientSession(timeout=self.timeout, headers=headers) as session:
            async with session.get(self.endpoint, allow_redirects=False) as response:
                if response.status in {401, 403}:
                    raise PermissionError("Bugcrowd rejected the configured API credentials")
                if response.status >= 400:
                    body = (await response.text())[:300]
                    raise RuntimeError(f"Bugcrowd endpoint returned HTTP {response.status}: {body}")
                content_type = response.headers.get("Content-Type", "").lower()
                body = await response.text()

        if "json" in content_type:
            try:
                import json
                payload = json.loads(body)
            except Exception as exc:
                raise RuntimeError("Bugcrowd endpoint returned invalid JSON") from exc
            return self._parse_json(payload)
        if "html" in content_type:
            return self._parse_html(body)
        raise RuntimeError("Bugcrowd endpoint must return JSON or HTML")

    def _parse_json(self, payload: Any) -> list[TargetAsset]:
        assets: dict[str, TargetAsset] = {}

        # Format 1: {"target_groups": [{"name": "In Scope", "targets": [...]}]}
        groups = None
        if isinstance(payload, dict):
            groups = payload.get("target_groups") or payload.get("groups")
        if groups and isinstance(groups, list):
            for group in groups:
                name = (group.get("name") or "").lower()
                # Skip out-of-scope groups
                if any(word in name for word in ("out of scope", "out_of_scope", "excluded")):
                    continue
                targets = group.get("targets") or []
                for t in targets:
                    asset = self._item_to_asset(t)
                    if asset:
                        assets[asset.key] = asset
            return list(assets.values())

        # Format 2: flat list of targets
        items = payload if isinstance(payload, list) else []
        if not items and isinstance(payload, dict):
            items = payload.get("targets") or payload.get("data") or []
        for item in items:
            asset = self._item_to_asset(item)
            if asset:
                assets[asset.key] = asset
        return list(assets.values())

    def _item_to_asset(self, item: Any) -> TargetAsset | None:
        if not isinstance(item, dict):
            return None
        identifier = (item.get("name") or item.get("target") or item.get("uri") or "").strip()
        if not identifier:
            return None
        raw_type = item.get("category") or item.get("type") or item.get("asset_type") or "Other"
        asset_type = self._map_type(str(raw_type))
        return TargetAsset(
            program=self.program_name,
            identifier=identifier,
            asset_type=asset_type,
            source_url=self.endpoint,
        )

    def _parse_html(self, html: str) -> list[TargetAsset]:
        """Fallback HTML parser for public Bugcrowd program pages."""
        soup = BeautifulSoup(html, "html.parser")
        assets: dict[str, TargetAsset] = {}
        for node in soup.select("[data-asset-identifier]"):
            identifier = (node.get("data-asset-identifier") or "").strip()
            if identifier:
                asset = TargetAsset(
                    program=self.program_name,
                    identifier=identifier,
                    asset_type=(node.get("data-asset-type") or "Other").strip(),
                    source_url=self.endpoint,
                )
                assets[asset.key] = asset
        return list(assets.values())

    @staticmethod
    def _map_type(raw: str) -> str:
        from adapters import normalize_asset_type
        return normalize_asset_type(raw)
