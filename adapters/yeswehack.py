"""YesWeHack scope adapter.

Accepts the YesWeHack Researcher API endpoint for a program's scope:
  GET https://api.yeswehack.com/programs/{slug}/user-scope
  Authorization: Bearer {jwt_token}
"""

from __future__ import annotations

from typing import Any

import aiohttp

from models import TargetAsset


class YesWeHackAdapter:
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
        # YesWeHack uses Bearer JWT token
        self.token = credential_token
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def fetch_assets(self) -> list[TargetAsset]:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "h1-target-monitor/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        async with aiohttp.ClientSession(timeout=self.timeout, headers=headers) as session:
            async with session.get(self.endpoint, allow_redirects=False) as response:
                if response.status in {401, 403}:
                    raise PermissionError("YesWeHack rejected the configured API credentials")
                if response.status >= 400:
                    body = (await response.text())[:300]
                    raise RuntimeError(f"YesWeHack endpoint returned HTTP {response.status}: {body}")
                payload = await response.json(content_type=None)

        return self._parse(payload)

    def _parse(self, payload: Any) -> list[TargetAsset]:
        assets: dict[str, TargetAsset] = {}

        # YesWeHack format: {"items": [{"scope": "*.example.com", "scope_type": "web-application"}]}
        # Also supports: {"scopes": [...]} or flat list
        items: list = []
        if isinstance(payload, dict):
            items = payload.get("items") or payload.get("scopes") or payload.get("data") or []
        elif isinstance(payload, list):
            items = payload

        for item in items:
            if not isinstance(item, dict):
                continue

            identifier = (
                item.get("scope") or item.get("target") or item.get("endpoint") or ""
            ).strip()
            if not identifier:
                continue

            raw_type = item.get("scope_type") or item.get("type") or item.get("asset_type") or "Other"
            asset_type = self._map_type(str(raw_type))
            asset = TargetAsset(
                program=self.program_name,
                identifier=identifier,
                asset_type=asset_type,
                source_url=self.endpoint,
            )
            assets[asset.key] = asset

        return list(assets.values())

    @staticmethod
    def _map_type(raw: str) -> str:
        from adapters import normalize_asset_type
        return normalize_asset_type(raw)

    @classmethod
    async def fetch_all_programs(
        cls,
        credential_identifier: str | None,
        credential_token: str | None,
        timeout_seconds: int = 30,
    ) -> list[dict[str, str]]:
        if not credential_token:
            raise ValueError("YesWeHack requires an API token (JWT) to fetch programs.")
        
        headers = {
            "Accept": "application/json",
            "User-Agent": "h1-target-monitor/1.0",
            "Authorization": f"Bearer {credential_token}"
        }
        url = "https://api.yeswehack.com/programs"
        programs = []

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_seconds), headers=headers) as session:
            while url:
                async with session.get(url, allow_redirects=False) as response:
                    if response.status in {401, 403}:
                        raise PermissionError("YesWeHack rejected the configured API credentials")
                    if response.status >= 400:
                        body = (await response.text())[:300]
                        raise RuntimeError(f"YesWeHack endpoint returned HTTP {response.status}: {body}")
                    
                    data = await response.json()
                    
                    items = data.get("items") or data.get("data") or []
                    if not items and isinstance(data, list):
                        items = data
                        
                    for item in items:
                        if isinstance(item, dict):
                            slug = item.get("slug")
                            title = item.get("title") or item.get("name")
                            if slug:
                                programs.append({
                                    "handle": slug,
                                    "name": title or slug
                                })
                    
                    # Basic pagination support (if any)
                    links = data.get("links", {}) if isinstance(data, dict) else {}
                    next_url = links.get("next")
                    url = next_url if next_url and next_url != url else None
                    
        return programs
