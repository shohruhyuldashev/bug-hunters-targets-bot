"""Intigriti scope adapter.

Accepts the Intigriti Researcher API v2 endpoint for a program's scope:
  GET https://api.intigriti.com/core/researcher/program/{companyHandle}/{programHandle}/targets
  Authorization: Bearer {token}
"""

from __future__ import annotations

from typing import Any

import aiohttp

from models import TargetAsset


class IntigritiAdapter:
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
        # Intigriti uses Bearer token only; identifier field is ignored
        self.token = credential_token
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    @classmethod
    async def fetch_all_programs(
        cls,
        credential_identifier: str,
        credential_token: str,
        timeout_seconds: int = 30,
    ) -> list[dict[str, str]]:
        """Fetch all Intigriti programs the researcher has access to.
        Returns a list of dicts with 'handle' ({companyHandle}/{programHandle}) and 'name'.
        """
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "h1-target-monitor/1.0",
        }
        if credential_token:
            headers["Authorization"] = f"Bearer {credential_token}"

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        programs = []
        offset = 0
        limit = 100

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            while True:
                url = f"https://api.intigriti.com/external/researcher/v1/programs?limit={limit}&offset={offset}"
                async with session.get(url, allow_redirects=False) as response:
                    if response.status >= 400:
                        break
                    payload = await response.json(content_type=None)

                records = payload.get("records") if isinstance(payload, dict) else payload
                if not isinstance(records, list) or not records:
                    break

                for p in records:
                    if isinstance(p, dict):
                        prog_id = p.get("id")
                        name = p.get("name") or p.get("handle")
                        if prog_id:
                            programs.append({
                                "handle": prog_id,
                                "name": name
                            })
                
                offset += limit
                
        return programs

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
                    raise PermissionError("Intigriti rejected the configured API credentials")
                if response.status >= 400:
                    body = (await response.text())[:300]
                    raise RuntimeError(f"Intigriti endpoint returned HTTP {response.status}: {body}")
                payload = await response.json(content_type=None)

        return self._parse(payload)

    def _parse(self, payload: Any) -> list[TargetAsset]:
        assets: dict[str, TargetAsset] = {}

        # Intigriti external v1: {"domains": {"content": [{"endpoint": "...", "type": {"value": "url"}, "tier": {"value": "in scope"}}]}}
        domains = payload.get("domains") if isinstance(payload, dict) else None
        content = domains.get("content") if isinstance(domains, dict) else None
        if content is None:
            content = payload.get("content") if isinstance(payload, dict) else None
        if content is None:
            # Try flat list
            content = payload if isinstance(payload, list) else []

        for item in content:
            if not isinstance(item, dict):
                continue
            # Skip out-of-scope items
            tier_val = item.get("tier") or item.get("inScope") or ""
            if isinstance(tier_val, dict):
                tier_val = tier_val.get("value", "")
            tier = str(tier_val).lower()
            if tier in {"out_of_scope", "outofscope", "out_scope", "false", "out of scope"}:
                continue

            identifier = (item.get("endpoint") or item.get("target") or "").strip()
            if not identifier:
                continue

            raw_type = item.get("type") or item.get("assetType") or "Other"
            if isinstance(raw_type, dict):
                raw_type = raw_type.get("value", "Other")
            
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
