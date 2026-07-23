"""HackerOne API/page source adapter.

The endpoint is configured per connection because scope visibility depends on
the account, program, and permissions granted to its API token. It accepts
either a permitted JSON API response or a public/authorized program page. The
page parser only consumes scope data rendered in the returned HTML; it never
attempts to bypass access controls or login barriers.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from models import TargetAsset


class HackerOneAdapter:
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
        self.credential_identifier = credential_identifier
        self.credential_token = credential_token
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def fetch_assets(self) -> list[TargetAsset]:
        auth = None
        if self.credential_identifier and self.credential_token:
            # HackerOne API tokens use HTTP Basic auth: identifier + token.
            auth = aiohttp.BasicAuth(self.credential_identifier, self.credential_token)

        headers = {"Accept": "application/json, text/html", "User-Agent": "h1-target-monitor/1.0"}
        url = self.endpoint
        all_assets: dict[str, TargetAsset] = {}

        async with aiohttp.ClientSession(timeout=self.timeout, headers=headers) as session:
            while url:
                async with session.get(url, auth=auth, allow_redirects=False) as response:
                    if response.status in {401, 403}:
                        raise PermissionError("HackerOne rejected the configured API credentials")
                    if response.status >= 400:
                        body = (await response.text())[:300]
                        raise RuntimeError(f"HackerOne endpoint returned HTTP {response.status}: {body}")
                    content_type = response.headers.get("Content-Type", "").lower()
                    body = await response.text()
                
                if "json" in content_type:
                    try:
                        payload = json.loads(body)
                    except json.JSONDecodeError as exc:
                        raise RuntimeError("Configured endpoint returned invalid JSON") from exc
                    
                    for asset in self._json_assets(payload):
                        all_assets[asset.key] = asset
                    
                    links = payload.get("links", {})
                    next_url = links.get("next")
                    url = next_url if next_url and next_url != url else None
                elif "html" in content_type:
                    for asset in self._html_assets(body):
                        all_assets[asset.key] = asset
                    break
                else:
                    break
                    
        if not all_assets and "json" not in content_type and "html" not in content_type:
            raise RuntimeError("Configured source must return JSON or HTML")
        return list(all_assets.values())

    @classmethod
    async def fetch_all_programs(
        cls,
        credential_identifier: str,
        credential_token: str,
        timeout_seconds: int = 30,
    ) -> list[dict[str, str]]:
        auth = aiohttp.BasicAuth(credential_identifier, credential_token)
        headers = {"Accept": "application/json", "User-Agent": "h1-target-monitor/1.0"}
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        programs = []
        url = "https://api.hackerone.com/v1/hackers/programs"
        
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            while url:
                async with session.get(url, auth=auth, allow_redirects=False) as response:
                    if response.status in {401, 403}:
                        raise PermissionError("HackerOne rejected the API credentials")
                    if response.status >= 400:
                        body = (await response.text())[:300]
                        raise RuntimeError(f"HackerOne endpoint returned HTTP {response.status}: {body}")
                    
                    data = await response.json()
                    
                    for item in data.get("data", []):
                        attrs = item.get("attributes", {})
                        programs.append({
                            "handle": attrs.get("handle"),
                            "name": attrs.get("name")
                        })
                    
                    links = data.get("links", {})
                    next_url = links.get("next")
                    url = next_url if next_url and next_url != url else None
                    
        return programs

    def _json_assets(self, payload: Any) -> list[TargetAsset]:
        assets: dict[str, TargetAsset] = {}
        for item in self._walk(payload):
            asset = self._to_asset(item)
            if asset:
                assets[asset.key] = asset
        return list(assets.values())

    def _html_assets(self, html: str) -> list[TargetAsset]:
        soup = BeautifulSoup(html, "html.parser")
        assets: dict[str, TargetAsset] = {}

        # Program pages frequently embed a JSON state object. Reuse the JSON
        # parser instead of relying on brittle visual selectors.
        for script in soup.find_all("script"):
            text = script.string or script.get_text(strip=True)
            if not text or not text.lstrip().startswith(("{", "[")):
                continue
            try:
                for asset in self._json_assets(json.loads(text)):
                    assets[asset.key] = asset
            except json.JSONDecodeError:
                continue

        # A small convention for stable, explicitly marked HTML scope feeds.
        for node in soup.select("[data-asset-identifier]"):
            identifier = (node.get("data-asset-identifier") or "").strip()
            if identifier:
                asset = TargetAsset(
                    program=(node.get("data-program-name") or self.program_name).strip(),
                    identifier=identifier,
                    asset_type=(node.get("data-asset-type") or "Other").strip(),
                    source_url=self.endpoint,
                )
                assets[asset.key] = asset

        # Fallback for server-rendered scope tables. Only a table that labels an
        # asset/scope column is considered, which prevents unrelated links from
        # becoming targets.
        for table in soup.find_all("table"):
            headers = [cell.get_text(" ", strip=True).casefold() for cell in table.find_all("th")]
            identifier_index = next(
                (index for index, header in enumerate(headers) if any(word in header for word in ("asset", "scope", "target", "domain", "url"))),
                None,
            )
            if identifier_index is None:
                continue
            type_index = next((index for index, header in enumerate(headers) if "type" in header), None)
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) <= identifier_index:
                    continue
                identifier = cells[identifier_index].get_text(" ", strip=True)
                if not identifier:
                    continue
                asset_type = cells[type_index].get_text(" ", strip=True) if type_index is not None and len(cells) > type_index else "Other"
                asset = TargetAsset(self.program_name, identifier, asset_type or "Other", self.endpoint)
                assets[asset.key] = asset
        return list(assets.values())

    def _walk(self, value: Any) -> Iterator[dict[str, Any]]:
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from self._walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from self._walk(child)

    @staticmethod
    def _map_asset_type(raw: str) -> str:
        from adapters import normalize_asset_type
        return normalize_asset_type(raw)

    def _to_asset(self, item: dict[str, Any]) -> TargetAsset | None:
        # HackerOne responses commonly use JSON:API {attributes: {...}}.
        attributes = item.get("attributes")
        data = attributes if isinstance(attributes, dict) else item
        identifier = data.get("asset_identifier")
        if not isinstance(identifier, str) or not identifier.strip():
            return None

        raw_type = data.get("asset_type") or data.get("type") or data.get("asset_type_name") or "Other"
        asset_type = self._map_asset_type(raw_type)
        program = data.get("program_name") or data.get("program") or self.program_name
        if isinstance(program, dict):
            program = program.get("name") or program.get("handle") or self.program_name
        source_url = data.get("asset_url") or data.get("url")
        
        bounty_eligible = data.get("eligible_for_bounty")
        eligible_sub = data.get("eligible_for_submission")
        coverage = "Eligible" if eligible_sub else ("Ineligible" if eligible_sub is False else None)
        max_severity = data.get("max_severity")
        if max_severity:
            max_severity = str(max_severity).capitalize()
        updated_at = data.get("updated_at") or data.get("created_at")

        return TargetAsset(
            program=str(program).strip() or self.program_name,
            identifier=identifier.strip(),
            asset_type=asset_type,
            source_url=source_url if isinstance(source_url, str) else None,
            coverage=coverage,
            max_severity=max_severity,
            bounty_eligible=bounty_eligible,
            updated_at=updated_at,
        )
