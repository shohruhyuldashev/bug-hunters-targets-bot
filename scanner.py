"""Fetch configured sources, compare snapshots, and notify on target changes.

Supports both Admin platforms and User connections for 24/7 server-side monitoring.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from adapters import get_adapter
from config import Settings
from database import Database
from security import decrypt_secret

if TYPE_CHECKING:
    from bot import TelegramNotifier
    from realtime import EventHub

LOG = logging.getLogger("target-monitor-scanner")


class ScanError(RuntimeError):
    pass


class TargetScanner:
    def __init__(
        self,
        database: Database,
        settings: Settings,
        notifier: "TelegramNotifier",
        event_hub: "EventHub",
    ) -> None:
        self.database = database
        self.settings = settings
        self.notifier = notifier
        self.event_hub = event_hub
        self._platform_locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._user_conn_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    # ── Admin Platforms Scanner ───────────────────────────────────────────────

    async def scan_platform(self, platform_id: int) -> dict[str, Any]:
        """Perform one safe snapshot comparison for an admin-configured platform."""
        async with self._platform_locks[platform_id]:
            platform = self.database.get_platform_for_scan(platform_id)
            if not platform["enabled"]:
                return {"platform_id": platform_id, "skipped": True, "reason": "disabled"}
            try:
                credentials: dict[str, str] = {}
                encrypted = platform.get("encrypted_credentials")
                if encrypted:
                    credentials = json.loads(decrypt_secret(self.settings.fernet(), encrypted))

                adapter_class = get_adapter(platform["kind"])
                adapter = adapter_class(
                    endpoint=platform["endpoint"],
                    program_name=platform["program_name"],
                    credential_identifier=credentials.get("identifier"),
                    credential_token=credentials.get("token"),
                    timeout_seconds=self.settings.request_timeout_seconds,
                )
                assets = await adapter.fetch_assets()
                first_snapshot, changes = self.database.save_scan(platform_id, assets)
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                self.database.record_scan_error(platform_id, message)
                raise ScanError(message) from exc

            should_notify = not first_snapshot or self.settings.notify_existing_on_first_sync
            notification_changes = changes if should_notify else []
            for change in notification_changes:
                await self.notifier.send_target(change, platform["name"])
                await self.event_hub.broadcast({"type": "target.added", "target": change})

            await self.event_hub.broadcast(
                {
                    "type": "scan.completed",
                    "platform_id": platform_id,
                    "first_snapshot": first_snapshot,
                    "targets_found": len(assets),
                    "changes": len(changes),
                }
            )
            return {
                "platform_id": platform_id,
                "platform": platform["name"],
                "first_snapshot": first_snapshot,
                "targets_found": len(assets),
                "changes": changes,
                "notified": len(notification_changes),
            }

    # ── User Connections Scanner (Hosted 24/7 Scanning for Bot Users) ─────────

    async def scan_user_connection(self, user_conn: dict[str, Any]) -> dict[str, Any]:
        """Perform 24/7 automated scan on a user's saved connection (H1, Intigriti, YWH, Bugcrowd)."""
        conn_id = user_conn["id"]
        owner_chat_id = user_conn["owner_chat_id"]
        program_name = user_conn["program_name"]
        platform_kind = user_conn["platform"]

        async with self._user_conn_locks[conn_id]:
            try:
                raw_token = None
                encrypted_token = user_conn.get("encrypted_token")
                if encrypted_token:
                    raw_token = decrypt_secret(self.settings.fernet(), encrypted_token)

                adapter_class = get_adapter(platform_kind)

                # --- NEW LOGIC: Global User Scan (All Programs) ---
                if program_name == "All Programs":
                    if platform_kind.lower() == "hackerone":
                        from adapters.hackerone import HackerOneAdapter
                        programs = await HackerOneAdapter.fetch_all_programs(
                            user_conn.get("credential_identifier", ""),
                            raw_token or "",
                            self.settings.request_timeout_seconds
                        )
                    elif platform_kind.lower() == "yeswehack":
                        from adapters.yeswehack import YesWeHackAdapter
                        programs = await YesWeHackAdapter.fetch_all_programs(
                            user_conn.get("credential_identifier", ""),
                            raw_token or "",
                            self.settings.request_timeout_seconds
                        )
                    elif platform_kind.lower() == "intigriti":
                        from adapters.intigriti import IntigritiAdapter
                        programs = await IntigritiAdapter.fetch_all_programs(
                            user_conn.get("credential_identifier", ""),
                            raw_token or "",
                            self.settings.request_timeout_seconds
                        )
                    else:
                        from adapters.bugcrowd import BugcrowdAdapter
                        programs = await BugcrowdAdapter.fetch_all_programs(
                            user_conn.get("credential_identifier"),
                            raw_token or None,
                            self.settings.request_timeout_seconds
                        )

                    
                    total_new = 0
                    sem = asyncio.Semaphore(10)

                    async def process_program(p: dict) -> int:
                        handle = p["handle"]
                        raw_name = p["name"]
                        name = raw_name if raw_name.casefold() == handle.casefold() else f"{raw_name} ({handle})"
                        
                        if platform_kind.lower() == "hackerone":
                            endpoint = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
                        elif platform_kind.lower() == "yeswehack":
                            endpoint = f"https://api.yeswehack.com/programs/{handle}/user-scope"
                        elif platform_kind.lower() == "intigriti":
                            endpoint = f"https://api.intigriti.com/external/researcher/v1/programs/{handle}"
                        else:
                            endpoint = f"https://bugcrowd.com/{handle}/target_groups.json"
                            
                        try:
                            async with sem:
                                adapter = adapter_class(
                                    endpoint=endpoint,
                                    program_name=name,
                                    credential_identifier=user_conn.get("credential_identifier"),
                                    credential_token=raw_token,
                                    timeout_seconds=self.settings.request_timeout_seconds,
                                )
                                assets = await adapter.fetch_assets()
                            
                            if not assets:
                                return 0
                                
                            existing_keys = self.database.get_all_relay_target_keys(owner_chat_id, name)
                            is_first_scan = len(existing_keys) == 0

                            target_items = [
                                {
                                    "identifier": a.identifier, 
                                    "asset_type": a.asset_type, 
                                    "source_url": a.source_url,
                                    "coverage": a.coverage,
                                    "max_severity": a.max_severity,
                                    "bounty_eligible": a.bounty_eligible,
                                    "updated_at": a.updated_at,
                                    "resolved_reports": a.resolved_reports
                                } for a in assets
                            ]
                            self.database.save_relay_targets(owner_chat_id, name, target_items)

                            asset_types_summary: dict[str, int] = defaultdict(int)
                            for a in assets:
                                asset_types_summary[a.asset_type] += 1

                            self.database.save_relay_program(
                                owner_chat_id, name,
                                {"program": name, "platform": platform_kind.capitalize(), "scope_count": len(assets), "asset_types": dict(asset_types_summary)}
                            )

                            new_count = 0
                            if not is_first_scan:
                                now_str = datetime.now(UTC).isoformat()
                                events = []
                                for asset in assets:
                                    key = f"{asset.identifier.strip().casefold()}|{asset.asset_type.strip().casefold()}"
                                    if key not in existing_keys:
                                        events.append({
                                            "program": name,
                                            "platform": platform_kind,
                                            "identifier": asset.identifier,
                                            "asset_type": asset.asset_type,
                                            "observed_at": now_str,
                                            "event_type": "added",
                                        })
                                        new_count += 1
                                if events:
                                    await self.notifier.send_client_targets_batch(owner_chat_id, events)
                            return new_count
                        except PermissionError:
                            # User does not have access to this program's structured scope, silently ignore
                            pass
                        except Exception as p_exc:
                            LOG.debug(f"Failed to scan program {name} for user {owner_chat_id}: {p_exc}")
                        return 0

                    tasks = [process_program(p) for p in programs]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in results:
                        if isinstance(r, int):
                            total_new += r


                    self.database.update_user_connection_scan_time(conn_id)
                    LOG.info(f"Server scan finished for user {owner_chat_id} [All Programs]: {len(programs)} programs, {total_new} new notifications")
                    return {"conn_id": conn_id, "program": program_name, "new_notifications": total_new}
                # --- END NEW LOGIC ---

                adapter = adapter_class(
                    endpoint=user_conn["endpoint"],
                    program_name=program_name,
                    credential_identifier=user_conn.get("credential_identifier"),
                    credential_token=raw_token,
                    timeout_seconds=self.settings.request_timeout_seconds,
                )

                assets = await adapter.fetch_assets()
                if not assets:
                    return {"conn_id": conn_id, "skipped": True, "reason": "zero assets parsed"}

                # Compare with prior targets saved in relay_targets table
                existing_keys = self.database.get_all_relay_target_keys(owner_chat_id, program_name)
                is_first_scan = len(existing_keys) == 0

                # Target items for database bulk save
                target_items = [
                    {"identifier": a.identifier, "asset_type": a.asset_type, "source_url": a.source_url}
                    for a in assets
                ]
                self.database.save_relay_targets(owner_chat_id, program_name, target_items)

                # Save program summary for /program list in bot
                asset_types_summary: dict[str, int] = defaultdict(int)
                for a in assets:
                    asset_types_summary[a.asset_type] += 1

                self.database.save_relay_program(
                    owner_chat_id,
                    program_name,
                    {
                        "program": program_name,
                        "platform": platform_kind.capitalize(),
                        "scope_count": len(assets),
                        "asset_types": dict(asset_types_summary),
                    },
                )

                # Notify on new targets (if not first baseline scan)
                new_notifications = 0
                now_str = datetime.now(UTC).isoformat()
                if not is_first_scan:
                    for asset in assets:
                        key = f"{asset.identifier.strip().casefold()}|{asset.asset_type.strip().casefold()}"
                        if key not in existing_keys:
                            event = {
                                "program": program_name,
                                "platform": platform_kind,
                                "identifier": asset.identifier,
                                "asset_type": asset.asset_type,
                                "observed_at": now_str,
                                "event_type": "added",
                            }
                            await self.notifier.send_client_target(owner_chat_id, event)
                            new_notifications += 1

                self.database.update_user_connection_scan_time(conn_id)
                LOG.info(
                    "Server scan finished for user %s [%s/%s]: %d assets, %d new notifications",
                    owner_chat_id,
                    platform_kind,
                    program_name,
                    len(assets),
                    new_notifications,
                )
                return {
                    "conn_id": conn_id,
                    "program": program_name,
                    "targets_found": len(assets),
                    "new_notifications": new_notifications,
                }

            except Exception as exc:
                err_msg = str(exc) or exc.__class__.__name__
                LOG.warning("Server scan failed for user %s [%s]: %s", owner_chat_id, program_name, err_msg)
                return {"conn_id": conn_id, "error": err_msg}

    # ── Scan All Due Items ───────────────────────────────────────────────────

    async def scan_due(self) -> list[dict[str, Any]]:
        results = []

        # 1. Admin platforms
        due_admin = self.database.due_platforms()
        if due_admin:
            res_admin = await asyncio.gather(
                *(self._scan_due_one(int(p["id"])) for p in due_admin),
                return_exceptions=False,
            )
            results.extend(res_admin)

        # 2. User connections (Server-side 24/7 hosted scanning)
        due_users = self.database.due_user_connections()
        if due_users:
            res_users = await asyncio.gather(
                *(self.scan_user_connection(uc) for uc in due_users),
                return_exceptions=False,
            )
            results.extend(res_users)

        return results

    async def _scan_due_one(self, platform_id: int) -> dict[str, Any]:
        try:
            return await self.scan_platform(platform_id)
        except ScanError as exc:
            return {"platform_id": platform_id, "error": str(exc)}
