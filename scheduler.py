"""APScheduler setup; polling is near-real-time and configurable per source."""

from __future__ import annotations

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from config import Settings
from scanner import TargetScanner


class MonitorScheduler:
    def __init__(self, scanner: TargetScanner, settings: Settings) -> None:
        self.scheduler = AsyncIOScheduler(timezone="UTC")
        self.scheduler.add_job(
            scanner.scan_due,
            trigger="interval",
            seconds=settings.scan_tick_seconds,
            id="target-monitor",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )

    def start(self) -> None:
        self.scheduler.start()

    def stop(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
