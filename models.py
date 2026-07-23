"""Internal normalized models shared by source adapters and the scanner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TargetAsset:
    program: str
    identifier: str
    asset_type: str
    source_url: str | None = None
    coverage: str | None = None
    max_severity: str | None = None
    bounty_eligible: bool | None = None
    updated_at: str | None = None
    resolved_reports: int | None = None

    @property
    def key(self) -> str:
        # Case-insensitive host names should not create duplicate targets.
        return "|".join(
            (self.program.strip().casefold(), self.identifier.strip().casefold(), self.asset_type.strip().casefold())
        )


@dataclass(frozen=True)
class ProgramDetails:
    """Publicly shareable program metadata normalized from an allowed source."""

    name: str
    source_url: str | None
    resolved_reports: int | None = None
    minimum_bounty: str | None = None
    average_bounty: str | None = None
    maximum_bounty: str | None = None
    currency: str | None = None
    program_updated_at: str | None = None
    policy_url: str | None = None
    description: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_url": self.source_url,
            "resolved_reports": self.resolved_reports,
            "minimum_bounty": self.minimum_bounty,
            "average_bounty": self.average_bounty,
            "maximum_bounty": self.maximum_bounty,
            "currency": self.currency,
            "program_updated_at": self.program_updated_at,
            "policy_url": self.policy_url,
            "description": self.description,
        }
