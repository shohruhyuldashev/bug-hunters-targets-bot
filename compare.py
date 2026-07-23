"""Small, deterministic snapshot helpers used before database comparison."""

from __future__ import annotations

from models import TargetAsset


def deduplicate_assets(assets: list[TargetAsset]) -> dict[str, TargetAsset]:
    """Return one normalized asset per stable key from a source response."""
    return {asset.key: asset for asset in assets}
