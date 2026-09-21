"""Compatibility view of the single SDK target registry."""

from ctf_mcp.targets import TargetRegistry

from .plugin_registry import get_target_registry


def get_full_hunt_registry() -> TargetRegistry:
    return get_target_registry()
