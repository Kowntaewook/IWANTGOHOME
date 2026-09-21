"""Installed target entry points consumed by host-side commands."""

from ctf_mcp.targets import TargetRegistry


def get_target_registry() -> TargetRegistry:
    return TargetRegistry()
