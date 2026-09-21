"""Load the code-owned full-hunt adapters into the generic registry."""

from ctf_mcp.full_hunt.registry import FULL_HUNT_REGISTRY, FullHuntRegistry


def get_full_hunt_registry() -> FullHuntRegistry:
    from . import gitea_hunt_adapter, mattermost_hunt_adapter
    del gitea_hunt_adapter, mattermost_hunt_adapter
    return FULL_HUNT_REGISTRY
