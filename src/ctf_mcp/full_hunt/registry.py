"""Explicit registry for target full-hunt adapter factories."""

from __future__ import annotations

from typing import Any, Callable

from ctf_mcp.local_targets.base import LocalTargetError


class FullHuntRegistry:
    def __init__(self) -> None:
        self._factories: dict[str, Callable[..., Any]] = {}

    def register(self, target: str, factory: Callable[..., Any]) -> None:
        if (not target or target in self._factories or not callable(factory)):
            raise LocalTargetError("invalid_full_hunt_registry")
        self._factories[target] = factory

    def create(self, target: str, *args: Any, **kwargs: Any) -> Any:
        factory = self._factories.get(target)
        if factory is None:
            raise LocalTargetError("FULL_HUNT_UNAVAILABLE")
        return factory(*args, **kwargs)

    @property
    def targets(self) -> frozenset[str]:
        return frozenset(self._factories)


FULL_HUNT_REGISTRY = FullHuntRegistry()
