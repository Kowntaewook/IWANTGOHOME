"""Versioned, lazy target plugin discovery for trusted host-side adapters."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
import inspect
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Protocol, runtime_checkable


TARGET_API_VERSION = 1
TARGET_ENTRY_POINT_GROUP = "iwantgohome.targets"
TARGET_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


class TargetPluginError(Exception):
    """Stable plugin failure code without imported exception details."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@runtime_checkable
class TargetAdapter(Protocol):
    """Host-side lifecycle implemented by an external target package."""

    target_id: str
    target_api_version: int
    supported_candidates: frozenset[str]

    def prepare(self) -> dict[str, Any]: ...
    def up(self, progress: Callable[[str], None] = print) -> dict[str, Any]: ...
    def status(self) -> dict[str, Any]: ...
    def bootstrap(self) -> dict[str, Any]: ...
    def validate(self, candidate: str | None = None) -> list[dict[str, Any]]: ...
    def stop(self) -> dict[str, Any]: ...
    def reset(self) -> dict[str, Any]: ...


REQUIRED_TARGET_METHODS = (
    "prepare", "up", "status", "bootstrap", "validate", "stop", "reset",
)
OPTIONAL_TARGET_CAPABILITIES = (
    "full_hunt", "hunt", "version_provider", "scenario_bindings",
    "release_provider", "regression_capabilities", "run_regression",
)


@dataclass(frozen=True)
class TargetPluginMetadata:
    target_id: str
    entry_point: str
    distribution: str | None
    distribution_version: str | None
    built_in: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "entry_point": self.entry_point,
            "distribution": self.distribution,
            "distribution_version": self.distribution_version,
            "built_in": self.built_in,
        }


@dataclass(frozen=True)
class BuiltinTarget:
    """A lazy built-in registration kept outside the target-neutral registry."""

    target_id: str
    value: str
    loader: Callable[[], Any]


@dataclass(frozen=True)
class _DiscoveredTarget:
    metadata: TargetPluginMetadata
    loader: Callable[[], Any]


class TargetRegistry:
    """Single target lookup registry backed only by explicit and installed entries."""

    def __init__(
        self,
        *,
        builtins: Iterable[BuiltinTarget] = (),
        entry_points_provider: Callable[[], Iterable[Any]] | None = None,
    ) -> None:
        self._builtins = tuple(builtins)
        self._entry_points_provider = entry_points_provider or _installed_entry_points

    def _discover(self) -> dict[str, _DiscoveredTarget]:
        discovered: dict[str, list[_DiscoveredTarget]] = {}
        for item in self._builtins:
            if not TARGET_ID.fullmatch(item.target_id) or not callable(item.loader):
                raise TargetPluginError("INVALID_TARGET_PLUGIN")
            value = _DiscoveredTarget(
                TargetPluginMetadata(
                    target_id=item.target_id,
                    entry_point=item.value,
                    distribution="iwantgohome",
                    distribution_version=None,
                    built_in=True,
                ),
                item.loader,
            )
            discovered.setdefault(item.target_id, []).append(value)
        try:
            external = tuple(self._entry_points_provider())
        except Exception as error:
            if isinstance(getattr(error, "code", None), str):
                raise
            raise TargetPluginError("INVALID_TARGET_PLUGIN") from None
        for entry_point in external:
            if getattr(entry_point, "group", TARGET_ENTRY_POINT_GROUP) != TARGET_ENTRY_POINT_GROUP:
                continue
            target_id = getattr(entry_point, "name", None)
            value = getattr(entry_point, "value", None)
            if (not isinstance(target_id, str) or not TARGET_ID.fullmatch(target_id)
                    or not isinstance(value, str) or not value
                    or not callable(getattr(entry_point, "load", None))):
                raise TargetPluginError("INVALID_TARGET_PLUGIN")
            dist = getattr(entry_point, "dist", None)
            dist_name = getattr(dist, "name", None)
            dist_version = getattr(dist, "version", None)
            found = _DiscoveredTarget(
                TargetPluginMetadata(
                    target_id=target_id,
                    entry_point=value,
                    distribution=dist_name if isinstance(dist_name, str) else None,
                    distribution_version=(
                        dist_version if isinstance(dist_version, str) else None
                    ),
                ),
                entry_point.load,
            )
            discovered.setdefault(target_id, []).append(found)
        duplicates = [key for key, values in discovered.items() if len(values) != 1]
        if duplicates:
            raise TargetPluginError("DUPLICATE_TARGET_ID")
        return {key: values[0] for key, values in discovered.items()}

    def list(self) -> list[TargetPluginMetadata]:
        """Return installed metadata without importing target modules."""

        discovered = self._discover()
        return [discovered[key].metadata for key in sorted(discovered)]

    def info(self, target_id: str) -> TargetPluginMetadata:
        value = self._select(target_id)
        return value.metadata

    @property
    def targets(self) -> frozenset[str]:
        return frozenset(self._discover())

    def load(
        self,
        target_id: str,
        *,
        root: Path,
        runner: Any | None = None,
    ) -> TargetAdapter:
        selected = self._select(target_id)
        try:
            plugin = selected.loader()
        except Exception:
            raise TargetPluginError("INVALID_TARGET_PLUGIN") from None
        factory = getattr(plugin, "create_adapter", plugin)
        if not callable(factory):
            raise TargetPluginError("INVALID_TARGET_PLUGIN")
        try:
            adapter = _call_factory(factory, root=root, runner=runner)
        except TargetPluginError:
            raise
        except Exception as error:
            if isinstance(getattr(error, "code", None), str):
                raise
            raise TargetPluginError("INVALID_TARGET_PLUGIN") from None
        api_version = getattr(adapter, "target_api_version", None)
        if api_version is None:
            api_version = getattr(plugin, "target_api_version", None)
        if api_version is None:
            api_version = getattr(plugin, "TARGET_API_VERSION", None)
        if api_version != TARGET_API_VERSION:
            raise TargetPluginError("INCOMPATIBLE_TARGET_PLUGIN")
        if getattr(adapter, "target_id", None) != target_id:
            raise TargetPluginError("INVALID_TARGET_PLUGIN")
        _validate_adapter(adapter)
        return adapter

    def doctor(
        self,
        target_id: str,
        *,
        root: Path,
        runner: Any | None = None,
    ) -> dict[str, Any]:
        """Load and inspect an adapter without invoking lifecycle or network methods."""

        adapter = self.load(target_id, root=root, runner=runner)
        return {
            "status": "compatible",
            "target_id": adapter.target_id,
            "target_api_version": TARGET_API_VERSION,
            "required_methods": list(REQUIRED_TARGET_METHODS),
            "optional_capabilities": {
                name: callable(getattr(adapter, name, None))
                for name in OPTIONAL_TARGET_CAPABILITIES
            },
        }

    def _select(self, target_id: str) -> _DiscoveredTarget:
        if not isinstance(target_id, str) or not TARGET_ID.fullmatch(target_id):
            raise TargetPluginError("INVALID_TARGET_PLUGIN")
        value = self._discover().get(target_id)
        if value is None:
            raise TargetPluginError("TARGET_NOT_FOUND")
        return value


def _installed_entry_points() -> Iterable[Any]:
    values = metadata.entry_points()
    if hasattr(values, "select"):
        return values.select(group=TARGET_ENTRY_POINT_GROUP)
    return values.get(TARGET_ENTRY_POINT_GROUP, ())


def _call_factory(factory: Callable[..., Any], *, root: Path, runner: Any | None) -> Any:
    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError):
        raise TargetPluginError("INVALID_TARGET_PLUGIN") from None
    parameters = signature.parameters
    if "root" not in parameters:
        raise TargetPluginError("INCOMPATIBLE_TARGET_PLUGIN")
    kwargs: dict[str, Any] = {"root": root}
    if "runner" in parameters:
        kwargs["runner"] = runner
    return factory(**kwargs)


def _validate_adapter(adapter: Any) -> None:
    if not isinstance(getattr(adapter, "supported_candidates", None), frozenset):
        raise TargetPluginError("INCOMPATIBLE_TARGET_PLUGIN")
    if any(not callable(getattr(adapter, name, None)) for name in REQUIRED_TARGET_METHODS):
        raise TargetPluginError("INCOMPATIBLE_TARGET_PLUGIN")
