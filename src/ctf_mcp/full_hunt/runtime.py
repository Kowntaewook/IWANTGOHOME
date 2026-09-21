"""Safety checks shared by isolated localhost runtimes."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
from typing import Any, Callable
from urllib.parse import urlsplit

from ctf_mcp.local_targets.base import LocalTargetError


@dataclass(frozen=True)
class IsolatedRuntime:
    kind: str
    runtime_id: str
    endpoint: str
    image_identity: str | None

    def __post_init__(self) -> None:
        parsed = urlsplit(
            self.endpoint if "://" in self.endpoint else "http://" + self.endpoint
        )
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError:
            raise LocalTargetError("non_local_retest_runtime") from None
        if (not address.is_loopback or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or not self.kind or not self.runtime_id):
            raise LocalTargetError("non_local_retest_runtime")


def assert_secret_free(value: Any) -> None:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True).lower()
    forbidden = (
        '"authorization"', '"cookie"', '"password"', '"access_token"',
        '"private_key"', '"credential"', "basic ", "bearer ",
    )
    if any(term in raw for term in forbidden) or re.search(r"gh[pousr]_[a-z0-9_]{20,}", raw):
        raise LocalTargetError("unsafe_hunt_report")


@dataclass
class IsolatedRuntimeLifecycle:
    """Run ownership, start, bootstrap, and cleanup gates without target knowledge."""

    port_in_use: Callable[[], bool]
    owned_healthy: Callable[[], bool]
    start: Callable[[], None]
    bootstrap: Callable[[], None]
    stop: Callable[[], None]

    def prepare(self) -> str:
        if self.port_in_use() and not self.owned_healthy():
            raise LocalTargetError("RUNTIME_PORT_CONFLICT")
        try:
            self.start()
        except LocalTargetError:
            try:
                self.stop()
            except LocalTargetError:
                pass
            raise LocalTargetError("RUNTIME_START_FAILED") from None
        try:
            self.bootstrap()
        except LocalTargetError as error:
            raise LocalTargetError(
                "RUNTIME_API_INCOMPATIBLE"
                if error.code == "BOOTSTRAP_FAILED" else "RUNTIME_BOOTSTRAP_FAILED"
            ) from None
        return "ready"
