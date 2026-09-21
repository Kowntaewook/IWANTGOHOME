"""Bounded HTTP client fixed to the Mattermost loopback endpoint."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
import re
from typing import Any

from .base import LocalTargetError


ID = r"[a-z0-9]{26}"
SAFE_NAME = r"finder-local-[a-z0-9-]{1,48}"
ALLOWED: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "health": (("GET", re.compile(r"/api/v4/system/ping\Z")),),
    "session": (("POST", re.compile(r"/api/v4/users/login\Z")),),
    "bootstrap": tuple((method, re.compile(pattern)) for method, pattern in (
        ("POST", r"/api/v4/users\Z"),
        ("GET", rf"/api/v4/users/username/{SAFE_NAME}\Z"),
        ("PUT", rf"/api/v4/users/{ID}/roles\Z"),
        ("GET", r"/api/v4/roles/name/system_user_manager\Z"),
        ("GET", rf"/api/v4/teams/name/{SAFE_NAME}\Z"),
        ("POST", r"/api/v4/teams\Z"),
        ("POST", rf"/api/v4/teams/{ID}/members\Z"),
        ("GET", rf"/api/v4/teams/name/{SAFE_NAME}/channels/name/{SAFE_NAME}\Z"),
        ("POST", r"/api/v4/channels\Z"),
        ("POST", rf"/api/v4/channels/{ID}/members\Z"),
        ("DELETE", rf"/api/v4/channels/{ID}/members/{ID}\Z"),
        ("POST", r"/api/v4/channels/direct\Z"),
        ("POST", r"/api/v4/posts\Z"),
        ("GET", rf"/api/v4/users/{ID}\Z"),
    )),
    "S12": tuple((method, re.compile(pattern)) for method, pattern in (
        ("GET", rf"/api/v4/users/{ID}/teams/{ID}/threads/{ID}\Z"),
        ("GET", rf"/api/v4/users/{ID}/teams/{ID}/threads\?per_page=100&extended=true\Z"),
    )),
    "S13": tuple((method, re.compile(pattern)) for method, pattern in (
        ("GET", rf"/api/v4/users/{ID}/teams/{ID}/channels/members\?page=0&per_page=100\Z"),
        ("GET", rf"/api/v4/users/{ID}/channel_members\?page=0&per_page=100\Z"),
    )),
    "S15": tuple((method, re.compile(pattern)) for method, pattern in (
        ("GET", rf"/api/v4/users/{ID}/teams/{ID}/threads\?per_page=100&extended=true\Z"),
        ("PUT", rf"/api/v4/users/{ID}/teams/{ID}/threads/{ID}/read/[0-9]+\Z"),
        ("PUT", rf"/api/v4/users/{ID}/teams/{ID}/threads/read\Z"),
    )),
}


@dataclass(frozen=True)
class LocalResponse:
    status: int
    data: Any
    shape: Any


def response_shape(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "depth_limit"
    if isinstance(value, dict):
        return {str(key): response_shape(item, depth + 1) for key, item in sorted(value.items())
                if key not in {"token", "password", "email"}}
    if isinstance(value, list):
        return {"type": "array", "count": len(value), "item": response_shape(value[0], depth + 1) if value else None}
    if value is None:
        return "null"
    return type(value).__name__


class LocalMattermostClient:
    host = "127.0.0.1"
    port = 13100
    max_body = 512 * 1024

    def __init__(self, token: str | None = None, timeout: float = 5.0):
        self._token = token
        self.timeout = timeout
        self.request_count = 0

    @property
    def session_fingerprint(self) -> str | None:
        return hashlib.sha256(self._token.encode()).hexdigest()[:16] if self._token else None

    def request(self, scope: str, method: str, path: str, payload: Any = None, *, count: bool = True) -> LocalResponse:
        method = method.upper()
        if scope not in ALLOWED or not any(m == method and pattern.fullmatch(path) for m, pattern in ALLOWED[scope]):
            raise LocalTargetError("local_route_not_allowed")
        body = None if payload is None else json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request(method, path, body=body, headers=headers)
            raw_response = connection.getresponse()
            raw = raw_response.read(self.max_body + 1)
            if len(raw) > self.max_body:
                raise LocalTargetError("local_response_too_large")
            token = raw_response.getheader("Token")
            if token:
                self._token = token
            data = _decode_body(raw, raw_response.getheader("Content-Type") or "")
            if count:
                self.request_count += 1
            return LocalResponse(raw_response.status, data, response_shape(data))
        except LocalTargetError:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise LocalTargetError("local_http_failed") from None
        finally:
            connection.close()


def _decode_body(raw: bytes, content_type: str) -> Any:
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
        if "application/x-ndjson" in content_type:
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        return json.loads(text)
    except (UnicodeDecodeError, ValueError):
        return {"unparsed": True, "bytes": len(raw)}
