"""Bounded HTTP client fixed to the local Gitea validation endpoint."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import http.client
import json
import re
from typing import Any

from .base import LocalTargetError
from .http import LocalResponse, response_shape


OWNER = "finder-local-repo-owner"
COLLABORATOR = "finder-local-collaborator"
OUTSIDER = "finder-local-outsider"
REPOSITORY = "finder-local-private-repo"
PUBLIC_REPOSITORY = "finder-local-public-repo"
ORGANIZATION = "finder-local-org"
ORG_PUBLIC_REPOSITORY = "finder-local-public-org-repo"
ORG_PRIVATE_REPOSITORY = "finder-local-private-org-repo"
LIMITED_ORGANIZATION = "finder-local-limited-org"
LIMITED_ORG_PUBLIC_REPOSITORY = "finder-local-limited-public-repo"
TEAM = "finder-local-team"
CONTROL_TOKEN_NAME = "finder-local-control"
PUBLIC_ONLY_TOKEN_NAME = "finder-local-public-only"
REPO_PATH = f"/api/v1/repos/{OWNER}/{REPOSITORY}"
PUBLIC_REPO_PATH = f"/api/v1/repos/{OWNER}/{PUBLIC_REPOSITORY}"
ORG_PATH = f"/api/v1/orgs/{ORGANIZATION}"
ORG_PUBLIC_REPO_PATH = f"/api/v1/repos/{ORGANIZATION}/{ORG_PUBLIC_REPOSITORY}"
ORG_PRIVATE_REPO_PATH = f"/api/v1/repos/{ORGANIZATION}/{ORG_PRIVATE_REPOSITORY}"
LIMITED_ORG_PATH = f"/api/v1/orgs/{LIMITED_ORGANIZATION}"
LIMITED_ORG_PUBLIC_REPO_PATH = (
    f"/api/v1/repos/{LIMITED_ORGANIZATION}/{LIMITED_ORG_PUBLIC_REPOSITORY}"
)
ORG_REPOS_PATH = f"/api/v1/orgs/{ORGANIZATION}/repos?limit=50"
ORG_TEAMS_PATH = f"/api/v1/orgs/{ORGANIZATION}/teams?limit=50"
USER_FEEDS_PATH = f"/api/v1/users/{OWNER}/activities/feeds?only-performed-by=true&limit=50"
USER_HEATMAP_PATH = f"/api/v1/users/{OWNER}/heatmap"
USER_REPOS_PATH = f"/api/v1/users/{OWNER}/repos?limit=50"
TOKEN_PATH = f"/api/v1/users/{OWNER}/tokens"
CONTROL_TOKEN_DELETE_PATH = TOKEN_PATH + "/" + CONTROL_TOKEN_NAME
PUBLIC_ONLY_TOKEN_DELETE_PATH = TOKEN_PATH + "/" + PUBLIC_ONLY_TOKEN_NAME
TEAM_REPOS_PATTERN = re.compile(r"/api/v1/teams/[1-9][0-9]{0,18}/repos\?limit=50\Z")
TEAM_REPOSITORIES = (ORG_PUBLIC_REPOSITORY, ORG_PRIVATE_REPOSITORY)
TEAM_REPO_MUTATION_PATTERNS = tuple(
    re.compile(
        rf"/api/v1/teams/[1-9][0-9]{{0,18}}/repos/{re.escape(ORGANIZATION)}/"
        rf"{re.escape(repository)}\Z"
    )
    for repository in TEAM_REPOSITORIES
)
TEAM_MEMBER_MUTATION_PATTERN = re.compile(
    rf"/api/v1/teams/[1-9][0-9]{{0,18}}/members/"
    rf"(?:{re.escape(COLLABORATOR)}|{re.escape(OUTSIDER)})\Z"
)

GITEA_ALLOWED: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "health": (("GET", re.compile(r"/api/healthz\Z")),),
    "identity": (("GET", re.compile(r"/api/v1/user\Z")),),
    "token_identity": (("GET", re.compile(r"/api/v1/token\Z")),),
    "bootstrap": tuple((method, re.compile(re.escape(path) + r"\Z")) for method, path in (
        ("GET", REPO_PATH),
        ("GET", PUBLIC_REPO_PATH),
        ("GET", ORG_PATH),
        ("GET", ORG_PUBLIC_REPO_PATH),
        ("GET", ORG_PRIVATE_REPO_PATH),
        ("GET", LIMITED_ORG_PATH),
        ("GET", LIMITED_ORG_PUBLIC_REPO_PATH),
        ("GET", ORG_TEAMS_PATH),
        ("GET", USER_FEEDS_PATH),
        ("POST", "/api/v1/user/repos"),
        ("POST", "/api/v1/orgs"),
        ("POST", f"/api/v1/orgs/{ORGANIZATION}/repos"),
        ("POST", f"/api/v1/orgs/{LIMITED_ORGANIZATION}/repos"),
        ("POST", f"/api/v1/orgs/{ORGANIZATION}/teams"),
        ("POST", TOKEN_PATH),
        ("DELETE", CONTROL_TOKEN_DELETE_PATH),
        ("DELETE", PUBLIC_ONLY_TOKEN_DELETE_PATH),
        ("DELETE", f"/api/v1/orgs/{ORGANIZATION}/members/{OUTSIDER}"),
        ("PUT", REPO_PATH + "/collaborators/" + COLLABORATOR),
        ("GET", REPO_PATH + "/collaborators/" + COLLABORATOR + "/permission"),
        ("GET", REPO_PATH + "/collaborators/" + OUTSIDER),
        ("DELETE", REPO_PATH + "/collaborators/" + OUTSIDER),
    )) + tuple(
        ("PUT", pattern) for pattern in TEAM_REPO_MUTATION_PATTERNS
    ) + (
        ("PUT", TEAM_MEMBER_MUTATION_PATTERN),
        ("DELETE", TEAM_MEMBER_MUTATION_PATTERN),
    ),
    "G01": (("GET", re.compile(re.escape(REPO_PATH) + r"\Z")),),
    "G02": (("GET", re.compile(re.escape(REPO_PATH) + r"\Z")),),
    "G03": (("PATCH", re.compile(re.escape(REPO_PATH) + r"\Z")),),
    "G04": tuple(("GET", re.compile(re.escape(path) + r"\Z")) for path in (
        LIMITED_ORG_PUBLIC_REPO_PATH,
        USER_FEEDS_PATH,
    )),
    "G05": tuple(("GET", re.compile(re.escape(path) + r"\Z")) for path in (
        REPO_PATH,
        USER_HEATMAP_PATH,
    )),
    "G06": (("GET", re.compile(re.escape(USER_REPOS_PATH) + r"\Z")),),
    "G07": (("GET", re.compile(re.escape(ORG_REPOS_PATH) + r"\Z")),),
    "G08": (("GET", TEAM_REPOS_PATTERN),),
}


def team_repository_path(team_id: int, repository: str) -> str:
    if (isinstance(team_id, bool) or not isinstance(team_id, int)
            or team_id <= 0 or len(str(team_id)) > 19
            or repository not in TEAM_REPOSITORIES):
        raise LocalTargetError("local_route_not_allowed")
    return f"/api/v1/teams/{team_id}/repos/{ORGANIZATION}/{repository}"


@dataclass(frozen=True)
class GiteaResponse(LocalResponse):
    total_count: int | None = None


class LocalGiteaClient:
    host = "127.0.0.1"
    port = 13000
    max_body = 512 * 1024

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 5.0,
        *,
        token: str | None = None,
        identity_label: str | None = None,
        port: int = 13000,
    ):
        basic_supplied = username is not None or password is not None
        if (username is None) != (password is None) or (basic_supplied and token is not None):
            raise LocalTargetError("local_http_failed")
        if token is not None and not token:
            raise LocalTargetError("local_http_failed")
        if isinstance(port, bool) or port not in {13000, 13001, 13002}:
            raise LocalTargetError("local_http_failed")
        self._identity_label = identity_label or username
        self._authorization = None
        if username is not None and password is not None:
            encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            self._authorization = "Basic " + encoded
        elif token is not None:
            self._authorization = "token " + token
        self.timeout = timeout
        self.port = port
        self.request_count = 0

    @property
    def session_fingerprint(self) -> str | None:
        if self._identity_label is None:
            return None
        return hashlib.sha256(("gitea-local:" + self._identity_label).encode()).hexdigest()[:16]

    def request(
        self,
        scope: str,
        method: str,
        path: str,
        payload: Any = None,
        *,
        count: bool = True,
    ) -> LocalResponse:
        method = method.upper()
        routes = GITEA_ALLOWED.get(scope, ())
        if not any(allowed_method == method and pattern.fullmatch(path) for allowed_method, pattern in routes):
            raise LocalTargetError("local_route_not_allowed")
        body = None if payload is None else json.dumps(
            payload, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._authorization is not None:
            headers["Authorization"] = self._authorization
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(self.max_body + 1)
            if len(raw) > self.max_body:
                raise LocalTargetError("local_response_too_large")
            data = _decode_json(raw)
            total_count = _total_count(response.getheader("X-Total-Count"))
            if count:
                self.request_count += 1
            return GiteaResponse(response.status, data, response_shape(data), total_count)
        except LocalTargetError:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise LocalTargetError("local_http_failed") from None
        finally:
            connection.close()


def _decode_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"unparsed": True, "bytes": len(raw)}


def _total_count(value: str | None) -> int | None:
    if value is None or not re.fullmatch(r"[0-9]{1,9}", value):
        return None
    return int(value)
