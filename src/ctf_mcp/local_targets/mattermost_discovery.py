"""Bounded, source-backed Mattermost full-hunt discovery."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from .base import LocalTargetError


MAX_SOURCE_BYTES = 2 * 1024 * 1024
VERSION_FILE = Path("server/public/model/version.go")
VERSION_PATTERN = re.compile(r'var\s+versions\s*=\s*\[\]string\s*\{\s*"([0-9]+\.[0-9]+\.[0-9]+)"')


@dataclass(frozen=True)
class MattermostRule:
    candidate_id: str
    baseline_candidate: str
    method: str
    route: str
    handler: str
    route_token: str
    auth_tokens: tuple[str, ...]
    data_tokens: tuple[str, ...]
    discovery_class: str
    security_invariant: str
    control_hypothesis: str
    probe_hypothesis: str
    root_cause_key: str
    automatic_safe: bool


RULES = (
    MattermostRule(
        "MM-S12", "S12", "GET",
        "/api/v4/users/{user_id}/teams/{team_id}/threads",
        "getThreadsForUser", 'UserThreads.Handle(""',
        ("SessionHasPermissionToUser", "SessionHasPermissionToTeam"),
        ("GetThreadsForUser",),
        "collection_and_direct_object_authorization_mismatch",
        "A collection must not return thread content that the requester cannot read directly.",
        "The delegated viewer is denied the exact private thread.",
        "The same viewer requests the bounded thread collection and it must omit that thread.",
        "getThreadsForUser/private-channel-membership", True,
    ),
    MattermostRule(
        "MM-S13", "S13", "GET",
        "/api/v4/users/{user_id}/channel_members",
        "getChannelMembersForUser", 'User.Handle("/channel_members"',
        ("SessionHasPermissionToUser", "SanitizeForCurrentUser"),
        ("GetChannelMembersWithTeamDataForUserWithPagination",),
        "authorization_and_response_sanitization_boundary",
        "A delegated viewer may receive only membership fields authorized for that viewer.",
        "The team-scoped membership route supplies the comparison shape.",
        "The cross-team route must apply the same requester-specific sanitization.",
        "getChannelMembersForUser/requester-sanitization", True,
    ),
    MattermostRule(
        "MM-S15", "S15", "PUT",
        "/api/v4/users/{user_id}/teams/{team_id}/threads/read",
        "updateReadStateAllThreadsByUser", 'UserThreads.Handle("/read"',
        ("SessionHasPermissionToUser",),
        ("UpdateThreadsReadForUser",),
        "bulk_and_direct_object_authorization_mismatch",
        "A bulk read-state update must not modify a thread the requester cannot read directly.",
        "The direct thread update is denied for the delegated viewer.",
        "The bulk update must leave the protected user's private thread state unchanged.",
        "updateReadStateAllThreadsByUser/private-channel-membership", False,
    ),
)


def discover_mattermost_candidates(source_root: Path) -> list[dict[str, Any]]:
    relative = Path("server/channels/api4/user.go")
    path = source_root / relative
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            raise LocalTargetError("SOURCE_NOT_PREPARED")
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except LocalTargetError:
        raise
    except (OSError, UnicodeDecodeError):
        raise LocalTargetError("SOURCE_NOT_PREPARED") from None
    file_hash = hashlib.sha256(raw).hexdigest()
    return [_candidate(rule, text, str(relative), file_hash) for rule in RULES]


def discover_mattermost_version(source_root: Path) -> str:
    """Read the release version declared by the exact checked-out source."""
    path = source_root / VERSION_FILE
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            raise LocalTargetError("SOURCE_NOT_PREPARED")
        text = path.read_text(encoding="utf-8")
    except LocalTargetError:
        raise
    except (OSError, UnicodeDecodeError):
        raise LocalTargetError("SOURCE_NOT_PREPARED") from None
    matched = VERSION_PATTERN.search(text)
    if matched is None:
        raise LocalTargetError("SOURCE_VERSION_UNRESOLVED")
    return matched.group(1)


def _candidate(
    rule: MattermostRule, text: str, relative: str, file_hash: str,
) -> dict[str, Any]:
    route_line = _line(text, rule.route_token)
    handler_line = _line(text, "func " + rule.handler)
    if handler_line is None:
        handler_line = _line(text, "func " + rule.handler.replace("update", "update"))
    assertions = {
        "route_exists": route_line is not None,
        "handler_resolved": _line(text, "func " + rule.handler) is not None,
        "authorization_path_resolved": all(token in _function_body(text, rule.handler) for token in rule.auth_tokens),
        "data_access_path_resolved": all(token in _function_body(text, rule.handler) for token in rule.data_tokens),
    }
    source_ok = all(assertions.values())
    if not source_ok:
        static_status = "BLOCKED_STATIC"
        reasons = ["missing_" + key for key, present in assertions.items() if not present]
    elif rule.automatic_safe:
        static_status = "NEEDS_LOCAL_VALIDATION"
        reasons = ["source_trace_supports_bounded_local_comparison"]
    else:
        static_status = "NEEDS_MANUAL_SCENARIO"
        reasons = ["mutation_not_allowed_in_automatic_validation"]
    locations = []
    for symbol, line in (("route", route_line), (rule.handler, handler_line)):
        if line is not None:
            locations.append({
                "symbol": symbol,
                "location": f"{relative}:{line}",
                "sha256": file_hash,
            })
    return {
        "candidate_id": rule.candidate_id,
        "baseline_candidate": rule.baseline_candidate,
        "discovery_class": rule.discovery_class,
        "route": {
            "method": rule.method,
            "path": rule.route,
            "location": f"{relative}:{route_line}" if route_line else relative,
        },
        "handler": {
            "symbol": rule.handler,
            "location": f"{relative}:{handler_line}" if handler_line else relative,
        },
        "authorization_path": list(rule.auth_tokens),
        "data_access_path": list(rule.data_tokens),
        "security_invariant": rule.security_invariant,
        "control_hypothesis": rule.control_hypothesis,
        "probe_hypothesis": rule.probe_hypothesis,
        "source_assertions": assertions,
        "source_facts": locations,
        "static_status": static_status,
        "static_reasons": reasons,
        "root_cause_key": rule.root_cause_key,
    }


def _line(text: str, token: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if token in line:
            return number
    return None


def _function_body(text: str, symbol: str) -> str:
    marker = "func " + symbol
    start = text.find(marker)
    if start < 0:
        return ""
    following = text.find("\nfunc ", start + len(marker))
    return text[start: following if following >= 0 else len(text)]
