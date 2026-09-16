"""Human-owned session policies and limits; never writable through model tools."""
from collections import deque
from contextlib import contextmanager
import ipaddress
import re
import threading
import time
from urllib.parse import urlsplit
from .config import Rejected

IDENTITIES = {"anonymous", "user_a", "user_b"}
BUDGET_DEFAULTS = {"max_requests_per_minute": 30, "max_concurrent_requests": 2,
    "max_total_requests_per_session": 60, "max_download_bytes": 8 * 1024 * 1024,
    "max_response_bytes": 2 * 1024 * 1024, "max_runtime_seconds": 45}
BUDGET_CEILINGS = {"max_requests_per_minute": 120, "max_concurrent_requests": 4,
    "max_total_requests_per_session": 300, "max_download_bytes": 32 * 1024 * 1024,
    "max_response_bytes": 8 * 1024 * 1024, "max_runtime_seconds": 120}


def origin(url):
    u = urlsplit(url)
    scheme = {"ws": "http", "wss": "https"}.get(u.scheme, u.scheme)
    return scheme, u.hostname, u.port or (443 if scheme == "https" else 80)


def session_plan(obj):
    from .web import canonical_url
    required = {"start_url", "allowed_urls", "excluded_urls", "identity_label"}
    optional = set(BUDGET_DEFAULTS) | {"private_cidrs", "allow_private_targets", "credential_origin", "observation_seconds",
        "allowed_post_requests", "max_requests", "max_bytes", "seconds", "program", "allowed_methods"}
    if not isinstance(obj, dict) or not required <= obj.keys() or obj.keys() - required - optional:
        raise Rejected("invalid_session_plan_fields")
    if obj["identity_label"] not in IDENTITIES:raise Rejected("invalid_identity_label")
    plan = {**BUDGET_DEFAULTS, **obj}
    if "program" in plan:
        from .programs import SAFE_METHODS, program_id
        ref = plan["program"]
        if not isinstance(ref, dict) or set(ref) != {"program_id", "approval_id", "sha256"}:
            raise Rejected("invalid_program_reference")
        program_id(ref["program_id"])
        if not isinstance(ref["approval_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", ref["approval_id"]):
            raise Rejected("invalid_program_reference")
        if not isinstance(ref["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]):
            raise Rejected("invalid_program_reference")
        methods = plan.setdefault("allowed_methods", sorted(SAFE_METHODS))
        if not isinstance(methods, list) or not methods or any(not isinstance(m, str) or m not in SAFE_METHODS for m in methods):
            raise Rejected("program_method_blocked")
        plan["allowed_methods"] = sorted(set(methods))
    elif "allowed_methods" in plan:
        raise Rejected("program_reference_required_for_methods")
    for field, maximum in BUDGET_CEILINGS.items():
        if type(plan[field]) is not int or not 1 <= plan[field] <= maximum:raise Rejected("invalid_session_budget")
    if plan["max_response_bytes"] > plan["max_download_bytes"]:raise Rejected("invalid_web_byte_limits")
    for field in ("allowed_urls", "excluded_urls"):
        if not isinstance(plan[field], list) or len(plan[field]) > 300:raise Rejected("invalid_session_url_list")
    plan["allowed_urls"] = sorted({canonical_url(u, browser=True) for u in plan["allowed_urls"]})
    if not all(isinstance(u, str) and len(u) <= 2048 for u in plan["excluded_urls"]):raise Rejected("invalid_exclusions")
    plan["start_url"] = canonical_url(plan["start_url"], browser=True)
    if urlsplit(plan["start_url"]).scheme not in {"http", "https"} or plan["start_url"] not in plan["allowed_urls"]:
        raise Rejected("start_url_not_allowlisted")
    plan["credential_origin"] = canonical_url(plan.get("credential_origin", plan["start_url"]), browser=True)
    if origin(plan["credential_origin"]) != origin(plan["start_url"]):raise Rejected("credential_origin_must_match_start")
    allow_private = plan.setdefault("allow_private_targets", False)
    cidrs = plan.setdefault("private_cidrs", [])
    if type(allow_private) is not bool or not isinstance(cidrs, list) or len(cidrs) > 30:raise Rejected("invalid_private_target_policy")
    if cidrs and not allow_private:raise Rejected("explicit_allow_private_targets_required")
    try:nets = [ipaddress.ip_network(c, strict=True) for c in cidrs]
    except (TypeError, ValueError):raise Rejected("invalid_private_cidr") from None
    if any(n.prefixlen == 0 for n in nets):raise Rejected("private_cidr_too_broad")
    plan["observation_seconds"] = plan.get("observation_seconds", min(3, plan["max_runtime_seconds"]))
    if type(plan["observation_seconds"]) is not int or not 1 <= plan["observation_seconds"] <= plan["max_runtime_seconds"]:
        raise Rejected("invalid_observation_duration")
    posts = plan.setdefault("allowed_post_requests", [])
    if not isinstance(posts, list) or len(posts) > 30:raise Rejected("invalid_post_plan")
    for post in posts:
        if not isinstance(post, dict) or set(post) != {"url", "sha256"} or not re.fullmatch(r"[0-9a-f]{64}", post.get("sha256", "")):
            raise Rejected("invalid_post_plan")
        post["url"] = canonical_url(post["url"], browser=True)
        if post["url"] not in plan["allowed_urls"]:raise Rejected("post_url_not_approved")
    # Internal compatibility aliases are derived, never separate limits to bypass.
    plan.update(max_requests=plan["max_total_requests_per_session"], max_bytes=plan["max_download_bytes"], seconds=plan["max_runtime_seconds"])
    return plan


class RequestBudget:
    def __init__(self, plan, clock=time.monotonic):
        self.plan, self.clock = plan, clock
        self.started = clock()
        self.total = self.active = self.downloaded = 0
        self.recent = deque()
        self.lock = threading.Lock()

    @contextmanager
    def request(self):
        with self.lock:
            t = self.clock()
            if t - self.started >= self.plan["max_runtime_seconds"]:raise Rejected("observation_time_limit")
            while self.recent and self.recent[0] <= t - 60:self.recent.popleft()
            if self.total >= self.plan["max_total_requests_per_session"]:raise Rejected("request_limit")
            if len(self.recent) >= self.plan["max_requests_per_minute"]:raise Rejected("requests_per_minute_limit")
            if self.active >= self.plan["max_concurrent_requests"]:raise Rejected("concurrent_request_limit")
            self.total += 1;self.active += 1;self.recent.append(t)
        try:yield
        finally:
            with self.lock:self.active -= 1

    def received(self, amount):
        with self.lock:
            if self.downloaded + amount > self.plan["max_download_bytes"]:raise Rejected("response_read_limit")
            self.downloaded += amount
