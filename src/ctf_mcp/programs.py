"""Offline program policy validation and scope decisions. Never sends requests."""
import ipaddress
import json
import re
from urllib.parse import unquote, urlsplit

import yaml

from .config import Rejected
from .research_policy import BUDGET_CEILINGS, IDENTITIES
from .safety import NoAliasLoader, bounded_tree

POLICY_BYTES = 65536
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DEFAULT_NETWORK = {
    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
    "max_requests_per_minute": 20, "max_concurrent_requests": 2,
    "max_total_requests_per_session": 60, "max_download_bytes": 8388608,
    "max_response_bytes": 2097152, "max_runtime_seconds": 45,
}
PROHIBITED = {"automated_scanning", "dos", "ddos", "social_engineering",
              "physical_attack", "large_scale_data_access", "destructive_testing", "credential_spraying"}


def program_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise Rejected("invalid_program_id")
    return value


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise Rejected("duplicate_or_invalid_policy_key")
        result[key] = value
    return result


class PolicyLoader(NoAliasLoader):
    def construct_mapping(self, node, deep=False):
        return unique_pairs((self.construct_object(k, deep=deep), self.construct_object(v, deep=deep))
                            for k, v in node.value)


def parse_policy(raw, suffix=".json"):
    if len(raw) > POLICY_BYTES:raise Rejected("policy_file_too_large")
    try:
        text = raw.decode("utf-8")
        if suffix.lower() in {".yaml", ".yml"}:
            obj = yaml.load(text, Loader=PolicyLoader)
        elif suffix.lower() == ".json":
            obj = json.loads(text, object_pairs_hook=unique_pairs)
        else:
            raise Rejected("structured_policy_json_or_yaml_required")
        return validate_profile(bounded_tree(obj, budget=[10000]))
    except (ValueError, UnicodeError, RecursionError, TypeError, yaml.YAMLError):
        raise Rejected("invalid_program_policy") from None


def _mapping(value, keys, code):
    if not isinstance(value, dict) or set(value) - keys:raise Rejected(code)
    return value


def _strings(value, *, maximum=100, pattern=None):
    if not isinstance(value, list) or len(value) > maximum:
        raise Rejected("invalid_policy_list")
    if any(not isinstance(x, str) or not 1 <= len(x) <= 128 or
           (pattern and not re.fullmatch(pattern, x)) for x in value):
        raise Rejected("invalid_policy_list")
    return sorted(set(value))


def _host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise Rejected("invalid_scope_host")
    wildcard = value.startswith("*.")
    host = value[2:] if wildcard else value
    try:host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:raise Rejected("invalid_scope_host") from None
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s) for s in host.split(".")):
            raise Rejected("invalid_scope_host")
        # Reject alternate numeric IPv4 notations, including integer and octal forms.
        if re.fullmatch(r"[0-9.]+", host) or host.startswith("0x"):
            raise Rejected("invalid_scope_host")
    else:
        if wildcard:raise Rejected("wildcard_ip_not_supported")
        host = addr.compressed
    return ("*." if wildcard else "") + host


def _path(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 2048:
        raise Rejected("invalid_scope_path")
    # Only a trailing /* means a subtree. No regex, shell glob or URL query rules.
    prefix = value[:-1] if value.endswith("/*") else value
    if "*" in prefix or "?" in value or "#" in value:raise Rejected("invalid_scope_path")
    try:decoded = unquote(prefix, errors="strict")
    except UnicodeError:raise Rejected("invalid_scope_path") from None
    if any(c in decoded for c in "%\\?#*") or "//" in decoded or re.search(r"[\x00-\x20\x7f]", decoded):
        raise Rejected("invalid_scope_path")
    if any(s in {".", ".."} for s in decoded.split("/")):raise Rejected("invalid_scope_path")
    return decoded + ("*" if value.endswith("/*") else "")


def _rules(value, excluded=False):
    if not isinstance(value, list) or len(value) > 100:raise Rejected("invalid_scope_rules")
    rules = []
    for item in value:
        _mapping(item, {"host", "schemes", "ports", "paths"}, "invalid_scope_rule")
        if "host" not in item:raise Rejected("scope_host_required")
        rule = {"host": _host(item["host"])}
        schemes = _strings(item.get("schemes", ["http", "https", "ws", "wss"] if excluded else ["https"]))
        if not schemes or not set(schemes) <= {"http", "https", "ws", "wss"}:
            raise Rejected("invalid_scope_schemes")
        rule["schemes"] = schemes
        if "ports" in item:
            ports = item["ports"]
            if not isinstance(ports, list) or not 1 <= len(ports) <= 100 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                raise Rejected("invalid_scope_ports")
            rule["ports"] = sorted(set(ports))
        paths = item.get("paths", ["/*"] if excluded else ["/"])
        if not isinstance(paths, list) or not 1 <= len(paths) <= 100:raise Rejected("invalid_scope_paths")
        rule["paths"] = sorted({_path(p) for p in paths})
        rules.append(rule)
    return rules


def validate_profile(obj):
    _mapping(obj, {"schema_version", "program_id", "name", "policy_source", "scope", "network_policy",
                   "prohibited_actions", "excluded_finding_categories", "identities", "reporting",
                   "allow_private_targets", "private_cidrs"}, "invalid_program_fields")
    if type(obj.get("schema_version", 1)) is not int or obj.get("schema_version", 1) != 1:
        raise Rejected("unsupported_program_schema")
    ident = program_id(obj.get("program_id"))
    name = obj.get("name", ident)
    if not isinstance(name, str) or not 1 <= len(name) <= 256 or re.search(r"[\x00-\x1f\x7f]", name):
        raise Rejected("invalid_program_name")
    source = obj.get("policy_source")
    if source is not None and (not isinstance(source, str) or len(source) > 2048 or re.search(r"[\x00-\x1f\x7f]", source)):
        raise Rejected("invalid_policy_source")
    scope = _mapping(obj.get("scope", {}), {"in_scope", "out_of_scope"}, "invalid_program_scope")
    network = _mapping(obj.get("network_policy", {}), set(DEFAULT_NETWORK), "invalid_network_policy")
    network = {**DEFAULT_NETWORK, **network}
    network["allowed_methods"] = _strings(network["allowed_methods"])
    if not network["allowed_methods"] or not set(network["allowed_methods"]) <= SAFE_METHODS:
        raise Rejected("state_changing_method_not_supported")
    for key, ceiling in BUDGET_CEILINGS.items():
        if type(network[key]) is not int or not 1 <= network[key] <= ceiling:raise Rejected("invalid_program_budget")
    if network["max_response_bytes"] > network["max_download_bytes"]:raise Rejected("invalid_web_byte_limits")
    identities = _strings(obj.get("identities", ["anonymous"]))
    if not identities or not set(identities) <= IDENTITIES:raise Rejected("invalid_identity_label")
    private = obj.get("allow_private_targets", False)
    if type(private) is not bool:raise Rejected("invalid_private_target_policy")
    cidrs = _strings(obj.get("private_cidrs", []), maximum=30)
    if cidrs and not private:raise Rejected("explicit_allow_private_targets_required")
    try:nets = [ipaddress.ip_network(c, strict=True) for c in cidrs]
    except ValueError:raise Rejected("invalid_private_cidr") from None
    if any(n.prefixlen == 0 for n in nets):raise Rejected("private_cidr_too_broad")
    reporting = _mapping(obj.get("reporting", {}), {"submission_url", "responsible_disclosure"}, "invalid_reporting_policy")
    submission = reporting.get("submission_url")
    if submission is not None:
        from .web import canonical_url
        submission = canonical_url(submission, browser=True)
    disclosure = reporting.get("responsible_disclosure", True)
    if type(disclosure) is not bool:raise Rejected("invalid_reporting_policy")
    return {"schema_version": 1, "program_id": ident, "name": name, "policy_source": source,
            "scope": {"in_scope": _rules(scope.get("in_scope", [])), "out_of_scope": _rules(scope.get("out_of_scope", []), True)},
            "network_policy": network,
            "prohibited_actions": sorted(PROHIBITED | set(_strings(obj.get("prohibited_actions", []), pattern=r"[a-z0-9][a-z0-9_-]*"))),
            "excluded_finding_categories": _strings(obj.get("excluded_finding_categories", []), pattern=r"[a-z0-9][a-z0-9_-]*"),
            "identities": identities, "allow_private_targets": private, "private_cidrs": sorted(str(n) for n in nets),
            "reporting": {"submission_url": submission, "responsible_disclosure": disclosure}}


def address_allowed(profile, value):
    addr = ipaddress.ip_address(value)
    if addr.is_multicast or addr.is_unspecified or addr.is_link_local:return False
    if addr.is_global:return True
    return profile["allow_private_targets"] and any(addr.version == n.version and addr in n
        for n in map(ipaddress.ip_network, profile["private_cidrs"]))


def scope_decision(profile, url, method="GET"):
    from .web import canonical_url
    result = {"allowed": False, "program_id": profile["program_id"], "matched_rule": None,
              "excluded_rule": None, "method_allowed": method in profile["network_policy"]["allowed_methods"],
              "network_request_sent": False}
    try:
        value = canonical_url(url, browser=True)
        u = urlsplit(value)
        host = _host(u.hostname)
    except Rejected as exc:
        return {**result, "reason": str(exc)}
    port = u.port or (443 if u.scheme in {"https", "wss"} else 80)
    path = unquote(u.path)
    def matches(rule, excluded=False):
        target = rule["host"]
        host_match = host.endswith("." + target[2:]) if target.startswith("*.") else host == target
        default_port = 443 if u.scheme in {"https", "wss"} else 80
        ports_match = port in rule["ports"] if "ports" in rule else (excluded or port == default_port)
        return host_match and u.scheme in rule["schemes"] and ports_match and any(
            path.startswith(p[:-1]) if p.endswith("/*") else path == p for p in rule["paths"])
    result["matched_rule"] = next((r for r in profile["scope"]["in_scope"] if matches(r)), None)
    result["excluded_rule"] = next((r for r in profile["scope"]["out_of_scope"] if matches(r, True)), None)
    try:addr = ipaddress.ip_address(host)
    except ValueError:private_ok = True
    else:private_ok = address_allowed(profile, str(addr))
    reason = ("program_url_excluded" if result["excluded_rule"] else
              "program_url_out_of_scope" if not result["matched_rule"] else
              "program_method_blocked" if not result["method_allowed"] else
              "private_destination_not_approved" if not private_ok else None)
    return {**result, "allowed": reason is None, "reason": reason,
            "dns_check_required_at_send": True}


def validate_program_plan(plan, profile):
    if plan["identity_label"] not in profile["identities"]:raise Rejected("program_identity_not_allowed")
    methods = plan.get("allowed_methods", [])
    if not methods or not set(methods) <= set(profile["network_policy"]["allowed_methods"]):
        raise Rejected("plan_methods_exceed_program")
    if plan.get("allowed_post_requests"):raise Rejected("program_method_blocked")
    for key in BUDGET_CEILINGS:
        if plan[key] > profile["network_policy"][key]:raise Rejected("plan_budget_exceeds_program")
    if plan["allow_private_targets"] and not profile["allow_private_targets"]:
        raise Rejected("plan_private_policy_exceeds_program")
    parents = list(map(ipaddress.ip_network, profile["private_cidrs"]))
    for net in map(ipaddress.ip_network, plan["private_cidrs"]):
        if not any(net.version == p.version and net.subnet_of(p) for p in parents):
            raise Rejected("plan_private_policy_exceeds_program")
    for url in plan["allowed_urls"]:
        for method in methods:
            decision = scope_decision(profile, url, method)
            if not decision["allowed"]:raise Rejected(decision["reason"])
    return plan
