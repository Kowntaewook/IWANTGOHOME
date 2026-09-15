"""Local artifact parsers. No network, project imports, or program execution."""
import ast
import re
import struct
import tomllib
from pathlib import PurePosixPath
from .config import Rejected
from .redaction import PATTERNS, public_url
from .safety import structured, text_input, SafeZip


def concern(rule, location, reason, remediation, alternative):
    return {"rule": rule, "location": location, "concern": reason,
            "remediation": remediation, "counterargument": alternative,
            "review_status": "needs_review", "confirmed": False}


SECURITY_HEADERS = {"content-security-policy", "strict-transport-security", "x-content-type-options",
                    "referrer-policy", "permissions-policy", "x-frame-options"}


def header_metadata(headers):
    if not isinstance(headers, dict):
        headers = {str(x.get("name", "")).lower(): str(x.get("value", "")) for x in headers if isinstance(x, dict)}
    else:
        headers = {k.lower(): str(v) for k, v in headers.items()}
    result = {k: k in headers for k in sorted(SECURITY_HEADERS)}
    result["nosniff"] = headers.get("x-content-type-options", "").lower() == "nosniff"
    result["cookies_present"] = "set-cookie" in headers
    if "set-cookie" in headers:
        v = headers["set-cookie"].lower()
        result["cookie_attributes_observed"] = {x: x in v for x in ("secure", "httponly", "samesite")}
    return result


def har(data, _limits):
    obj = structured(data)
    try:
        entries = obj["log"]["entries"]
        if not isinstance(entries, list):
            raise ValueError()
        out = []
        for i, e in enumerate(entries):
            req, res = e["request"], e["response"]
            names = {str(x.get("name", "")).lower() for x in req.get("headers", [])}
            out.append({"entry": i, "url": public_url(req["url"]),
                        "method": method(req["method"]), "status": int(res["status"]),
                        "request_header_count": len(names),
                        "credentials_observed": bool(names & {"authorization", "cookie"} or req.get("cookies")),
                        "query_parameter_count": len(req.get("queryString", [])),
                        "request_body_present": "postData" in req,
                        "response_security": header_metadata(res.get("headers", []))})
        return {"observations": out, "limitations": ["Bodies, credential values and query values omitted.",
                "A credential header or its absence does not establish an authorization boundary.",
                "Cookie attributes across multiple Set-Cookie headers need individual review."]}
    except (TypeError, KeyError, ValueError):
        raise Rejected("invalid_har") from None


def method(value):
    return value if value in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"} else "OTHER"


def http_log(data, limits):
    text = text_input(data)
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if line.lstrip().startswith("{"):
            obj = structured(line.encode())
            if "url" not in obj or "status" not in obj:
                raise Rejected("http_log_requires_url_and_status")
            out.append({"line": n, "url": public_url(obj["url"]), "method": method(obj.get("method", "GET")),
                        "status": int(obj["status"]), "response_security": header_metadata(obj.get("headers", {}))})
        else:
            m = re.search(r'"(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ([^ ]+) HTTP/[\d.]+" (\d{3})', line)
            if m:
                out.append({"line": n, "method": m[1], "url": public_url(m[2]), "status": int(m[3])})
            else:
                raise Rejected("unsupported_http_log_format")
        if len(out) > limits.files * 20:
            raise Rejected("http_entry_limit")
    if not out:
        raise Rejected("empty_http_log")
    return {"observations": out, "limitations": ["Supports JSONL (url/status/method/headers) and common/combined access logs only.",
            "Client addresses, bodies, timestamps and credential values omitted."]}


def openapi(data, _limits):
    obj = structured(data)
    if not isinstance(obj, dict) or not str(obj.get("openapi", obj.get("swagger", ""))).startswith(("2.", "3.")):
        raise Rejected("expected_openapi_document")
    out, external = [], 0
    def refs(o):
        nonlocal external
        if isinstance(o, dict):
            if "$ref" in o and not str(o["$ref"]).startswith("#"):
                external += 1
            for v in o.values(): refs(v)
        elif isinstance(o, list):
            for v in o: refs(v)
    refs(obj)
    try:
        for path, item in obj.get("paths", {}).items():
            for verb, op in item.items():
                if verb not in {"get", "post", "put", "delete", "patch", "head", "options", "trace"}:
                    continue
                sec = op.get("security", obj.get("security", None))
                out.append({"path": public_url(path), "method": method(verb.upper()),
                            "security_declaration": "unspecified" if sec is None else "optional_or_none" if not sec or {} in sec else "declared",
                            "security_schemes": sorted({k for s in (sec or []) for k in s}),
                            "parameters": [{"name": p.get("name"), "in": p.get("in"), "required": p.get("required", False)}
                                           for p in item.get("parameters", []) + op.get("parameters", []) if isinstance(p, dict)],
                            "response_codes": list(op.get("responses", {})), "request_body_declared": "requestBody" in op})
        schemes = obj.get("components", {}).get("securitySchemes", obj.get("securityDefinitions", {}))
        return {"observations": out, "scheme_types": {k: v.get("type") for k, v in schemes.items()},
                "external_references_not_fetched": external,
                "limitations": ["Contract declarations are not evidence of runtime authorization enforcement.",
                                "No external references are resolved; referenced parameters may be incomplete."]}
    except (TypeError, AttributeError):
        raise Rejected("invalid_openapi_structure") from None


RULES = [
    ("source.dynamic-eval", re.compile(r"\b(?:eval|exec)\s*\("), "Dynamic evaluation call requires input provenance review.",
     "Use a data parser or an explicit operation mapping.", "A fixed literal or trusted compiler path can be intentional."),
    ("source.shell-flag", re.compile(r"\bshell\s*=\s*True\b"), "Shell interpretation is explicitly enabled.",
     "Pass an argument list with shell disabled.", "A fixed command without external input may have limited risk."),
    ("source.tls-verify", re.compile(r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false"), "TLS certificate verification is disabled.",
     "Configure the expected CA bundle and verify the peer.", "An isolated synthetic test may intentionally exercise this setting."),
    ("source.html-sink", re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML"), "HTML insertion sink needs a source and sanitization review.",
     "Prefer text rendering or an independently reviewed sanitizer.", "Static markup or proven sanitization can make this safe."),
    ("source.sql-format", re.compile(r"\b(?:execute|executemany)\s*\(\s*f[\"']"), "SQL uses a formatted string.",
     "Bind data values as parameters.", "Formatting a fixed identifier is not proof of untrusted input flow."),
    ("source.debug", re.compile(r"\bdebug\s*[=:]\s*(?:True|true)\b"), "Debug mode is explicitly configured.",
     "Separate development settings from deployed configuration.", "Local development configuration may be intentional."),
]


def source(data, _limits):
    text = text_input(data)
    findings, symbols, boundaries = [], [], []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", "//", "*", "/*")):
            continue
        for rule, pat, reason, fix, alt in RULES:
            if pat.search(line):
                findings.append(concern(rule, {"line": n}, reason, fix, alt))
        if any(p.search(line) for p in PATTERNS):
            findings.append(concern("source.secret-sign", {"line": n}, "A secret or personal-data pattern was observed; its value is suppressed.",
                            "Check whether real; remove from distribution and rotate exposed credentials as appropriate.", "Synthetic values and test keys can match."))
        if re.search(r"(?:@\w+\.(?:route|get|post)|\brequest\.|\breq\.|\bfetch\s*\(|\bopen\s*\(|\bsubprocess\.)", line):
            boundaries.append({"line": n, "kind": "input_io_or_route_hint"})
        m = re.search(r"(?:def|class|function)\s+([A-Za-z_$][\w$]*)", line)
        if m:
            symbols.append({"line": n, "name": m[1]})
    return {"observations": {"line_count": len(text.splitlines()), "symbols": symbols, "trust_boundary_hints": boundaries},
            "concerns": findings, "limitations": ["Reviewed local lexical rules; no taint or reachability analysis.",
            "No imports, installation hooks, build scripts or code were executed. No raw lines returned."]}


def source_map(data, limits):
    obj = structured(data)
    if not isinstance(obj, dict) or obj.get("version") != 3 or not isinstance(obj.get("sources"), list):
        raise Rejected("expected_sourcemap_v3")
    bodies = obj.get("sourcesContent", []) or []
    if len(obj["sources"]) > limits.files or len(bodies) > limits.files:
        raise Rejected("sourcemap_source_limit")
    reviews = []
    for i, body in enumerate(bodies):
        if body is not None:
            if not isinstance(body, str) or len(body.encode()) > limits.file_bytes:
                raise Rejected("invalid_embedded_source")
            reviews.append({"source_index": i, "analysis": source(body.encode(), limits)})
    return {"observations": {"source_count": len(obj["sources"]), "names_count": len(obj.get("names", [])),
                             "embedded_sources": len(reviews), "has_mappings": bool(obj.get("mappings"))},
            "reviews": reviews, "limitations": ["Source URLs never fetched; raw embedded source omitted.",
            "VLQ mappings are not decoded; review lines refer to embedded source, not generated code."]}


def diff(data, limits):
    text = text_input(data)
    if not re.search(r"^@@ -\d", text, re.M) or not re.search(r"^\+\+\+ ", text, re.M):
        raise Rejected("expected_unified_diff")
    changes, added, removed = [], [], []
    line_number, path = 0, "unknown"
    for line in text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].split("\t")[0]
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            if m: line_number = int(m[1])
        elif line.startswith("+"):
            analysis = source(line[1:].encode(), limits)
            for f in analysis["concerns"]:
                f["location"] = {"path": path, "line": line_number}
                changes.append(f)
            added.append({"path": path, "line": line_number})
            line_number += 1
        elif line.startswith("-") and not line.startswith("---"):
            if re.search(r"auth|permission|validat|sanitiz|verify|csrf", line, re.I):
                removed.append({"path": path, "kind": "removed_guard_hint"})
        elif line.startswith(" "):
            line_number += 1
    return {"observations": {"added_lines": added, "removed_guard_hints": removed}, "concerns": changes,
            "limitations": ["User-supplied unified diff; no git hooks or external diff drivers run.",
                            "Callers and removed guards require context review in the matching revision."]}


def dependencies(data, _limits):
    text = text_input(data)
    packages = []
    fmt = ""
    if text.lstrip().startswith(("{", "[")):
        try:
            obj = structured(data)
        except Rejected:
            obj = tomllib.loads(text)
    elif "[[package]]" in text:
        obj = tomllib.loads(text)
    else:
        obj = structured(data)
    if isinstance(obj, dict) and "lockfileVersion" in obj and "packages" in obj:
        fmt = "npm-package-lock"
        for path, v in obj["packages"].items():
            if path and isinstance(v, dict):
                packages.append({"name": v.get("name", path.split("node_modules/")[-1]), "version": v.get("version"), "integrity_present": "integrity" in v})
    elif isinstance(obj, dict) and isinstance(obj.get("package"), list):
        fmt = "toml-lock"
        packages = [{"name": p.get("name"), "version": p.get("version")} for p in obj["package"]]
    elif isinstance(obj, dict) and obj.get("bomFormat") == "CycloneDX":
        fmt = "cyclonedx"
        packages = [{"name": p.get("name"), "version": p.get("version"), "purl": public_url(p.get("purl", ""))} for p in obj.get("components", [])]
    elif isinstance(obj, dict) and "spdxVersion" in obj:
        fmt = "spdx"
        packages = [{"name": p.get("name"), "version": p.get("versionInfo")} for p in obj.get("packages", [])]
    elif isinstance(obj, dict) and "lockfileVersion" in obj and "snapshots" in obj:
        fmt = "pnpm-lock"
        packages = [{"name_version": k} for k in obj["snapshots"]]
    else:
        fmt = "requirements-pinned"
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):continue
            m = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)\s*(?:#.*)?", line)
            if not m:raise Rejected("unsupported_lockfile_format")
            packages.append({"name": m[1], "version": m[2]})
    return {"observations": {"format": fmt, "packages": packages}, "vulnerability_database": None,
            "external_queries": 0, "limitations": ["Version inventory only; no CVE database or reachability assessment.",
            "No registry, advisory service or package source was contacted."]}


def infrastructure(data, _limits):
    text = text_input(data)
    findings = []
    checks = [
        (r"\bprivileged\s*:\s*true", "infra.privileged", "A privileged container is configured.", "Drop privileged mode and grant only needed capabilities."),
        (r"docker\.sock", "infra.docker-socket", "Docker daemon access is referenced.", "Remove the socket mount from analysis workloads."),
        (r"network_mode\s*:\s*['\"]?host", "infra.host-network", "Host networking is configured.", "Use a dedicated bridge with bounded services."),
        (r"(?:0\.0\.0\.0/0|::/0)", "infra.public-range", "An all-address network range is configured.", "Review the associated ingress rule and restrict intended peers."),
        (r"^\s*USER\s+(?:root|0)(?:\s|$)", "infra.root-user", "The image explicitly selects root.", "Use a non-root runtime user."),
        (r"^\s*FROM\s+\S+:latest(?:\s|$)", "infra.floating-image", "An image uses the latest tag.", "Pin a reviewed version and digest."),
        (r"\b(?:allowPrivilegeEscalation|hostPID|hostIPC|hostNetwork)\s*:\s*true", "infra.host-privilege", "Host access or privilege escalation is enabled.", "Disable unused privileges."),
        (r"(?i)(?:actions?|resources?)\s*[:=]\s*\[?\s*['\"]\*['\"]", "infra.wildcard-policy", "A wildcard policy element is present.", "Scope actions and resources to the service's role."),
    ]
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):continue
        for pattern, rule, reason, fix in checks:
            if re.search(pattern, line):
                findings.append(concern(rule, {"line": n}, reason, fix, "Context, role, and deployment overrides can change exposure."))
    parsed_services = []
    if re.search(r"^services:", text, re.M):
        obj = structured(data)
        if not isinstance(obj.get("services"), dict):raise Rejected("invalid_compose")
        for name, svc in obj["services"].items():
            if not isinstance(svc, dict):raise Rejected("invalid_compose_service")
            parsed_services.append({"name": name, "read_only": svc.get("read_only", False),
                                    "privileged": svc.get("privileged", False),
                                    "user_explicit": "user" in svc,
                                    "port_mapping_count": len(svc.get("ports", [])),
                                    "cap_add_count": len(svc.get("cap_add", []))})
    return {"observations": {"line_count": len(text.splitlines()), "compose_services": parsed_services},
            "concerns": findings, "limitations": ["Text/configuration review only; no cloud access, Terraform evaluation, variable expansion or image execution."]}


def crash(data, _limits):
    text = text_input(data)
    events, frames = [], []
    for n, line in enumerate(text.splitlines(), 1):
        for kind in ("SIGSEGV", "SIGABRT", "EXC_BAD_ACCESS", "EXCEPTION_ACCESS_VIOLATION", "AddressSanitizer", "Traceback"):
            if kind in line:events.append({"line": n, "type": kind})
        if re.match(r"\s*(?:#\d+\s|\d+\s+\S+\s+0x|File \"|[0-9a-fA-F]+ [tT] )", line):
            frames.append({"line": n, "kind": "frame_or_symbol"})
    if not events and not frames:raise Rejected("unrecognized_crash_or_symbol_text")
    return {"observations": {"events": events, "frame_or_symbol_locations": frames},
            "limitations": ["No process execution, symbol server access, minidump decoding, or exploitability determination.",
                            "Raw stack text may contain personal data and is omitted."]}


def packet(data, _limits):
    magic = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    if data[:4] not in magic or len(data) < 24:raise Rejected("expected_classic_pcap")
    endian = magic[data[:4]]
    major, minor, _, _, snaplen, network = struct.unpack(endian + "HHiIII", data[4:24])
    if (major, minor) != (2, 4):raise Rejected("unsupported_pcap_version")
    pos, count, captured = 24, 0, 0
    while pos < len(data):
        if pos + 16 > len(data):raise Rejected("truncated_pcap_record")
        _, _, cap, original = struct.unpack(endian + "IIII", data[pos:pos + 16])
        if cap > snaplen or cap > original or pos + 16 + cap > len(data):raise Rejected("invalid_pcap_length")
        captured += cap; count += 1; pos += 16 + cap
    return {"observations": {"format": "pcap-2.4", "linktype": network, "snaplen": snaplen, "packet_count": count, "captured_bytes": captured},
            "limitations": ["Container metadata only; no protocol decoding, packet replay, payload output or traffic capture."]}


def archive(data, limits):
    z = SafeZip(data, limits)
    return {"observations": {"members": z.names}, "limitations": ["ZIP inventory only; not firmware unpacking or emulation.", "Nested archives are not expanded."]}


ANALYZERS = {"har": har, "http_log": http_log, "openapi": openapi, "source": source,
             "source_map": source_map, "diff": diff, "dependencies": dependencies,
             "infrastructure": infrastructure, "crash": crash, "packet": packet, "archive": archive}
