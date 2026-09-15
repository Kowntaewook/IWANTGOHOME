"""Output minimization first; heuristic redaction is an additional layer."""
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl

PATTERNS = [
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]+", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16})"),
    re.compile(r'''(?i)["']?(?:password|passwd|secret|client[_-]?secret|api[_-]?key|(?:access|refresh|id)[_-]?token|token|session[_-]?id|authorization|cookie)["']?\s*[=:]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;"'}]+)'''),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
]
SENSITIVE_KEY = re.compile(r"(?i)^(?:password|passwd|secret|api.?key|access.?token|refresh.?token|id.?token|authorization|cookie|set-cookie|postData|sourcesContent|body|text|content)$")


def redact_text(value: str):
    value = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value)
    for p in PATTERNS:
        value = p.sub("[REDACTED]", value)
    return value


def clean(value, depth=0):
    if depth > 40:
        return "[DEPTH LIMIT]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {redact_text(str(k)): "[REDACTED]" if SENSITIVE_KEY.fullmatch(str(k)) else clean(v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v, depth + 1) for v in value]
    return value


def public_url(value: str):
    try:
        u = urlsplit(value)
        host = u.hostname or ""
        authority = ("[" + host + "]") if ":" in host else host
        if u.port:
            authority += ":" + str(u.port)
        segs = []
        for s in u.path.split("/"):
            if len(s) > 32 or re.search(r"\d{4}|@|%40", s):
                s = "[VALUE]"
            segs.append(s)
        query = "&".join(redact_text(k) + "=[REDACTED]" for k, _ in parse_qsl(u.query, keep_blank_values=True))
        return redact_text(urlunsplit((u.scheme, authority, "/".join(segs), query, "")))
    except ValueError:
        return "[INVALID URL]"
