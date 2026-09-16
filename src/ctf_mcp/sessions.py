"""Private persistent browser directories and sanitized stored-observation comparisons."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
from .config import Rejected
from .records import valid_id
from .research_policy import IDENTITIES
from .safety import SafeRoot, bounded_tree


class SessionStore:
    def __init__(self, settings, program=None):
        self.settings = settings
        self.root = settings.browser_root
        if self.root is None:raise Rejected("browser_session_volume_required")
        roots = [settings.input_root, settings.results_root, settings.grants_root]
        if settings.programs_root is not None:roots.append(settings.programs_root)
        if self.root.is_symlink() or not self.root.is_dir():raise Rejected("unsafe_browser_session_root")
        resolved = self.root.resolve()
        if any(resolved == p.resolve() or resolved in p.resolve().parents or p.resolve() in resolved.parents for p in roots):
            raise Rejected("browser_root_must_be_disjoint")
        if program is not None:
            from .programs import program_id
            for part in ("programs", program_id(program)):
                self.root = self.root / part
                self.root.mkdir(mode=0o700, exist_ok=True)
                if self.root.is_symlink() or not self.root.is_dir():raise Rejected("unsafe_browser_session_path")
                self.root.chmod(0o700)

    def directory(self, identity):
        if identity not in IDENTITIES:raise Rejected("invalid_identity_label")
        path = self.root / identity
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():raise Rejected("unsafe_browser_session_path")
        path.chmod(0o700)
        return path

    @contextmanager
    def locked(self, identity):
        path = self.directory(identity)
        fd = os.open(path / ".finder-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected("browser_identity_in_use") from None
            yield path
        finally:os.close(fd)

    def import_state(self, identity, raw):
        # Human-only local CLI; no MCP accepts cookies, tokens, storage contents or paths.
        if len(raw) > 2 * 1024 * 1024:raise Rejected("session_import_limit")
        try:state = bounded_tree(json.loads(raw))
        except (ValueError, TypeError):raise Rejected("invalid_browser_storage_state") from None
        if not isinstance(state, dict) or set(state) - {"cookies", "origins"}:raise Rejected("invalid_browser_storage_state")
        if identity == "anonymous":raise Rejected("anonymous_session_cannot_import_credentials")
        if not isinstance(state.get("cookies", []), list) or not isinstance(state.get("origins", []), list):raise Rejected("invalid_browser_storage_state")
        with self.locked(identity) as directory:
            # One seed per identity; importing again requires a new identity directory
            # chosen by the human outside MCP, rather than silently changing accounts.
            fd = os.open(directory / "import-state.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:f.write(raw)
        return {"identity_label": identity, "status": "imported", "credential_values_returned": False}

    def seed(self, directory):
        if (directory / ".import-applied").exists():return None
        if not (directory / "import-state.json").exists():return None
        return json.loads(SafeRoot(directory, self.settings.limits).read("import-state.json", 2 * 1024 * 1024))


def compare_sessions(records, user_a_id, user_b_id):
    before, after = records.read(user_a_id), records.read(user_b_id)
    for record, identity in ((before, "user_a"), (after, "user_b")):
        if record["kind"] != "analysis" or record["payload"].get("analyzer") != "web_spa" or record["payload"].get("identity_label") != identity:
            raise Rejected("matching_user_a_and_user_b_observations_required")
    if before["payload"].get("program") != after["payload"].get("program"):
        raise Rejected("same_program_observations_required")
    def structures(record):
        events = record["payload"]["result"].get("observations", [])
        return [{k: e.get(k) for k in ("url", "method", "resource_type", "status", "request_shape", "response_shape", "response_security")} for e in events if e.get("event") == "response"]
    a, b = structures(before), structures(after)
    differences = []
    for index in range(max(len(a), len(b))):
        x, y = a[index] if index < len(a) else None, b[index] if index < len(b) else None
        if x != y:differences.append({"observation_index": index, "user_a": x, "user_b": y})
    return records.save("session_comparison", {**({"program": before["payload"]["program"]} if "program" in before["payload"] else {}), "FACTS": {"user_a_evidence": user_a_id, "user_b_evidence": user_b_id,
        "user_a_response_count": len(a), "user_b_response_count": len(b), "requests_replayed": 0},
        "DIFFERENCES": differences,
        "POSSIBLE_SECURITY_RELEVANCE": ["Different response structures or status codes can inform a human authorization review; no finding is confirmed."],
        "MISSING_EVIDENCE": ["A human must confirm both observations represent the same normal action and intended role policy.",
            "Account data, timing, feature flags, request ordering and incomplete loads can explain differences.",
            "Object identifiers and request parameters were not changed or cross-used between accounts."]})
