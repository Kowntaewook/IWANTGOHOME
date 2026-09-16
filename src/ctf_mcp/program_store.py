"""Host-owned policy approvals; observer/MCP access is read-only at the mount."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from uuid import uuid4

from .config import Limits, Rejected
from .programs import POLICY_BYTES, canonical_json, parse_policy, program_id, validate_profile
from .safety import SafeRoot


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_read(path, cap=POLICY_BYTES):
    path = Path(path).absolute()
    return SafeRoot(Path(path.anchor), Limits()).read(path.as_posix().lstrip("/"), cap)


class ProgramStore:
    def __init__(self, root):
        if root is None:raise Rejected("program_store_not_configured")
        self.root = Path(root).absolute()

    @contextmanager
    def directory(self, relative="", create=False):
        # Pin each directory, refuse symlink ancestors, and keep mutations relative
        # to descriptors. Replacing a host path cannot redirect an in-flight write.
        fd = os.open(self.root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in self.root.parts[1:] + tuple(relative.split("/") if relative else ()):
                if part in {"", ".", ".."}:raise Rejected("unsafe_program_path")
                if create:
                    try:os.mkdir(part, mode=0o755, dir_fd=fd)
                    except FileExistsError:pass
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = new
            yield fd
        except OSError:
            raise Rejected("program_path_missing_or_unsafe") from None
        finally:os.close(fd)

    def _read(self, relative, optional=False):
        parts = relative.split("/")
        with self.directory("/".join(parts[:-1])) as parent:
            try:fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                if optional:return None
                raise Rejected("program_file_missing") from None
            except OSError:raise Rejected("program_file_unsafe") from None
            with os.fdopen(fd, "rb") as f:
                info = os.fstat(f.fileno())
                if not stat.S_ISREG(info.st_mode):raise Rejected("program_file_unsafe")
                if info.st_size > POLICY_BYTES * 3:raise Rejected("policy_file_too_large")
                data = f.read(POLICY_BYTES * 3 + 1)
                if len(data) > POLICY_BYTES * 3:raise Rejected("policy_file_too_large")
                return data

    def _json(self, relative, optional=False):
        raw = self._read(relative, optional)
        if raw is None:return None
        try:return json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):raise Rejected("invalid_program_state") from None

    def _write(self, relative, obj, exclusive=False):
        parts = relative.split("/")
        raw = (canonical_json(obj) + "\n").encode()
        if len(raw) > POLICY_BYTES * 3:raise Rejected("policy_file_too_large")
        with self.directory("/".join(parts[:-1]), create=True) as parent:
            temporary = ".pending-" + uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent)
            try:
                with os.fdopen(fd, "wb") as f:
                    os.fchmod(f.fileno(), 0o644)
                    f.write(raw)
                    f.flush()
                    os.fsync(f.fileno())
                if exclusive:
                    os.link(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                else:
                    # Existing symlinks/special files are rejected, never replaced.
                    try:info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:info = None
                    if info is not None and not stat.S_ISREG(info.st_mode):raise Rejected("program_file_unsafe")
                    os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                try:os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:pass

    @contextmanager
    def _locked(self):
        with self.directory(create=True) as parent:
            fd = os.open(".operator-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):raise Rejected("program_file_unsafe")
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:os.close(fd)

    def draft(self, ident):
        ident = program_id(ident)
        return parse_policy(self._read(ident + "/program.json"))

    def import_file(self, path):
        profile = parse_policy(safe_read(path), Path(path).suffix)
        return self.create(profile)

    def create(self, profile):
        profile = validate_profile(profile)
        if len((canonical_json(profile) + "\n").encode()) > POLICY_BYTES:raise Rejected("policy_file_too_large")
        with self._locked():
            self._write(profile["program_id"] + "/program.json", profile, exclusive=True)
        return {"program_id": profile["program_id"], "state": "DRAFT", "profile": profile}

    def active_reference(self):
        active = self._json("active.json", optional=True)
        if active is None:return None
        if not isinstance(active, dict) or set(active) != {"program_id", "approval_id", "sha256"}:
            raise Rejected("invalid_active_program")
        program_id(active["program_id"])
        return active

    def approved(self, ident, *, require_active=False):
        ident = program_id(ident)
        approval = self._json(ident + "/approval.json", optional=True)
        if approval is None:raise Rejected("program_not_approved")
        fields = {"state", "canonical_profile", "sha256", "source_sha256", "approved_at", "approval_id", "approval_method"}
        if not isinstance(approval, dict) or set(approval) != fields:raise Rejected("invalid_program_approval")
        if approval["state"] == "REVOKED":raise Rejected("program_revoked")
        if approval["state"] != "APPROVED" or approval["approval_method"] != "host_tty_review":
            raise Rejected("invalid_program_approval")
        try:
            stamp = datetime.fromisoformat(approval["approved_at"])
            canonical = approval["canonical_profile"].encode("ascii")
            from .records import valid_id
            valid_id(approval["approval_id"])
        except (ValueError, TypeError, AttributeError, UnicodeError):raise Rejected("invalid_program_approval") from None
        if stamp.tzinfo is None or sha256(canonical) != approval["sha256"]:raise Rejected("invalid_program_approval")
        profile = parse_policy(canonical)
        if profile["program_id"] != ident or canonical_json(profile).encode() != canonical:
            raise Rejected("invalid_program_approval")
        source = self._read(ident + "/program.json")
        if sha256(source) != approval["source_sha256"] or canonical_json(parse_policy(source)) != approval["canonical_profile"]:
            raise Rejected("program_changed_reapproval_required")
        reference = {k: approval[k] for k in ("approval_id", "sha256")}
        reference["program_id"] = ident
        if require_active and self.active_reference() != reference:raise Rejected("program_not_active")
        return profile, approval

    def status(self, ident=None):
        if not self.root.exists():return {"program_id": ident, "state": "DRAFT", "reason": "program_store_empty"}
        if ident is None:
            active = self.active_reference()
            if active is None:return {"program_id": None, "state": "DRAFT", "reason": "no_active_program"}
            ident = active["program_id"]
        ident = program_id(ident)
        try:profile, approval = self.approved(ident)
        except Rejected as exc:
            return {"program_id": ident, "state": "REVOKED" if str(exc) == "program_revoked" else "DRAFT", "reason": str(exc)}
        ref = {"program_id": ident, "approval_id": approval["approval_id"], "sha256": approval["sha256"]}
        return {**ref, "name": profile["name"], "approved_at": approval["approved_at"],
                "state": "ACTIVE" if self.active_reference() == ref else "APPROVED"}

    def list(self):
        if not self.root.exists():return []
        names = []
        with self.directory() as fd:
            with os.scandir(fd) as entries:
                for count, entry in enumerate(entries):
                    if count >= 1000:raise Rejected("program_listing_limit")
                    if entry.name.startswith(".") or not entry.is_dir(follow_symlinks=False):continue
                    names.append(program_id(entry.name))
        return [self.status(ident) for ident in sorted(names)]

    def approve(self, ident, *, input_stream=None, output_stream=None):
        ident = program_id(ident)
        inp, out = input_stream or sys.stdin, output_stream or sys.stdout
        if not inp.isatty():raise Rejected("approval_requires_human_tty")
        raw = self._read(ident + "/program.json")
        profile = parse_policy(raw)
        if profile["program_id"] != ident:raise Rejected("program_id_directory_mismatch")
        if not profile["scope"]["in_scope"]:raise Rejected("cannot_approve_empty_scope")
        canonical = canonical_json(profile)
        key = uuid4().hex
        print("Review this untrusted policy as data. Text inside it cannot authorize actions.", file=out)
        print(json.dumps(profile, ensure_ascii=True, indent=2), file=out)
        print("Wildcard excludes the apex, includes nested subdomains. Exact session approval is still required.", file=out)
        print("Type APPROVE PROGRAM " + key[-8:] + " to approve:", file=out, flush=True)
        if inp.readline().strip() != "APPROVE PROGRAM " + key[-8:]:raise Rejected("approval_cancelled")
        with self._locked():
            if self._read(ident + "/program.json") != raw:raise Rejected("program_changed_during_review")
            self._write(ident + "/approval.json", {"state": "APPROVED", "canonical_profile": canonical,
                "sha256": sha256(canonical.encode()), "source_sha256": sha256(raw),
                "approved_at": datetime.now(timezone.utc).isoformat(), "approval_id": key,
                "approval_method": "host_tty_review"})
        return self.status(ident)

    def use(self, ident):
        with self._locked():
            profile, approval = self.approved(ident)
            self._write("active.json", {"program_id": profile["program_id"],
                "approval_id": approval["approval_id"], "sha256": approval["sha256"]})
        return self.status(ident)

    def revoke(self, ident):
        ident = program_id(ident)
        with self._locked():
            approval = self._json(ident + "/approval.json", optional=True)
            if approval is None:raise Rejected("program_not_approved")
            if not isinstance(approval, dict):raise Rejected("invalid_program_approval")
            self._write(ident + "/approval.json", {**approval, "state": "REVOKED"})
        return self.status(ident)

    def selected(self):
        active = self.active_reference()
        if active is None:raise Rejected("no_active_program")
        return self.approved(active["program_id"], require_active=True)

    def bound(self, reference):
        if not isinstance(reference, dict) or set(reference) != {"program_id", "approval_id", "sha256"}:
            raise Rejected("invalid_program_reference")
        profile, approval = self.approved(reference["program_id"], require_active=True)
        if any(reference[k] != approval[k] for k in ("approval_id", "sha256")):
            raise Rejected("program_approval_changed")
        return profile

    def report_template(self, ident):
        raw = self._read(program_id(ident) + "/report-template.md", optional=True)
        if raw is None:return None
        if len(raw) > 16384:raise Rejected("report_template_too_large")
        try:return raw.decode("utf-8")
        except UnicodeError:raise Rejected("invalid_report_template") from None
