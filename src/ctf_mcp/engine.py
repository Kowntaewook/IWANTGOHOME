"""Fixed worker entrypoint, process deadlines and immutable evidence envelopes."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from .config import Rejected
from .records import Records, VERSION, digest
from .safety import SafeRoot



def _playwright_browsers_path():
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if configured:
        return configured

    home = Path.home()

    if sys.platform == "darwin":
        return str(home / "Library" / "Caches" / "ms-playwright")

    return str(home / ".cache" / "ms-playwright")

def run_worker(settings, request, *, seconds=None, stop=None):
    payload = json.dumps({"settings": asdict(settings), "request": request}, default=str).encode()
    if len(payload) > 65536:raise Rejected("worker_request_limit")
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
           "HOME": "/tmp", "PLAYWRIGHT_BROWSERS_PATH": _playwright_browsers_path()}
    env["FINDER_TOOL_ROOT"] = os.environ.get("FINDER_TOOL_ROOT", "/opt/finder-tools")
    if request.get("operation") == "device":
        for key in ("FINDER_ADB_ENDPOINT", "FINDER_FRIDA_ENDPOINT"):
            if os.environ.get(key):env[key] = os.environ[key]
    deadline = time.monotonic() + (seconds or settings.limits.seconds)
    with tempfile.TemporaryFile() as output:
        proc = subprocess.Popen([sys.executable, "-m", "ctf_mcp.worker"], stdin=subprocess.PIPE,
            stdout=output, stderr=subprocess.DEVNULL, cwd=Path(__file__).resolve().parent,
            env=env, shell=False, start_new_session=True)
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
            while proc.poll() is None:
                if stop and stop.is_set():raise Rejected("observation_stopped")
                if time.monotonic() >= deadline:raise Rejected("worker_time_limit")
                try:proc.wait(timeout=0.05)
                except subprocess.TimeoutExpired:pass
            if time.monotonic() >= deadline:raise Rejected("worker_time_limit")
            if proc.returncode != 0:raise Rejected("worker_failed_or_resource_limit")
            if output.tell() > settings.limits.output_bytes:raise Rejected("worker_output_limit")
            output.seek(0)
            try:reply = json.loads(output.read(settings.limits.output_bytes + 1))
            except ValueError:raise Rejected("invalid_worker_response") from None
            if "error" in reply:raise Rejected(reply["error"])
            return reply["result"]
        finally:
            # Terminate every subprocess in this worker's process group, including
            # browser children. An observation timeout does not leave work running.
            try:os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:pass
            proc.wait()


class Engine:
    def __init__(self, settings):
        self.settings = settings
        self.records = Records(settings.results_root, settings.limits, settings.programs_root)
        self.lock = threading.BoundedSemaphore(2)

    def analyze(self, analyzer, path, **options):
        if not self.lock.acquire(blocking=False):raise Rejected("analysis_busy")
        try:
            payload = run_worker(self.settings, {"operation": "analyze", "analyzer": analyzer, "path": path, **options})
            return self.records.save("analysis", payload)
        finally:
            self.lock.release()

    def device(self, analyzer, **options):
        if not self.lock.acquire(blocking=False):raise Rejected("analysis_busy")
        try:
            payload = run_worker(self.settings, {"operation": "device", "analyzer": analyzer, **options}, seconds=15)
            return self.records.save("analysis", payload)
        finally:self.lock.release()

    def compare(self, before_id, after_id):
        before, after = self.records.read(before_id), self.records.read(after_id)
        if before["kind"] != "analysis" or after["kind"] != "analysis":raise Rejected("analysis_records_required")
        a, b = before["payload"], after["payload"]
        if a["analyzer"] != b["analyzer"]:raise Rejected("different_analyzers")
        changes = []
        def visit(x, y, location):
            if len(changes) >= 200:raise Rejected("comparison_change_limit")
            if x == y:return
            if isinstance(x, dict) and isinstance(y, dict):
                for key in sorted(x.keys() | y.keys()):visit(x.get(key), y.get(key), location + [key])
            elif isinstance(x, list) and isinstance(y, list) and len(x) == len(y):
                for i, (v, w) in enumerate(zip(x, y)):visit(v, w, location + [i])
            else:changes.append({"location": location, "before": x, "after": y})
        visit(a["result"], b["result"], [])
        return self.records.save("comparison", {"before_id": before_id, "after_id": after_id, "changes": changes})

    def context(self, path, start_line, line_count):
        if type(start_line) is not int or type(line_count) is not int or start_line < 1 or not 1 <= line_count <= 80:
            raise Rejected("invalid_context_range")
        if not self.lock.acquire(blocking=False):raise Rejected("analysis_busy")
        try:
            payload = run_worker(self.settings, {"operation": "analyze", "analyzer": "source_context", "path": path,
                "start_line": start_line, "line_count": line_count})
            return self.records.save("analysis", payload)
        finally:self.lock.release()

    def regression(self, record_id, required_headers):
        # Produces an executable offline assertion for a saved observation. It never
        # replays requests or imports the target's code. User runs it on an exported record.
        from .artifacts import SECURITY_HEADERS
        if not set(required_headers) <= SECURITY_HEADERS:raise Rejected("unsupported_security_header")
        record = self.records.read(record_id)
        if record["kind"] != "analysis" or record["payload"]["analyzer"] != "web_read":raise Rejected("web_read_record_required")
        code = ("import json\nfrom pathlib import Path\n\n"
                "def test_observed_response_security():\n"
                f"    record = json.loads(Path({(record_id + '.json')!r}).read_text())\n"
                "    result = record['payload']['result']\n"
                "    assert result['final_status'] == 200\n"
                f"    for header in {sorted(set(required_headers))!r}:\n"
                "        assert result['response_security'][header], header\n")
        return self.records.save("regression_test", {"evidence_id": record_id, "python": code,
            "instructions": "Export the referenced JSON record beside test_observation.py, then run pytest. This checks saved evidence; obtain a new human grant to observe the updated local server."})
