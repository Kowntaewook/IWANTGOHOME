"""Supervisor-owned job control shared with the bounded worker process."""
import json
import os
import time
from uuid import uuid4
from .config import Rejected
from .records import valid_id
from .safety import SafeRoot


def write_control(settings, job, state, initial=False):
    path = settings.results_root / (".research-control-" + valid_id(job))
    raw = json.dumps({"state": state}).encode()
    if initial:
        with path.open("xb") as f:f.write(raw)
    else:
        temp = settings.results_root / (".control-pending-" + uuid4().hex)
        try:
            with temp.open("xb") as f:f.write(raw)
            os.replace(temp, path)
        finally:temp.unlink(missing_ok=True)


class FileControl:
    def __init__(self, settings, job, grant):
        self.reader = SafeRoot(settings.results_root, settings.limits)
        self.path = ".research-control-" + valid_id(job)
        self.grant = grant
        self.deadline = time.monotonic() + grant.plan["seconds"]

    def is_set(self):
        while True:
            self.grant.live()
            if time.monotonic() >= self.deadline:raise Rejected("observation_time_limit")
            try:state = json.loads(self.reader.read(self.path, 1024))["state"]
            except (KeyError, ValueError):raise Rejected("invalid_research_control") from None
            if state == "aborted":return True
            if state == "running":return False
            if state != "paused":raise Rejected("invalid_research_control")
            time.sleep(.05)
