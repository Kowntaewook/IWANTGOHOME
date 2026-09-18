import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.local_target_integration
@pytest.mark.skipif(os.environ.get("FINDER_RUN_LOCAL_TARGET_INTEGRATION") != "1",
                    reason="set FINDER_RUN_LOCAL_TARGET_INTEGRATION=1 on an authorized Docker host")
def test_mattermost_prepare_and_status():
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "FINDER_TARGET": "mattermost"}
    subprocess.run([str(root / "IWANTGOHOME"), "local", "prepare"], cwd=root, env=env, check=True, timeout=1800)
    result = subprocess.run([str(root / "IWANTGOHOME"), "local", "status"], cwd=root, env=env,
                            check=True, capture_output=True, text=True, timeout=10)
    assert "Source status: READY" in result.stdout
