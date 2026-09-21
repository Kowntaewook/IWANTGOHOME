import http.client
import json
import os
from pathlib import Path
import subprocess

import pytest

from ctf_mcp.local_targets.base import load_adapter


@pytest.mark.local_target_integration
@pytest.mark.skipif(os.environ.get("FINDER_RUN_LOCAL_TARGET_INTEGRATION") != "1",
                    reason="set FINDER_RUN_LOCAL_TARGET_INTEGRATION=1 on an authorized Docker host")
def test_mattermost_proxy_health_and_http_semantics():
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "FINDER_TARGET": "mattermost"}
    subprocess.run([str(root / "IWANTGOHOME"), "local", "prepare"], cwd=root, env=env, check=True, timeout=1800)
    subprocess.run([str(root / "IWANTGOHOME"), "local", "up"], cwd=root, env=env, check=True, timeout=1800)
    subprocess.run([str(root / "IWANTGOHOME"), "local", "bootstrap"], cwd=root, env=env, check=True, timeout=300)
    result = subprocess.run([str(root / "IWANTGOHOME"), "local", "status"], cwd=root, env=env,
                            check=True, capture_output=True, text=True, timeout=10)
    assert "Source status: READY" in result.stdout
    assert "Health: healthy" in result.stdout
    assert "Local proxy container: running" in result.stdout

    target = load_adapter(root, "mattermost")
    password = target._load_secrets(create=False)["victim"]
    login_body = json.dumps({
        "login_id": "finder-local-victim", "password": password,
    }).encode()
    connection = http.client.HTTPConnection("127.0.0.1", 13100, timeout=10)
    try:
        connection.request("POST", "/api/v4/users/login", body=login_body, headers={
            "Accept": "application/json", "Content-Type": "application/json",
        })
        login = connection.getresponse()
        login_raw = login.read()
        token = login.getheader("Token")
        assert login.status == 200
        assert (login.getheader("Content-Type") or "").startswith("application/json")
        assert isinstance(token, str) and token
        assert isinstance(json.loads(login_raw), dict)
    finally:
        connection.close()

    connection = http.client.HTTPConnection("127.0.0.1", 13100, timeout=10)
    try:
        connection.request("GET", "/api/v4/users/me", headers={
            "Accept": "application/json", "Authorization": "Bearer " + token,
        })
        current = connection.getresponse()
        current_raw = current.read()
        assert current.status == 200
        assert (current.getheader("Content-Type") or "").startswith("application/json")
        assert json.loads(current_raw).get("username") == "finder-local-victim"
    finally:
        connection.close()
