import asyncio
import importlib.util
import json
import plistlib
from pathlib import Path
import subprocess
import sys
import zipfile
import pytest
import yaml
from ctf_mcp.config import Rejected
from ctf_mcp.engine import Engine
from ctf_mcp.records import REVIEW_STATUSES
from ctf_mcp.server import create_server
from conftest import ROOT


def result(settings, tool, path, **options):
    return Engine(settings).analyze(tool, path, **options)["payload"]["result"]


def test_new_candidate_states_and_provenance_preserve_old_records(settings):
    engine = Engine(settings)
    evidence = engine.analyze("har", "sample.har")
    saved = (settings.results_root / (evidence["id"] + ".json")).read_bytes()
    p = evidence["provenance"]
    assert p["analysis_id"] == evidence["id"] and p["timestamp_utc"].endswith("+00:00")
    assert len(p["input_sha256"]) == 64 and p["identity_label"] == "not_applicable"
    assert p["tool_result_path"] == evidence["id"] + ".json" and p["redaction_status"]
    candidate = dict(project="demo", title="Observation", facts="Synthetic evidence", concerns="Needs review",
        assumptions="No live validation", counterarguments="Fixture may be intentional", missing_evidence="Runtime behavior",
        remediation="Review configuration", evidence_ids=[evidence["id"]])
    for state in REVIEW_STATUSES:
        record = engine.records.candidate({**candidate, "review_status": state})
        assert record["payload"]["review_status"] == state
    with pytest.raises(Rejected):engine.records.candidate({**candidate, "review_status": "CONFIRMED"})
    assert (settings.results_root / (evidence["id"] + ".json")).read_bytes() == saved


def test_api_views_and_graphql_values_never_returned(settings):
    path = settings.input_root / "schema.graphql"
    path.write_text('type Query { account(id: ID!): Account } type Account { id: ID! }\nquery Read($id: ID!) { account(id: "SENSITIVE_SENTINEL") { id } }')
    output = result(settings, "graphql_document_summary", path.name)
    assert output["observations"]["operations"][0]["operation"] == "query"
    assert output["observations"]["operations"][0]["variable_names"] == ["id"]
    assert "SENSITIVE_SENTINEL" not in json.dumps(output)
    assert len(result(settings, "graphql_schema_summary", path.name)["observations"]["types"]) == 2
    assert result(settings, "openapi_operations", "api.json")["observations"]
    after = json.loads((settings.input_root / "api.json").read_text())
    after["paths"]["/new"] = {"post": {"responses": {"200": {"description": "ok"}}}}
    (settings.input_root / "after.json").write_text(json.dumps(after))
    changes = result(settings, "openapi_compare_versions", "api.json", after_path="after.json")
    assert changes["added"][0]["path"] == "/new"
    assert any(op["method"] == "POST" for op in result(settings, "openapi_sensitive_operations", "after.json")["observations"])
    path.write_text("query { broken(")
    with pytest.raises(Rejected, match="graphql"):result(settings, "graphql_document_summary", path.name)


def test_source_ast_search_and_no_execution(settings):
    source = settings.input_root / "review.py"
    source.write_text('import pathlib\nfrom auth import guard\n@app.get("/example")\ndef endpoint():\n    return eval("SYNTHETIC_SENTINEL")\n')
    review = result(settings, "source_security_scan", source.name)
    assert review["reviews"][0]["result"]["structure"]["parser"] == "python.ast"
    assert result(settings, "source_entrypoints", source.name)["reviews"][0]["result"]["entrypoints"][0]["name"] == "endpoint"
    imports = result(settings, "source_dependency_map", source.name)["reviews"][0]["result"]["imports"]
    assert {x["module"] for x in imports} == {"pathlib", "auth"}
    search = result(settings, "source_search", source.name, query="SYNTHETIC_SENTINEL")
    assert search["reviews"][0]["line_numbers"] == [5]
    assert "SYNTHETIC_SENTINEL" not in json.dumps(search)
    source.write_text('password = "NEVER_RETURN_THIS"\n')
    assert result(settings, "source_secret_indicators", source.name)["reviews"][0]["values_withheld"]
    with pytest.raises(Rejected):result(settings, "source_search", "../escape.py", query="a")
    with pytest.raises(Rejected):result(settings, "source_search", source.name, query="a\nb")


@pytest.mark.parametrize("view,path", [("android_permissions", "sample.apk"), ("android_manifest", "sample.aab"),
    ("android_exported_components", "sample.apk"), ("android_network_security", "sample.apk"),
    ("android_certificate_info", "sample.apk"), ("android_find_deeplinks", "sample.apk"),
    ("ios_info_plist", "sample.ipa"), ("ios_url_schemes", "sample.ipa"), ("ios_ats_config", "sample.ipa"),
    ("ios_entitlements", "entitlements.plist"), ("ios_frameworks", "sample.ipa"), ("binary_identify", "sample.elf"),
    ("binary_imports", "sample.exe"), ("binary_exports", "sample.macho"), ("binary_strings", "sample.elf")])
def test_platform_views_and_malformed_input(settings, view, path):
    assert "observations" in result(settings, view, path)
    (settings.input_root / "malformed").write_bytes(b"broken")
    with pytest.raises(Rejected):result(settings, view, "malformed")


def test_ci_iac_and_generated_sbom(settings):
    (settings.input_root / "workflow.yml").write_text('on: pull_request_target\npermissions: write-all\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@main\n')
    rules = {x["rule"] for x in result(settings, "github_actions_review", "workflow.yml")["concerns"]}
    assert {"ci.privileged-pr-trigger", "ci.write-all", "ci.unpinned-action"} <= rules
    (settings.input_root / "main.tf").write_text('resource "sample" "test" { publicly_accessible = true }')
    assert result(settings, "terraform_review", "main.tf")["concerns"]
    bom = result(settings, "sbom_generate", "package-lock.json")["observations"]
    assert bom["bomFormat"] == "CycloneDX" and bom["components"][0]["name"]


def test_ios_macho_view_reads_only_selected_bundle_executable(settings):
    package = settings.input_root / "executable.ipa"
    def write(binary):
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps({
                "CFBundleIdentifier": "org.example.fixture", "CFBundleExecutable": "Fixture"}))
            if binary is not None:archive.writestr("Payload/Fixture.app/Fixture", binary)
    write((settings.input_root / "sample.macho").read_bytes())
    assert result(settings, "ios_macho_info", package.name)["observations"][0]["analysis"]["observations"][0]["format"] == "Mach-O"
    write(None)
    assert result(settings, "ios_macho_info", package.name)["observations"][0]["status"] == "EXECUTABLE_NOT_PROVIDED"
    write((settings.input_root / "sample.elf").read_bytes())
    with pytest.raises(Rejected, match="ipa_executable_not_macho"):result(settings, "ios_macho_info", package.name)


def test_tmpfs_mount_options_remain_one_string():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for svc in compose["services"].values():
        for mount in svc.get("tmpfs", []):
            assert mount.startswith("/tmp:rw,") and ",nosuid," in mount and ",mode=1777" in mount
    # A YAML parser alone accepted the old broken sequence. Inspect resolved mounts too.
    compose_cli = Path("/tmp/finder-compose")
    if compose_cli.is_file():
        completed = subprocess.run([str(compose_cli), "--profile", "*", "config", "--format", "json"], cwd=ROOT,
            capture_output=True, text=True, timeout=30, check=True)
        parsed = json.loads(completed.stdout)
        for svc in parsed["services"].values():
            assert all(m.startswith("/tmp:") and "mode=1777" in m for m in svc.get("tmpfs", []))


def test_installed_command_works_from_unrelated_directory_without_overwrite(tmp_path):
    spec = importlib.util.spec_from_file_location("installer", ROOT / "scripts/install_command.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    project = tmp_path / "project with spaces"; (project / "scripts").mkdir(parents=True)
    (project / "scripts/finder.sh").write_text('#!/bin/sh\nprintf "%s\\n" "${1:-run}"\n')
    config = tmp_path / ".zshrc";config.write_text("# Existing settings\n")
    command, entry = module.install(tmp_path / "bin", config, project)
    original = config.read_bytes()
    module.install(tmp_path / "bin", config, project)
    assert config.read_bytes() == original and original.startswith(b"# Existing settings\n")
    for action in [None, "build", "login", "status", "doctor", "stop"]:
        proc = subprocess.run([str(command)] + ([action] if action else []), cwd="/tmp", capture_output=True, text=True, check=True)
        assert proc.stdout.strip() == (action or "run")
    command.write_text("existing unrelated command")
    with pytest.raises(ValueError):module.install(tmp_path / "bin", config, project)


def test_new_tools_list_and_call(settings):
    async def run():
        server = create_server(settings)
        names = {tool.name for tool in await server.list_tools()}
        assert {"source_search", "openapi_compare_versions", "graphql_document_summary", "github_actions_review", "sbom_generate"} <= names
        value = await server.call_tool("openapi_summary", {"path": "api.json"})
        assert value and not getattr(value, "isError", False)
    asyncio.run(run())
