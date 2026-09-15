"""Bounded source inspection. Only snapshotted bytes reach optional fixed tools."""
import ast
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from .artifacts import source, infrastructure, dependencies, concern
from .config import Rejected
from .records import digest
from .redaction import PATTERNS, public_url
from .safety import text_input, structured

SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".swift", ".c", ".cpp", ".h", ".go", ".rs", ".php", ".rb", ".cs", ".smali"}


def selected_sources(reader, path):
    # A lexical path check and descriptor-based opening precede any external tool.
    try:
        data = reader.read(path)
        return [(path, data)]
    except Rejected as exc:
        if str(exc) not in {"not_regular_file_or_directory", "file_missing_or_unsafe"}:raise
    result, total = [], 0
    for entry in reader.walk(path):
        if entry["kind"] != "file" or Path(entry["path"]).suffix.lower() not in SOURCE_SUFFIXES:continue
        data = reader.read(entry["path"])
        total += len(data)
        if total > reader.limits.total_bytes:raise Rejected("project_read_limit")
        result.append((entry["path"], data))
    return result


def python_structure(data):
    try:tree = ast.parse(text_input(data))
    except (SyntaxError, RecursionError):raise Rejected("invalid_python_syntax") from None
    imports, entrypoints, symbols = [], [], []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.append({"name": node.name, "line": node.lineno, "kind": type(node).__name__})
            for decorator in getattr(node, "decorator_list", []):
                call = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(call, ast.Attribute) and call.attr in {"route", "get", "post", "put", "delete", "patch", "websocket"}:
                    entrypoints.append({"name": node.name, "line": node.lineno, "decorator": call.attr})
        if isinstance(node, ast.Import):
            imports.extend({"module": item.name, "line": node.lineno} for item in node.names)
        if isinstance(node, ast.ImportFrom):imports.append({"module": "." * node.level + (node.module or ""), "line": node.lineno})
    return {"parser": "python.ast", "symbols": symbols, "entrypoints": entrypoints, "imports": imports}


def literal_locations(data, query, limits):
    if not isinstance(query, str) or not 1 <= len(query) <= 256 or "\n" in query or "\x00" in query:raise Rejected("invalid_literal_search")
    text = text_input(data)
    binary = shutil.which("rg")
    if binary:
        with tempfile.TemporaryDirectory(prefix="finder-search-") as temp:
            snapshot = Path(temp) / "snapshot.txt"; snapshot.write_bytes(data)
            result = subprocess.run([binary, "--no-config", "--fixed-strings", "--line-number", "--only-matching", "--max-count", "201", "--", query, str(snapshot)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=limits.seconds, shell=False, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if result.returncode not in {0, 1}:raise Rejected("source_search_failed")
            lines = sorted({int(line.split(b":", 1)[0]) for line in result.stdout.splitlines()})
    else:lines = [n for n, line in enumerate(text.splitlines(), 1) if query in line]
    if len(lines) > 200:raise Rejected("search_match_limit")
    return lines, "ripgrep-fixed-string" if binary else "python-fixed-string"


def source_view(reader, path, view, query=None):
    reviews, inputs, matches = [], [], 0
    for filename, data in selected_sources(reader, path):
        item = {"path": filename, "sha256": digest(data)};inputs.append(item)
        text = text_input(data)
        if view in {"source_search", "android_search_code"}:
            locations, backend = literal_locations(data, query, reader.limits)
            matches += len(locations)
            if matches > 200:raise Rejected("search_match_limit")
            if locations:reviews.append({"input": item, "line_numbers": locations, "backend": backend})
        elif view == "source_secret_indicators":
            lines = [n for n, line in enumerate(text.splitlines(), 1) if any(p.search(line) for p in PATTERNS)]
            if lines:reviews.append({"input": item, "line_numbers": lines, "values_withheld": True})
        elif view in {"android_find_urls", "android_find_webviews"}:
            pattern = r"https?://[^\s\"'<>]+" if view.endswith("urls") else r"\b(?:WebView|loadUrl|loadDataWithBaseURL|addJavascriptInterface|setJavaScriptEnabled)\b"
            found = [{"line": n, "kind": "url_reference" if view.endswith("urls") else "webview_reference",
                      **({"url": public_url(m.group())} if view.endswith("urls") else {})}
                for n, line in enumerate(text.splitlines(), 1) for m in re.finditer(pattern, line)]
            if found:reviews.append({"input": item, "references": found})
        else:
            lexical = source(data, reader.limits)
            if Path(filename).suffix == ".py":
                structure = python_structure(data)
            else:
                structure = {"parser": "lexical_hints", "symbols": lexical["observations"]["symbols"],
                    "entrypoints": lexical["observations"]["trust_boundary_hints"],
                    "imports": [{"line": n, "kind": "import_or_include_hint"} for n, line in enumerate(text.splitlines(), 1)
                        if re.search(r"^\s*(?:import\b|from\s+\S+\s+import\b|#include\b|use\s+)|\brequire\s*\(", line)]}
            if view == "source_entrypoints":result = {"parser": structure["parser"], "entrypoints": structure["entrypoints"]}
            elif view == "source_dependency_map":result = {"parser": structure["parser"], "imports": structure["imports"]}
            else:result = {"structure": structure, "review": lexical}
            reviews.append({"input": item, "result": result})
    tree_hash = digest(json.dumps(inputs, sort_keys=True).encode())
    return {"analyzer": view, "input": {"path": path, "sha256": tree_hash, "hash_kind": "ordered_file_manifest"},
        "result": {"reviews": reviews, "files_inspected": len(inputs), "limitations": [
            "No imports, project scripts, package installation or build hooks executed.",
            "Python uses AST syntax; other language boundaries/imports are lexical hints, not complete dependency or taint graphs.",
            "Search returns locations rather than source/secret values. URL references are never requested."]}}


def infrastructure_view(data, limits, view):
    review = infrastructure(data, limits)
    text = text_input(data)
    if view in {"compose_review", "github_actions_review", "kubernetes_manifest_review"}:
        obj = structured(data)
        if not isinstance(obj, dict):raise Rejected("expected_configuration_mapping")
        required = {"compose_review": "services", "github_actions_review": "jobs", "kubernetes_manifest_review": "kind"}[view]
        if required not in obj:raise Rejected("configuration_kind_mismatch")
    checks = []
    if view == "github_actions_review":
        checks = [(r"pull_request_target", "ci.privileged-pr-trigger", "A privileged pull-request trigger needs trusted-code review."),
                  (r"permissions:\s*write-all", "ci.write-all", "Workflow token permissions allow broad writes."),
                  (r"uses:\s*[^\s]+@(?![a-f0-9]{40}\b)[^\s]+", "ci.unpinned-action", "Action reference is not a full commit SHA.")]
    elif view == "terraform_review":
        if not re.search(r"\b(?:resource|module|provider|terraform|data)\s+[\"{]", text):raise Rejected("expected_terraform_configuration")
        checks = [(r"(?i)(?:acl\s*=\s*\"public-read|publicly_accessible\s*=\s*true)", "iac.public-resource", "A public access setting is present."),
                  (r"(?i)encrypted\s*=\s*false", "iac.encryption-disabled", "Encryption is explicitly disabled.")]
    elif view == "dockerfile_review" and not re.search(r"^\s*(?:ARG\b|FROM\b)", text, re.M):raise Rejected("expected_dockerfile")
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):continue
        for pattern, rule, reason in checks:
            if re.search(pattern, line):review["concerns"].append(concern(rule, {"line": n}, reason,
                "Restrict to the deployment's intended privileges and trusted inputs.", "Local fixtures and deployment overrides can alter relevance."))
    return review


def sbom(data, limits):
    review = dependencies(data, limits)
    components = []
    for item in review["observations"]["packages"]:
        name, version = item.get("name"), item.get("version")
        if not name and "name_version" in item:
            name, _, version = item["name_version"].rpartition("@")
        component = {"type": "library", "name": name or "unknown"}
        if version:component["version"] = str(version)
        components.append(component)
    return {"observations": {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components},
        "input_sha256": digest(data), "limitations": ["Generated solely from supplied lockfile/SBOM inventory; completeness and transitive reachability are not verified.",
        "No vulnerability database, registry or application execution."]}
