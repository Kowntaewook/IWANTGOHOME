"""Dispatch for incremental fixed-purpose offline tools, within the existing worker."""
from . import artifacts
from .api_analysis import openapi_view, graphql_view, compare_openapi
from .platform_views import ANDROID_VIEWS, IOS_VIEWS, BINARY_VIEWS, android_view, ios_view, binary_view
from .source_analysis import source_view, infrastructure_view, sbom
from .records import digest

OPENAPI_VIEWS = {"openapi_summary", "openapi_operations", "openapi_auth_schemes", "openapi_sensitive_operations"}
GRAPHQL_VIEWS = {"graphql_document_summary", "graphql_operations_from_file", "graphql_schema_summary"}
SOURCE_VIEWS = {"source_search", "source_security_scan", "source_secret_indicators", "source_entrypoints", "source_dependency_map", "android_search_code", "android_find_urls", "android_find_webviews"}
INFRA_VIEWS = {"dockerfile_review", "compose_review", "github_actions_review", "terraform_review", "kubernetes_manifest_review"}
ALIASES = {"source_tree": "source_tree", "source_diff_review": "diff", "dependency_inventory": "dependencies", "dependency_lockfile_summary": "dependencies"}
EXTENDED = OPENAPI_VIEWS | GRAPHQL_VIEWS | SOURCE_VIEWS | INFRA_VIEWS | ANDROID_VIEWS | IOS_VIEWS | BINARY_VIEWS | {"openapi_compare_versions", "sbom_generate", "android_decompile_summary", "ghidra_analyze"}


def analyze(reader, request):
    view, path, limits = request["analyzer"], request["path"], reader.limits
    from .native_tools import jadx_review, ghidra_review
    if view == "ghidra_analyze":return ghidra_review(reader, path)
    if view == "android_decompile_summary" or view in {"android_search_code", "android_find_urls", "android_find_webviews"} and path.lower().endswith((".apk", ".aab")):
        return jadx_review(reader, path, view, request.get("query"))
    if view in SOURCE_VIEWS:return source_view(reader, path, view, request.get("query"))
    data = reader.read(path)
    input_info = {"path": path, "bytes": len(data), "sha256": digest(data)}
    if view in OPENAPI_VIEWS:result = openapi_view(data, limits, view)
    elif view in GRAPHQL_VIEWS:result = graphql_view(data, limits, view)
    elif view in ANDROID_VIEWS:result = android_view(data, limits, view)
    elif view in IOS_VIEWS:result = ios_view(data, limits, view)
    elif view in BINARY_VIEWS:result = binary_view(data, limits, view)
    elif view in INFRA_VIEWS:result = infrastructure_view(data, limits, view)
    elif view == "sbom_generate":result = sbom(data, limits)
    elif view == "openapi_compare_versions":
        after = reader.read(request["after_path"])
        input_info["after"] = {"path": request["after_path"], "sha256": digest(after)}
        result = compare_openapi(data, after, limits)
    else:raise AssertionError("unregistered offline view")
    return {"analyzer": view, "input": input_info, "result": result}


def register(mcp, engine, role, annotations):
    from typing import Any
    names = set()
    if role == "analysis":
        names |= OPENAPI_VIEWS | GRAPHQL_VIEWS | INFRA_VIEWS | (SOURCE_VIEWS - {"source_search", "android_search_code", "android_find_urls", "android_find_webviews"}) | (IOS_VIEWS - {"ios_macho_info"})
        names |= set(ALIASES) | {"sbom_generate"}
    if role in {"platform", "android"}:names |= ANDROID_VIEWS | {"android_find_urls", "android_find_webviews"}
    if role in {"platform", "binary"}:names |= BINARY_VIEWS | {"ios_macho_info"}
    def add(name):
        def tool(path: str) -> dict[str, Any]:
            return engine.analyze(ALIASES.get(name, name), path)
        tool.__name__ = name
        tool.__doc__ = "Inspect authorized local input with " + name + "; return minimized immutable evidence. No target execution or network requests."
        mcp.tool(annotations=annotations)(tool)
    for name in sorted(names):add(name)
    if role == "analysis":
        @mcp.tool(annotations=annotations)
        def source_search(path: str, query: str) -> dict[str, Any]:
            """Find a bounded literal in local source; return locations without matching secret values."""
            return engine.analyze("source_search", path, query=query)
        @mcp.tool(annotations=annotations)
        def openapi_compare_versions(before_path: str, after_path: str) -> dict[str, Any]:
            """Compare two local OpenAPI contracts without making requests or resolving external references."""
            return engine.analyze("openapi_compare_versions", before_path, after_path=after_path)
    if role in {"platform", "android"}:
        @mcp.tool(annotations=annotations)
        def android_search_code(path: str, query: str) -> dict[str, Any]:
            """Find literal locations in provided Android source/decompiled output without executing it."""
            return engine.analyze("android_search_code", path, query=query)
