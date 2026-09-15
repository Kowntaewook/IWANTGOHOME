"""Local API contracts and GraphQL syntax. No network or resolver execution."""
import re
from . import artifacts
from .config import Rejected
from .safety import structured, text_input


def openapi_view(data, limits, view):
    review = artifacts.openapi(data, limits)
    obj = structured(data)
    operations = review["observations"]
    if view == "openapi_operations":
        observations = operations
    elif view == "openapi_auth_schemes":
        definitions = obj.get("components", {}).get("securitySchemes", obj.get("securityDefinitions", {}))
        observations = {name: {key: value for key, value in scheme.items()
            if key in {"type", "scheme", "in", "bearerFormat"}}
            for name, scheme in definitions.items()}
    elif view == "openapi_sensitive_operations":
        observations = [{**op, "review_reason": "State-changing verb or sensitive route vocabulary; not a vulnerability finding."}
            for op in operations if op["method"] in {"POST", "PUT", "PATCH", "DELETE"}
            or re.search(r"auth|admin|account|payment|export|upload|secret", op["path"], re.I)]
    else:
        observations = {"version": obj.get("openapi", obj.get("swagger")), "operation_count": len(operations),
            "paths_count": len(obj["paths"]), "scheme_types": review["scheme_types"],
            "methods": sorted({op["method"] for op in operations})}
    return {"observations": observations, "limitations": review["limitations"],
            "external_references_not_fetched": review["external_references_not_fetched"]}


def compare_openapi(before, after, limits):
    a = artifacts.openapi(before, limits)["observations"]
    b = artifacts.openapi(after, limits)["observations"]
    old = {(x["path"], x["method"]): x for x in a}
    new = {(x["path"], x["method"]): x for x in b}
    return {"added": [new[k] for k in sorted(new.keys() - old.keys())],
        "removed": [old[k] for k in sorted(old.keys() - new.keys())],
        "changed": [{"before": old[k], "after": new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]],
        "limitations": ["Local contract changes only. No live requests, external references, or runtime authorization validation."]}


def graphql_view(data, limits, view):
    from graphql import parse, GraphQLError
    from graphql.language.ast import OperationDefinitionNode, FragmentDefinitionNode
    try:
        doc = parse(text_input(data), max_tokens=min(limits.files * 100, 50000))
    except (GraphQLError, RecursionError):
        raise Rejected("invalid_or_excessive_graphql_document") from None
    operations, fragments, types = [], [], []
    for definition in doc.definitions:
        name = definition.name.value if getattr(definition, "name", None) else None
        line = text_input(data)[:definition.loc.start].count("\n") + 1
        if isinstance(definition, OperationDefinitionNode):
            # Names/types are structural; argument/default/variable values are never returned.
            operations.append({"name": name, "operation": definition.operation.value, "line": line,
                "variable_names": [v.variable.name.value for v in definition.variable_definitions],
                "root_fields": [s.name.value for s in definition.selection_set.selections if hasattr(s, "name")]})
        elif isinstance(definition, FragmentDefinitionNode):
            fragments.append({"name": name, "on_type": definition.type_condition.name.value, "line": line})
        else:
            fields = []
            for field in getattr(definition, "fields", ()):
                fields.append({"name": field.name.value, "argument_names": [a.name.value for a in getattr(field, "arguments", ())]})
            types.append({"name": name, "kind": definition.kind, "line": line, "fields": fields})
    if view == "graphql_schema_summary" and not types:raise Rejected("graphql_schema_definition_required")
    if view == "graphql_operations_from_file" and not operations:raise Rejected("graphql_operation_required")
    observations = {"operations": operations, "fragments": fragments, "types": types}
    if view == "graphql_schema_summary":observations = {"types": types}
    if view == "graphql_operations_from_file":observations = {"operations": operations, "fragments": fragments}
    return {"observations": observations, "parser": "graphql-core",
        "limitations": ["Syntax/structure analysis only; schema validation and execution are not performed.",
                        "No remote introspection, resolver invocation or argument values in output."]}
