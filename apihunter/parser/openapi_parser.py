from __future__ import annotations

from typing import Any

from apihunter.parser.models import ParameterLocation, SpecEndpoint, SpecParameter, SpecResult


def parse_spec(spec: dict[str, Any]) -> SpecResult:
    """
    Parses an OpenAPI 3.x specification dictionary into a SpecResult.

    Args:
        spec: The raw OpenAPI specification as a dictionary.

    Returns:
        A SpecResult containing the parsed endpoints and metadata.
    """
    info = spec.get("info", {})
    title = info.get("title", "Unknown API")
    version = info.get("version", "0.0.0")

    endpoints = []
    paths = spec.get("paths", {})

    # Extract global security requirements
    global_security = spec.get("security", [])

    # Components for shared parameters and security schemes
    components = spec.get("components", {})
    parameters_comp = components.get("parameters", {})
    security_schemes = components.get("securitySchemes", {})

    for path, path_item in paths.items():
        for method, operation in path_item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch", "options", "head", "trace"):
                continue

            # Handle parameters
            params = []
            # Path-level parameters
            for p in path_item.get("parameters", []):
                params.append(_parse_parameter(p, parameters_comp))

            # Operation-level parameters
            for p in operation.get("parameters", []):
                params.append(_parse_parameter(p, parameters_comp))

            # Auth analysis
            auth_required = False
            auth_schemes = []

            # Operation security overrides global
            op_security = operation.get("security")
            if op_security is not None:
                for sec in op_security:
                    for scheme_name in sec:
                        auth_required = True
                        scheme = security_schemes.get(scheme_name, {})
                        auth_schemes.append(scheme.get("type", "unknown"))
            else:
                # Fallback to global security
                for sec in global_security:
                    for scheme_name in sec:
                        auth_required = True
                        scheme = security_schemes.get(scheme_name, {})
                        auth_schemes.append(scheme.get("type", "unknown"))

            # Responses
            responses = {}
            for code, resp in operation.get("responses", {}).items():
                responses[int(code)] = resp.get("description")

            endpoints.append(
                SpecEndpoint(
                    path=path,
                    method=method.upper(),
                    summary=operation.get("summary"),
                    description=operation.get("description"),
                    parameters=params,
                    request_body_required=(
                        "requestBody" in operation and operation["requestBody"].get("required", False)
                    ),
                    responses=responses,
                    auth_required=auth_required,
                    auth_schemes=list(set(auth_schemes)),
                )
            )

    return SpecResult(title=title, version=version, endpoints=endpoints, base_url=None, raw_spec=spec)


def _parse_parameter(param: dict[str, Any], components_params: dict[str, Any]) -> SpecParameter:
    """Resolves a parameter reference and returns a SpecParameter."""
    if "$ref" in param:
        ref_path = param["$ref"]
        # Handle #/components/parameters/NAME
        if ref_path.startswith("#/components/parameters/"):
            name = ref_path.split("/")[-1]
            param = components_params.get(name, {})
        else:
            # Unsupported ref
            return SpecParameter(name="unknown", location=ParameterLocation.QUERY, required=False)

    name = param.get("name", "unknown")
    location = ParameterLocation(param.get("in", "query"))
    required = param.get("required", False)
    description = param.get("description")

    schema = param.get("schema", {})
    schema_type = schema.get("type") if isinstance(schema, dict) else None

    return SpecParameter(
        name=name, location=location, required=required, description=description, schema_type=schema_type
    )
