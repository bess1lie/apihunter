from __future__ import annotations

from apihunter.parser.models import ParameterLocation
from apihunter.parser.openapi_parser import parse_spec


def test_parse_basic_spec():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {"/users": {"get": {"summary": "List users", "responses": {"200": {"description": "OK"}}}}},
    }
    result = parse_spec(spec)
    assert result.title == "Test API"
    assert result.version == "1.0.0"
    assert len(result.endpoints) == 1
    assert result.endpoints[0].path == "/users"
    assert result.endpoints[0].method == "GET"


def test_parse_with_parameters():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    result = parse_spec(spec)
    assert len(result.endpoints[0].parameters) == 1
    assert result.endpoints[0].parameters[0].name == "id"
    assert result.endpoints[0].parameters[0].location == ParameterLocation.PATH


def test_parse_with_components():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/QueryParam"}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
        "components": {"parameters": {"QueryParam": {"name": "q", "in": "query", "required": False}}},
    }
    result = parse_spec(spec)
    assert len(result.endpoints[0].parameters) == 1
    assert result.endpoints[0].parameters[0].name == "q"
    assert result.endpoints[0].parameters[0].location == ParameterLocation.QUERY


def test_parse_auth_schemes():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {"/secure": {"get": {"security": [{"BearerAuth": []}], "responses": {"200": {"description": "OK"}}}}},
        "components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}},
    }
    result = parse_spec(spec)
    assert result.endpoints[0].auth_required is True
    assert "http" in result.endpoints[0].auth_schemes
