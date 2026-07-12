from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ParameterLocation(StrEnum):
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


@dataclass(frozen=True)
class SpecParameter:
    name: str
    location: ParameterLocation
    required: bool
    description: str | None = None
    schema_type: str | None = None


@dataclass(frozen=True)
class SpecEndpoint:
    path: str
    method: str
    summary: str | None = None
    description: str | None = None
    parameters: list[SpecParameter] = field(default_factory=list)
    request_body_required: bool = False
    responses: dict[int, str | None] = field(default_factory=dict)
    auth_required: bool = False
    auth_schemes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SpecResult:
    title: str
    version: str
    endpoints: list[SpecEndpoint] = field(default_factory=list)
    base_url: str | None = None
    raw_spec: dict[str, Any] | None = None
