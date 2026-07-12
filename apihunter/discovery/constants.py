"""Constants for the discovery module.

This module centralises:

* :data:`COMMON_PATHS` — 22 well-known paths where OpenAPI/Swagger
  specifications and related documents are commonly hosted.
* :data:`PATH_CONFIDENCE` — mapping from path pattern to
  :class:`DiscoveryConfidence`, used to rank discovered documents.
* :data:`VALID_STATUS_CODES` — HTTP status codes that indicate a
  potentially interesting response (not just 200).
* :data:`DEFAULT_MAX_SIZE` / :data:`DEFAULT_CONCURRENCY` — tunable
  defaults for the path provider.

Keeping these in a separate module allows future providers (robots.txt,
``.well-known``, sitemap, Wayback) to add their own constants without
touching the provider implementation.
"""

from __future__ import annotations

# 22 well-known paths for OpenAPI / Swagger / GraphQL endpoints.
COMMON_PATHS: list[str] = [
    "/openapi.json",
    "/openapi.yaml",
    "/api/openapi.json",
    "/swagger.json",
    "/swagger.yaml",
    "/api/swagger.json",
    "/api/docs",
    "/docs",
    "/redoc",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/spec",
    "/spec",
    "/swagger-resources",
    "/api/swagger-resources",
    "/api/v1/api-docs",
    "/api/v2/api-docs",
    "/api/v3/api-docs",
    "/graphql",
    "/graphiql",
    "/voyager",
    "/altair",
]

# Confidence mapping: paths with explicit spec filenames → HIGH,
# documentation UIs → MEDIUM, GraphQL playgrounds → LOW.
PATH_CONFIDENCE: dict[str, str] = {
    "/openapi.json": "high",
    "/openapi.yaml": "high",
    "/api/openapi.json": "high",
    "/swagger.json": "high",
    "/swagger.yaml": "high",
    "/api/swagger.json": "high",
    "/v2/api-docs": "high",
    "/v3/api-docs": "high",
    "/api/v1/api-docs": "high",
    "/api/v2/api-docs": "high",
    "/api/v3/api-docs": "high",
    "/api/docs": "medium",
    "/docs": "medium",
    "/redoc": "medium",
    "/api/spec": "medium",
    "/spec": "medium",
    "/swagger-resources": "medium",
    "/api/swagger-resources": "medium",
    "/graphql": "low",
    "/graphiql": "low",
    "/voyager": "low",
    "/altair": "low",
}

# Status codes that indicate a potentially interesting response.
# 200/204 — content or empty success.
# 301/302/307/308 — redirects (followed by httpx, but we also accept
#   them in case follow_redirects is disabled).
# 401/403 — auth required / forbidden (the path exists but is protected).
VALID_STATUS_CODES: frozenset[int] = frozenset({200, 204, 301, 302, 307, 308, 401, 403})

# Maximum response body size in bytes (1 MB by default).
DEFAULT_MAX_SIZE: int = 1_048_576

# Default concurrency for parallel path probing.
DEFAULT_CONCURRENCY: int = 10
