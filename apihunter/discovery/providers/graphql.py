from __future__ import annotations

import json

from apihunter.core.exceptions import PermanentHttpError, RetryableHttpError
from apihunter.core.http_client import HttpClient
from apihunter.core.scope import Scope
from apihunter.discovery.base import BaseDiscoveryProvider
from apihunter.discovery.models import DiscoveredSpec, DiscoveryConfidence

_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/api", "/graphiql"]


class GraphQLDiscoveryProvider(BaseDiscoveryProvider):
    """Detects GraphQL endpoints via introspection probe."""

    def __init__(self, client: HttpClient, scope: Scope | None = None) -> None:
        super().__init__(client, scope)

    @property
    def name(self) -> str:
        return "graphql"

    async def discover(self, base_url: str) -> list[DiscoveredSpec]:
        specs: list[DiscoveredSpec] = []
        for path in _GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            if self._scope and not self._scope.is_in_scope(url):
                continue
            try:
                resp = await self._client.request("POST", url, json=_INTROSPECTION_QUERY)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and ("data" in data or "errors" in data):
                            specs.append(
                                DiscoveredSpec(
                                    url=url,
                                    path=path,
                                    status_code=resp.status_code,
                                    content_type=resp.headers.get("content-type"),
                                    content_length=None,
                                    confidence=DiscoveryConfidence.HIGH,
                                    source=self.name,
                                )
                            )
                    except (json.JSONDecodeError, ValueError):
                        continue
                # Also try GET for graphiql
                if path == "/graphiql":
                    resp2 = await self._client.request("GET", url)
                    if resp2.status_code == 200 and "graphql" in resp2.text.lower():
                        specs.append(
                            DiscoveredSpec(
                                url=url,
                                path=path,
                                status_code=resp2.status_code,
                                content_type=resp2.headers.get("content-type"),
                                content_length=None,
                                confidence=DiscoveryConfidence.MEDIUM,
                                source=self.name,
                            )
                        )
            except (RetryableHttpError, PermanentHttpError):
                continue
        return specs
