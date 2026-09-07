from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from apihunter.core.exceptions import PermanentHttpError, RetryableHttpError
from apihunter.core.http_client import HttpClient
from apihunter.core.scope import Scope
from apihunter.discovery.base import BaseDiscoveryProvider
from apihunter.discovery.models import DiscoveredSpec, DiscoveryConfidence


class CrawlDiscoveryProvider(BaseDiscoveryProvider):
    """Light crawl: robots.txt, sitemap.xml, and root HTML for /api/ links."""

    def __init__(self, client: HttpClient, scope: Scope | None = None) -> None:
        super().__init__(client, scope)

    @property
    def name(self) -> str:
        return "crawl"

    async def discover(self, base_url: str) -> list[DiscoveredSpec]:
        specs: list[DiscoveredSpec] = []
        base = base_url.rstrip("/")

        # robots.txt
        try:
            url = base + "/robots.txt"
            if not self._scope or self._scope.is_in_scope(url):
                resp = await self._client.request("GET", url)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        m = re.search(r"Allow:\s*(/[^\s#]+)", line, re.I)
                        if m:
                            path = m.group(1).strip()
                            if "/api" in path or "/v1" in path or "/openapi" in path:
                                specs.append(
                                    DiscoveredSpec(
                                        url=base + path,
                                        path=path,
                                        status_code=200,
                                        content_type="text/plain",
                                        content_length=None,
                                        confidence=DiscoveryConfidence.LOW,
                                        source=self.name,
                                    )
                                )
        except (RetryableHttpError, PermanentHttpError):
            pass

        # sitemap.xml
        try:
            url = base + "/sitemap.xml"
            if not self._scope or self._scope.is_in_scope(url):
                resp = await self._client.request("GET", url)
                if resp.status_code == 200 and "<url" in resp.text:
                    try:
                        root = ET.fromstring(resp.text)
                        ns = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                        for loc in root.findall(".//ns:loc", ns) or root.findall(".//loc"):
                            u = (loc.text or "").strip()
                            if "/api" in u or "/openapi" in u or "/swagger" in u:
                                path = "/" + u.split("/", 3)[-1] if "://" in u else u
                                specs.append(
                                    DiscoveredSpec(
                                        url=u,
                                        path=path,
                                        status_code=200,
                                        content_type="text/xml",
                                        content_length=None,
                                        confidence=DiscoveryConfidence.LOW,
                                        source=self.name,
                                    )
                                )
                    except ET.ParseError:
                        pass
        except (RetryableHttpError, PermanentHttpError):
            pass

        # root HTML for /api/ links
        try:
            url = base + "/"
            if not self._scope or self._scope.is_in_scope(url):
                resp = await self._client.request("GET", url)
                if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("text/html"):
                    for m in re.finditer(r'["\'](/[a-z0-9/_-]*api[a-z0-9/_-]*)["\']', resp.text, re.I):
                        path = m.group(1)
                        if len(path) > 4:
                            specs.append(
                                DiscoveredSpec(
                                    url=base + path,
                                    path=path,
                                    status_code=200,
                                    content_type="text/html",
                                    content_length=None,
                                    confidence=DiscoveryConfidence.LOW,
                                    source=self.name,
                                )
                            )
                            if len(specs) >= 5:
                                break
        except (RetryableHttpError, PermanentHttpError):
            pass

        return specs[:5]
