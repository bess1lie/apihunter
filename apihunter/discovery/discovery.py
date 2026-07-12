"""Discovery orchestrator.

:class:`Discovery` coordinates one or more
:class:`BaseDiscoveryProvider` instances, aggregates their results and
errors, and returns a single :class:`DiscoveryResult`.

This is the **only** public entry point for the discovery module::

    from apihunter.discovery import Discovery, PathDiscoveryProvider

    async with HttpClient() as client:
        provider = PathDiscoveryProvider(client, scope)
        discovery = Discovery([provider])
        result = await discovery.run("https://api.example.com")
        for spec in result.specs:
            print(spec.url, spec.confidence)

Design
------
* The orchestrator does **not** know which providers exist — they are
  injected.  Adding a provider in Stage 2 requires zero changes here.
* Providers run sequentially (each may probe internally in parallel).
  This prevents concurrent providers from doubling the request rate.
* Per-provider exceptions are caught and recorded as
  :class:`DiscoveryError` entries — one provider's failure does not
  affect others.
"""

from __future__ import annotations

import asyncio

from apihunter.discovery.base import BaseDiscoveryProvider
from apihunter.discovery.models import DiscoveredSpec, DiscoveryError, DiscoveryResult

_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


class Discovery:
    """Coordinates discovery across multiple providers.

    Parameters
    ----------
    providers:
        Ordered list of :class:`BaseDiscoveryProvider` instances.
    """

    def __init__(self, providers: list[BaseDiscoveryProvider]) -> None:
        if not providers:
            raise ValueError("At least one discovery provider is required")
        self._providers = providers

    async def run(self, base_url: str) -> DiscoveryResult:
        """Run all providers against *base_url* and aggregate results.

        Returns
        -------
        DiscoveryResult
            Aggregated specs (sorted by confidence, HIGH first) and
            non-fatal errors.
        """
        all_specs: list[DiscoveredSpec] = []
        all_errors: list[DiscoveryError] = []

        for provider in self._providers:
            try:
                specs = await provider.discover(base_url)
                all_specs.extend(specs)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                all_errors.append(
                    DiscoveryError(
                        url=base_url,
                        error_type="provider_error",
                        message=f"{provider.name}: {exc}",
                    )
                )

        all_specs.sort(key=lambda s: _CONFIDENCE_ORDER.get(s.confidence.value, 99))
        return DiscoveryResult(specs=all_specs, errors=all_errors)
