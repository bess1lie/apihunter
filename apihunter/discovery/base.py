"""Abstract base class for discovery providers.

A **discovery provider** is responsible for finding specification
documents from a single source.  Each provider implements
:meth:`BaseDiscoveryProvider.discover` and returns a list of
:class:`DiscoveredSpec` (or raises on unrecoverable failure).

Adding a new provider in Stage 2
--------------------------------
1.  Create a new module under ``discovery/providers/``.
2.  Subclass :class:`BaseDiscoveryProvider`.
3.  Implement :meth:`discover`.
4.  Register it in the :class:`Discovery` orchestrator constructor.

No existing code needs to change — the orchestrator iterates over
whatever providers it is given.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from apihunter.core.http_client import HttpClient
from apihunter.core.scope import Scope
from apihunter.discovery.models import DiscoveredSpec


class BaseDiscoveryProvider(ABC):
    """Abstract base for all discovery providers.

    Parameters
    ----------
    client:
        An :class:`HttpClient` instance — injected, never created
        internally.
    scope:
        Optional :class:`Scope` for host-level and extension filtering.
    """

    def __init__(self, client: HttpClient, scope: Scope | None = None) -> None:
        self._client = client
        self._scope = scope

    @property
    def name(self) -> str:
        """Short identifier for this provider (e.g. ``"path"``)."""
        return self.__class__.__name__

    @abstractmethod
    async def discover(self, base_url: str) -> list[DiscoveredSpec]:
        """Probe *base_url* and return discovered documents.

        Implementations should:

        * Not raise on per-URL failures — return partial results.
        * Respect the injected :class:`HttpClient` rate limit.
        * Apply scope filtering when :attr:`_scope` is set.

        Parameters
        ----------
        base_url:
            Root URL to probe (e.g. ``"https://api.example.com"``).

        Returns
        -------
        list[DiscoveredSpec]
            Documents found by this provider.
        """
