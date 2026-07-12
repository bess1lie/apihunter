"""Discovery module — OpenAPI/Swagger/GraphQL specification discovery.

Public API::

    from apihunter.discovery import Discovery, PathDiscoveryProvider
    from apihunter.discovery.models import DiscoveredSpec, DiscoveryResult

Providers are injected into :class:`Discovery` — no global registry,
no hidden state.  Adding a new provider in Stage 2 requires only a new
module under :mod:`apihunter.discovery.providers` and passing it to the
``Discovery`` constructor.
"""

from __future__ import annotations

from apihunter.discovery.base import BaseDiscoveryProvider
from apihunter.discovery.constants import COMMON_PATHS, VALID_STATUS_CODES
from apihunter.discovery.discovery import Discovery
from apihunter.discovery.models import (
    DiscoveredSpec,
    DiscoveryConfidence,
    DiscoveryError,
    DiscoveryResult,
)
from apihunter.discovery.providers.path import PathDiscoveryProvider

__all__ = [
    "BaseDiscoveryProvider",
    "COMMON_PATHS",
    "Discovery",
    "DiscoveryConfidence",
    "DiscoveryError",
    "DiscoveryResult",
    "DiscoveredSpec",
    "PathDiscoveryProvider",
    "VALID_STATUS_CODES",
]
