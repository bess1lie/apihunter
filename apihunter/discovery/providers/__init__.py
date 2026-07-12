"""Discovery provider package.

Each module in this package implements one discovery source:

* :mod:`apihunter.discovery.providers.path` — probes well-known paths
  (Stage 1, implemented).
* Future: ``robots.py``, ``wellknown.py``, ``sitemap.py``, etc.

Providers are registered explicitly in the
:class:`apihunter.discovery.discovery.Discovery` orchestrator — there is
no global registry, keeping the system free of hidden state.
"""

from __future__ import annotations

from apihunter.discovery.providers.path import PathDiscoveryProvider

__all__ = ["PathDiscoveryProvider"]
