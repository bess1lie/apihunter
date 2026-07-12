"""Unified scope configuration for apihunter.

A :class:`Scope` instance gates every network operation.  It is loaded
from a YAML file with four top-level keys::

    allow:
      - "*.example.com"
    deny:
      - "admin.example.com"
    targets:
      - "https://api.example.com"
    excluded_extensions:
      - png
      - jpg
      - css
      - js

Matching rules (``fnmatch`` wildcards):

* ``*.example.com`` matches ``api.example.com`` but **not** the bare
  ``example.com``.
* ``example.com`` matches ``example.com`` and any subdomain
  (``api.example.com``).

Decision order in :meth:`Scope.can_scan`:

1.  If **all** lists are empty the scope is considered unset and the
    answer is ``False`` (fail-closed).
2.  If the host matches any **deny** pattern → ``False``.
3.  If **allow** is non-empty → the host must match at least one allow
    pattern.
4.  If **allow** is empty but **targets** are set → the host must match
    the hostname of at least one target URL.
5.  Otherwise (only **deny** is set) → ``True`` (allow everything not
    explicitly denied).

:meth:`Scope.is_extension_excluded` filters out static-asset URLs
(images, stylesheets, scripts) during discovery without affecting
host-level scope decisions.

Extensibility
-------------
The public API (``from_yaml``, ``is_in_scope``, ``can_scan``,
``is_extension_excluded``, ``to_dict``) is stable.  Matching is
delegated to private helpers ``_matches_deny`` and ``_matches_allow``
which currently use :func:`fnmatch.fnmatch`.  A future version can
override these to support regex, CIDR ranges, or hostname-suffix rules
**without changing any caller**.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from apihunter.core.exceptions import ScopeError


@dataclass(frozen=True)
class Scope:
    """Immutable scope configuration loaded from YAML.

    Attributes
    ----------
    allow:
        Patterns that permit scanning.  Empty means "allow everything
        not denied" (when deny or targets are set).
    deny:
        Patterns that block scanning unconditionally.
    targets:
        Concrete URLs to scan (used by batch/monitor commands).
    excluded_extensions:
        File extensions to skip during discovery (e.g. ``png``, ``jpg``,
        ``css``, ``js``).  Does not affect host-level scope decisions.
    """

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    excluded_extensions: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> Scope:
        """Load a :class:`Scope` from a YAML file.

        Parameters
        ----------
        path:
            Path to a YAML file with ``allow``, ``deny`` and ``targets``
            keys (all optional).

        Raises
        ------
        ScopeError:
            If the file does not exist or cannot be parsed.
        """
        yaml_path = Path(path)
        if not yaml_path.exists():
            raise ScopeError(f"Scope file not found: {yaml_path}")
        with yaml_path.open() as fh:
            data = yaml.safe_load(fh)
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise ScopeError(f"Scope file must contain a mapping, got {type(data).__name__}")
        return cls(
            allow=list(data.get("allow", []) or []),
            deny=list(data.get("deny", []) or []),
            targets=list(data.get("targets", []) or []),
            excluded_extensions=list(data.get("excluded_extensions", []) or []),
        )

    # ------------------------------------------------------------------
    # Public decision API
    # ------------------------------------------------------------------

    def is_in_scope(self, url: str) -> bool:
        """Check whether *url* (by hostname) is inside the scope.

        Returns ``False`` when the URL has no parseable hostname.
        """
        host = urlparse(url).hostname
        if not host:
            return False
        return self.can_scan(host)

    def can_scan(self, host: str) -> bool:
        """Decide whether *host* may be scanned.

        Decision order:

        1. If **all** lists are empty → ``False`` (fail-closed).
        2. If *host* matches any **deny** pattern → ``False``.
        3. If **allow** is non-empty → *host* must match at least one
           allow pattern.
        4. If **allow** is empty but **targets** are set → *host* must
           match the hostname of at least one target URL.
        5. Otherwise (only **deny** is set) → ``True`` (allow everything
           not explicitly denied).
        """
        if not self.allow and not self.deny and not self.targets:
            return False
        if self._matches_deny(host):
            return False
        if self.allow:
            return self._matches_allow(host)
        if self.targets:
            return self._matches_targets(host)
        return True

    def is_extension_excluded(self, path_or_url: str) -> bool:
        """Check whether *path_or_url* has an excluded file extension.

        This is orthogonal to :meth:`can_scan` — it filters individual
        URLs (e.g. ``/static/logo.png``) without affecting host-level
        scope decisions.

        Returns ``False`` when ``excluded_extensions`` is empty.
        """
        if not self.excluded_extensions:
            return False
        path = urlparse(path_or_url).path
        for ext in self.excluded_extensions:
            if path.endswith(f".{ext.lstrip('.')}"):
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialise the scope back to a plain dict (YAML-round-trippable)."""
        return {
            "allow": list(self.allow),
            "deny": list(self.deny),
            "targets": list(self.targets),
            "excluded_extensions": list(self.excluded_extensions),
        }

    # ------------------------------------------------------------------
    # Private matching helpers (override points for future extensions)
    # ------------------------------------------------------------------

    def _matches_deny(self, host: str) -> bool:
        """Return ``True`` if *host* matches any deny pattern."""
        return self._matches_any(host, self.deny)

    def _matches_allow(self, host: str) -> bool:
        """Return ``True`` if *host* matches any allow pattern."""
        return self._matches_any(host, self.allow)

    def _matches_targets(self, host: str) -> bool:
        """Return ``True`` if *host* matches the hostname of any target URL."""
        lowered = host.lower()
        for target in self.targets:
            target_host = urlparse(target).hostname
            if target_host:
                t_lower = target_host.lower()
                if fnmatch.fnmatch(lowered, t_lower) or lowered.endswith(f".{t_lower}"):
                    return True
        return False

    @staticmethod
    def _matches_any(host: str, patterns: list[str]) -> bool:
        """Match *host* against *patterns*.

        Uses case-insensitive :func:`fnmatch.fnmatch` for wildcard
        patterns (``*.example.com``).  For bare patterns without a
        wildcard (``example.com``), the pattern also matches any
        subdomain (``api.example.com``), following the convention
        established by bounthunt.
        """
        lowered = host.lower()
        for p in patterns:
            p_lower = p.lower()
            if fnmatch.fnmatch(lowered, p_lower):
                return True
            if not p_lower.startswith("*."):
                if lowered.endswith(f".{p_lower}"):
                    return True
        return False
