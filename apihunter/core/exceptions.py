"""Typed exceptions for apihunter core modules.

All custom errors inherit from :class:`ApihunterError` so callers can
catch the entire hierarchy with a single ``except``.  Each leaf class
carries enough context for CLI-level error reporting without exposing
internals.

Hierarchy::

    ApihunterError
    ├── DatabaseError
    │   ├── DatabaseClosedError
    │   └── MigrationError
    ├── ScopeError
    └── HttpClientError
        ├── RetryableHttpError
        └── PermanentHttpError
"""

from __future__ import annotations


class ApihunterError(Exception):
    """Base class for every apihunter-specific exception."""


class DatabaseError(ApihunterError):
    """Raised when a database operation fails or is used incorrectly."""


class DatabaseClosedError(DatabaseError):
    """Raised when a method is called on a closed :class:`Database`."""

    def __init__(self) -> None:
        super().__init__("Database is closed — call connect() before using it.")


class MigrationError(DatabaseError):
    """Raised when a schema migration cannot be completed.

    Attributes
    ----------
    from_version:
        Schema version detected before the failed migration step.
    to_version:
        Schema version that was being applied.
    """

    def __init__(self, from_version: int, to_version: int, detail: str) -> None:
        self.from_version = from_version
        self.to_version = to_version
        super().__init__(
            f"Migration {from_version} -> {to_version} failed: {detail}",
        )


class ScopeError(ApihunterError):
    """Raised when a scope file is missing, empty, or malformed."""


class HttpClientError(ApihunterError):
    """Base class for HTTP-related errors."""


class RetryableHttpError(HttpClientError):
    """Transient HTTP error that may succeed on retry.

    Raised after all retry attempts are exhausted (timeouts, connection
    errors).  Callers that catch this error know the failure was
    network-level, not a permanent rejection.
    """


class PermanentHttpError(HttpClientError):
    """Non-retryable HTTP error.

    Raised for errors that will not improve with retry (e.g. invalid
    request, DNS resolution failure on a known host).  This lets callers
    distinguish "try again later" from "this will never work".
    """
