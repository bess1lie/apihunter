"""Typed models for the discovery module.

All models are **frozen dataclasses** — they represent immutable
snapshots of discovery results.  No plain ``dict`` is returned from any
public discovery API.

:class:`DiscoveryConfidence` uses :class:`enum.StrEnum` (available in
Python 3.11+) so values serialise naturally as strings in JSON, YAML,
and database columns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class DiscoveryConfidence(StrEnum):
    """Confidence level for a discovered specification document.

    * ``HIGH`` — explicit spec filename (e.g. ``/openapi.json``).
    * ``MEDIUM`` — documentation UI or generic spec path (``/docs``).
    * ``LOW`` — indirect indicator (``/graphql``, ``/graphiql``).
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class DiscoveredSpec:
    """A single discovered specification or endpoint document.

    Attributes
    ----------
    url:
        Full URL where the document was found.
    path:
        The path component that was probed (e.g. ``/openapi.json``).
    status_code:
        HTTP status code of the response.
    content_type:
        Value of the ``Content-Type`` response header, or ``None``.
    content_length:
        Value of the ``Content-Length`` response header, or ``None``.
    confidence:
        How confident the provider is that this is a real spec document.
    source:
        Name of the provider that discovered this document
        (e.g. ``"path"``).
    """

    url: str
    path: str
    status_code: int
    content_type: str | None = None
    content_length: int | None = None
    confidence: DiscoveryConfidence = DiscoveryConfidence.LOW
    source: str = "path"


@dataclass(frozen=True)
class DiscoveryError:
    """An error encountered while probing a single URL.

    Attributes
    ----------
    url:
        The URL that caused the error.
    error_type:
        Short identifier for the error class (e.g. ``"timeout"``,
        ``"permanent"``, ``"scope_denied"``).
    message:
        Human-readable error description.
    """

    url: str
    error_type: str
    message: str


@dataclass(frozen=True)
class DiscoveryResult:
    """Aggregate result of a discovery run.

    Attributes
    ----------
    specs:
        All discovered specification documents, ordered by confidence
        (HIGH first).
    errors:
        Non-fatal errors encountered during discovery.  A non-empty
        ``errors`` list does **not** mean discovery failed — partial
        results are expected.
    """

    specs: list[DiscoveredSpec] = field(default_factory=list)
    errors: list[DiscoveryError] = field(default_factory=list)
