"""Typed row models for database query results.

Each frozen dataclass corresponds to a table row.  They are immutable
because they represent snapshots of database state at query time —
callers receive, read, and pass them along but never mutate them.

Using typed models instead of plain ``dict`` gives:

* static type checking for field access;
* IDE autocompletion;
* explicit contracts between Database/Queries and callers;
* protection against silent schema drift.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanRun:
    """Row from the ``scan_runs`` table."""

    id: int
    endpoint: str
    started_at: str
    finished_at: str | None = None
    status: str = "running"


@dataclass(frozen=True)
class Endpoint:
    """Row from the ``endpoints`` table."""

    id: int
    scan_run_id: int
    path: str
    method: str
    status_code: int | None = None
    auth_required: str | None = None
    discovered_at: str = ""


@dataclass(frozen=True)
class SpecInfo:
    """Row from the ``spec_info`` table."""

    id: int
    scan_run_id: int
    title: str = ""
    version: str = ""
    endpoints_count: int = 0
    spec_url: str = ""
    parsed_at: str = ""


@dataclass(frozen=True)
class AuthResult:
    """Row from the ``auth_results`` table.

    The ``auth_type`` field is always stored **redacted** in the database
    via :func:`apihunter.core.redaction.redact_secret`.
    """

    id: int
    scan_run_id: int
    endpoint_id: int | None = None
    method: str = ""
    auth_type: str | None = None
    status_with: int | None = None
    status_without: int | None = None
    classification: str = ""
    tested_at: str = ""


@dataclass(frozen=True)
class Finding:
    """Row from the ``security_findings`` table."""

    id: int
    scan_run_id: int
    endpoint_id: int | None = None
    check_type: str = ""
    severity: str = ""
    confidence: str = ""
    title: str = ""
    detail: str | None = None
    remediation: str | None = None
    found_at: str = ""


@dataclass(frozen=True)
class FuzzResult:
    """Row from the ``fuzz_results`` table.

    ``is_idor_candidate`` is stored as ``INTEGER`` (0/1) in SQLite.
    """

    id: int
    scan_run_id: int
    endpoint_id: int | None = None
    param_name: str = ""
    param_in: str | None = None
    variants: str | None = None
    is_idor_candidate: int = 0
    found_at: str = ""


@dataclass(frozen=True)
class Checkpoint:
    """Row from the ``checkpoints`` table."""

    id: int
    target: str
    module: str
    status: str = "in_progress"
    started_at: str = ""
    completed_at: str | None = None
