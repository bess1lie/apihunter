from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ScanRun:
    endpoint: str
    status: str
    id: int = 0
    started_at: Any | None = None
    finished_at: Any | None = None


@dataclass(frozen=True)
class Endpoint:
    path: str
    method: str
    status_code: int | None = None
    auth_required: str | None = None
    id: int = 0
    scan_run_id: int = 0
    discovered_at: Any | None = None


@dataclass(frozen=True)
class SpecInfo:
    title: str
    version: str
    endpoints_count: int
    spec_url: str
    id: int = 0
    scan_run_id: int = 0
    parsed_at: Any | None = None


@dataclass(frozen=True)
class AuthResult:
    method: str
    auth_type: str | None
    status_with: int
    status_without: int
    classification: str
    id: int = 0
    scan_run_id: int = 0
    endpoint_id: int | None = None
    tested_at: Any | None = None


@dataclass(frozen=True)
class Finding:
    check_type: str
    severity: Severity
    confidence: Confidence
    title: str
    detail: str | None = None
    remediation: str | None = None
    id: int = 0
    scan_run_id: int = 0
    endpoint_id: int | None = None
    found_at: Any | None = None


@dataclass(frozen=True)
class FuzzResult:
    param_name: str
    param_in: str | None
    variants: str | None
    is_idor_candidate: int
    id: int = 0
    scan_run_id: int = 0
    endpoint_id: int | None = None
    found_at: Any | None = None


@dataclass(frozen=True)
class Checkpoint:
    target: str
    module: str
    status: str
    started_at: str
    id: int = 0
    completed_at: Any | None = None
