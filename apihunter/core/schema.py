"""SQLite schema definition for apihunter.

This module contains only the DDL (data definition language) for the
database.  It is separated from :class:`apihunter.core.db.Database` so
that schema changes are reviewed in isolation and the Database class
stays focused on connection and write operations.

Tables (8):
    1. scan_runs        — top-level container for a scan execution.
    2. endpoints        — discovered HTTP endpoints within a scan run.
    3. spec_info        — metadata extracted from OpenAPI/Swagger docs.
    4. auth_results     — comparison of responses with/without auth.
    5. security_findings — heuristic observations from analyzers.
    6. fuzz_results     — parameter fuzzing and IDOR candidates.
    7. metadata         — key/value store for schema versioning.
    8. checkpoints      — resume support for interrupted scans.
"""

from __future__ import annotations

CURRENT_SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- 1. scan_runs — top-level container for a single scan execution.
CREATE TABLE IF NOT EXISTS scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint    TEXT NOT NULL,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running'
);

-- 2. endpoints — discovered HTTP endpoints within a scan run.
CREATE TABLE IF NOT EXISTS endpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id   INTEGER REFERENCES scan_runs(id),
    path          TEXT NOT NULL,
    method        TEXT NOT NULL,
    status_code   INTEGER,
    auth_required TEXT,
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scan_run_id, path, method)
);

-- 3. spec_info — metadata extracted from an OpenAPI/Swagger document.
CREATE TABLE IF NOT EXISTS spec_info (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id    INTEGER REFERENCES scan_runs(id),
    title          TEXT,
    version        TEXT,
    endpoints_count INTEGER DEFAULT 0,
    spec_url       TEXT,
    parsed_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 4. auth_results — comparison of responses with/without auth token.
CREATE TABLE IF NOT EXISTS auth_results (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id       INTEGER REFERENCES scan_runs(id),
    endpoint_id       INTEGER REFERENCES endpoints(id),
    method            TEXT NOT NULL,
    auth_type         TEXT,
    status_with       INTEGER,
    status_without    INTEGER,
    classification    TEXT NOT NULL
        CHECK(classification IN ('public','auth_required','unknown')),
    tested_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 5. security_findings — heuristic observations from analyzers.
CREATE TABLE IF NOT EXISTS security_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id  INTEGER REFERENCES scan_runs(id),
    endpoint_id  INTEGER REFERENCES endpoints(id),
    check_type   TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
    confidence   TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
    title        TEXT NOT NULL,
    detail       TEXT,
    remediation  TEXT,
    found_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 6. fuzz_results — parameter fuzzing and IDOR candidate tracking.
CREATE TABLE IF NOT EXISTS fuzz_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id      INTEGER REFERENCES scan_runs(id),
    endpoint_id      INTEGER REFERENCES endpoints(id),
    param_name       TEXT NOT NULL,
    param_in         TEXT,
    variants         TEXT,
    is_idor_candidate INTEGER DEFAULT 0,
    found_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 7. metadata — key/value store for schema versioning and tool info.
CREATE TABLE IF NOT EXISTS metadata (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    key   TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL
);

-- 8. checkpoints — resume support for interrupted scans.
CREATE TABLE IF NOT EXISTS checkpoints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    module       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'in_progress',
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(target, module)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_endpoints_run     ON endpoints(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_auth_results_run  ON auth_results(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run      ON security_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_fuzz_results_run  ON fuzz_results(scan_run_id);
"""
