"""Read-only queries for apihunter.

This module separates **read** operations from the write-focused
:class:`apihunter.core.db.Database`.  The :class:`Queries` class wraps a
Database reference and delegates to its connection — no duplicate
connections are created.

All methods return typed :mod:`apihunter.core.models` dataclasses, never
plain ``dict``.  This gives callers static type checking and explicit
contracts.

Rationale
---------
Keeping reads and writes in separate classes prevents Database from
growing into a god object.  As new report/export/dashboard features add
more query patterns, they live here without touching the write path.
"""

from __future__ import annotations

import sqlite3

from apihunter.core.db import Database
from apihunter.core.models import (
    AuthResult,
    Checkpoint,
    Endpoint,
    Finding,
    FuzzResult,
    ScanRun,
    SpecInfo,
)


class Queries:
    """Read-only access to scan data stored by :class:`Database`.

    Parameters
    ----------
    db:
        A connected (or connectable) :class:`Database` instance.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _conn(self) -> sqlite3.Connection:
        """Return the active connection from the underlying Database."""
        return self._db.connect()

    # ------------------------------------------------------------------
    # scan_runs
    # ------------------------------------------------------------------

    def get_latest_scan_run(self) -> ScanRun | None:
        """Return the most recent scan run, or ``None`` if the table is empty."""
        row = self._conn.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1").fetchone()
        return ScanRun(**dict(row)) if row else None

    # ------------------------------------------------------------------
    # endpoints
    # ------------------------------------------------------------------

    def get_endpoints(self, scan_run_id: int) -> list[Endpoint]:
        """Return all endpoints for *scan_run_id* ordered by path."""
        rows = self._conn.execute(
            "SELECT * FROM endpoints WHERE scan_run_id = ? ORDER BY path, method",
            (scan_run_id,),
        ).fetchall()
        return [Endpoint(**dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # spec_info
    # ------------------------------------------------------------------

    def get_spec_info(self, scan_run_id: int) -> SpecInfo | None:
        """Return spec info for *scan_run_id*, or ``None`` if absent."""
        row = self._conn.execute("SELECT * FROM spec_info WHERE scan_run_id = ?", (scan_run_id,)).fetchone()
        return SpecInfo(**dict(row)) if row else None

    # ------------------------------------------------------------------
    # auth_results
    # ------------------------------------------------------------------

    def get_auth_results(self, scan_run_id: int) -> list[AuthResult]:
        """Return all auth results for *scan_run_id* ordered by test time."""
        rows = self._conn.execute(
            "SELECT * FROM auth_results WHERE scan_run_id = ? ORDER BY tested_at",
            (scan_run_id,),
        ).fetchall()
        return [AuthResult(**dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # security_findings
    # ------------------------------------------------------------------

    def get_findings(self, scan_run_id: int) -> list[Finding]:
        """Return all findings for *scan_run_id* ordered by severity."""
        rows = self._conn.execute(
            "SELECT * FROM security_findings WHERE scan_run_id = ? "
            "ORDER BY CASE severity "
            "  WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
            "  WHEN 'low' THEN 2 ELSE 3 END, found_at",
            (scan_run_id,),
        ).fetchall()
        return [Finding(**dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # fuzz_results
    # ------------------------------------------------------------------

    def get_fuzz_results(self, scan_run_id: int) -> list[FuzzResult]:
        """Return all fuzz results for *scan_run_id* ordered by param name."""
        rows = self._conn.execute(
            "SELECT * FROM fuzz_results WHERE scan_run_id = ? ORDER BY param_name",
            (scan_run_id,),
        ).fetchall()
        return [FuzzResult(**dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # checkpoints
    # ------------------------------------------------------------------

    def get_checkpoints(self, target: str) -> list[Checkpoint]:
        """Return all checkpoint rows for *target* ordered by start time."""
        rows = self._conn.execute(
            "SELECT * FROM checkpoints WHERE target = ? ORDER BY started_at",
            (target,),
        ).fetchall()
        return [Checkpoint(**dict(r)) for r in rows]
