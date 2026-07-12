"""SQLite write operations for apihunter.

:class:`Database` handles **connection management, schema initialisation,
and write operations only**.  Read operations live in
:class:`apihunter.core.queries.Queries`.

Responsibility split:

* :class:`Database` — connect, initialize, migrate, save (write), checkpoint.
* :class:`Queries` — get (read), list, count.

All SQL is executed through parameterised statements — no f-strings,
no string concatenation in queries.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from apihunter import __version__
from apihunter.core.exceptions import DatabaseClosedError, MigrationError
from apihunter.core.migrations import MIGRATIONS
from apihunter.core.redaction import redact_secret
from apihunter.core.schema import CURRENT_SCHEMA_VERSION, SCHEMA_SQL


class Database:
    """SQLite storage with schema versioning, writes, and checkpoints.

    The class supports two usage patterns::

        # Context manager (preferred — guarantees cleanup)
        with Database("scan.db") as db:
            db.initialize()
            run_id = db.create_scan_run("https://example.com")

        # Manual lifecycle
        db = Database("scan.db")
        db.connect()
        db.initialize()
        ...
        db.close()

    Read operations are handled by :class:`apihunter.core.queries.Queries`::

        from apihunter.core.queries import Queries
        q = Queries(db)
        findings = q.get_findings(run_id)

    Parameters
    ----------
    path:
        Filesystem path for the SQLite database file.

    Raises
    ------
    DatabaseClosedError:
        If a write method is called before :meth:`connect`.
    MigrationError:
        If a migration step fails.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None

    # ==================================================================
    # Connection management
    # ==================================================================

    def connect(self) -> sqlite3.Connection:
        """Lazily create and return the SQLite connection.

        Calling this method multiple times returns the **same** connection
        (idempotent).  WAL journal mode and foreign keys are enabled on
        first creation.
        """
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self) -> None:
        """Close the connection if open.  Safe to call multiple times."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Database:
        """Enter context: ensure a connection exists."""
        self.connect()
        return self

    def __exit__(self, *args: Any) -> None:
        """Exit context: close the connection."""
        self.close()

    def _ensure_connected(self) -> sqlite3.Connection:
        """Return the active connection or raise :class:`DatabaseClosedError`."""
        if self._conn is None:
            raise DatabaseClosedError
        return self._conn

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection, commit on success, rollback on exception.

        This ensures the database remains in a consistent state and the
        connection stays usable after a failed write.
        """
        conn = self._ensure_connected()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ==================================================================
    # Schema & migrations
    # ==================================================================

    def initialize(self) -> None:
        """Create all tables and set the initial schema version.

        This method is **idempotent** — safe to call multiple times.
        Tables use ``CREATE TABLE IF NOT EXISTS`` and metadata uses
        upsert semantics.
        """
        conn = self.connect()
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        if self.get_schema_version() is None:
            self.set_schema_version(CURRENT_SCHEMA_VERSION)
        self.set_metadata("tool_version", __version__)

    def get_schema_version(self) -> int | None:
        """Return the current schema version, or ``None`` if not set."""
        raw = self.get_metadata("schema_version")
        return int(raw) if raw is not None else None

    def set_schema_version(self, version: int) -> None:
        """Persist *version* as the current schema version."""
        self.set_metadata("schema_version", str(version))

    def migrate(self) -> None:
        """Apply pending migrations up to :data:`CURRENT_SCHEMA_VERSION`.

        Migrations are recorded in :data:`apihunter.core.migrations.MIGRATIONS`.
        Each step runs its SQL, commits, and updates ``schema_version``.
        If the database is already at the target version this is a no-op.

        Raises
        ------
        MigrationError:
            If a migration step raises an exception.
        """
        current = self.get_schema_version()
        if current is None:
            current = 0
        target = CURRENT_SCHEMA_VERSION
        if current >= target:
            return
        for version in range(current + 1, target + 1):
            sql = MIGRATIONS.get(version, "")
            if sql:
                try:
                    self.connect().executescript(sql)
                    self.connect().commit()
                except sqlite3.Error as exc:
                    raise MigrationError(current, version, str(exc)) from exc
            self.set_schema_version(version)

    # ==================================================================
    # Metadata
    # ==================================================================

    def set_metadata(self, key: str, value: str) -> None:
        """Insert or update a metadata key/value pair."""
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
                (key, value, value),
            )

    def get_metadata(self, key: str) -> str | None:
        """Return the metadata value for *key*, or ``None`` if absent."""
        conn = self._ensure_connected()
        row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    # ==================================================================
    # scan_runs (write)
    # ==================================================================

    def create_scan_run(self, endpoint: str) -> int:
        """Create a new scan run row and return its ID."""
        with self._transaction() as conn:
            cur = conn.execute(
                "INSERT INTO scan_runs (endpoint) VALUES (?)",
                (endpoint,),
            )
            return cur.lastrowid

    def finish_scan_run(self, run_id: int) -> None:
        """Mark a scan run as finished with the current timestamp."""
        with self._transaction() as conn:
            conn.execute(
                "UPDATE scan_runs SET finished_at = datetime('now'), status = 'completed' WHERE id = ?",
                (run_id,),
            )

    # ==================================================================
    # endpoints (write)
    # ==================================================================

    def save_endpoint(
        self,
        run_id: int,
        path: str,
        method: str,
        status_code: int | None = None,
        auth_required: str | None = None,
    ) -> int:
        """Insert or update an endpoint within a scan run.

        Returns the endpoint row ID.  The pair ``(scan_run_id, path,
        method)`` is unique — an existing row is updated in place.
        """
        with self._transaction() as conn:
            existing = conn.execute(
                "SELECT id FROM endpoints WHERE scan_run_id = ? AND path = ? AND method = ?",
                (run_id, path, method),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE endpoints SET status_code = ?, auth_required = ? WHERE id = ?",
                    (status_code, auth_required, existing["id"]),
                )
                return existing["id"]
            cur = conn.execute(
                "INSERT INTO endpoints (scan_run_id, path, method, status_code, auth_required) VALUES (?, ?, ?, ?, ?)",
                (run_id, path, method, status_code, auth_required),
            )
            return cur.lastrowid

    # ==================================================================
    # spec_info (write)
    # ==================================================================

    def save_spec_info(
        self,
        run_id: int,
        title: str,
        version: str,
        endpoints_count: int,
        spec_url: str,
    ) -> None:
        """Persist metadata extracted from an OpenAPI/Swagger document."""
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO spec_info (scan_run_id, title, version, endpoints_count, spec_url) VALUES (?, ?, ?, ?, ?)",
                (run_id, title, version, endpoints_count, spec_url),
            )

    # ==================================================================
    # auth_results (write — with automatic redaction)
    # ==================================================================

    def save_auth(
        self,
        run_id: int,
        endpoint_id: int | None,
        method: str,
        auth_type: str | None,
        status_with: int | None,
        status_without: int | None,
        classification: str,
    ) -> None:
        """Persist an auth analysis result.

        The *auth_type* field (e.g. ``"Bearer eyJ..."``) is redacted via
        :func:`redact_secret` before storage.
        """
        safe_auth_type = redact_secret(auth_type) if auth_type else None
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO auth_results "
                "(scan_run_id, endpoint_id, method, auth_type, status_with, status_without, classification) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (run_id, endpoint_id, method, safe_auth_type, status_with, status_without, classification),
            )

    # ==================================================================
    # security_findings (write)
    # ==================================================================

    def save_finding(
        self,
        run_id: int,
        endpoint_id: int | None,
        check_type: str,
        severity: str,
        confidence: str,
        title: str,
        detail: str | None = None,
        remediation: str | None = None,
    ) -> None:
        """Persist a heuristic security finding."""
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO security_findings "
                "(scan_run_id, endpoint_id, check_type, severity, confidence, title, detail, remediation) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, endpoint_id, check_type, severity, confidence, title, detail, remediation),
            )

    # ==================================================================
    # fuzz_results (write)
    # ==================================================================

    def save_fuzz_result(
        self,
        run_id: int,
        endpoint_id: int | None,
        param_name: str,
        param_in: str | None = None,
        variants: str | None = None,
        is_idor: bool = False,
    ) -> None:
        """Persist a parameter fuzzing result."""
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fuzz_results "
                "(scan_run_id, endpoint_id, param_name, param_in, variants, is_idor_candidate) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, endpoint_id, param_name, param_in, variants, 1 if is_idor else 0),
            )

    # ==================================================================
    # checkpoints (write)
    # ==================================================================

    def save_checkpoint(self, target: str, module: str, status: str = "in_progress") -> None:
        """Insert or update a checkpoint row (upsert on ``target, module``).

        Setting *status* to ``"completed"`` records the completion
        timestamp; setting it to ``"in_progress"`` resets the start time.
        """
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO checkpoints (target, module, status, started_at) "
                "VALUES (?, ?, ?, datetime('now')) "
                "ON CONFLICT(target, module) DO UPDATE SET "
                "  status = excluded.status, "
                "  started_at = CASE WHEN excluded.status = 'in_progress' "
                "    THEN excluded.started_at ELSE started_at END, "
                "  completed_at = CASE WHEN excluded.status = 'completed' "
                "    THEN excluded.started_at ELSE NULL END",
                (target, module, status),
            )

    def clear_checkpoints(self, target: str) -> None:
        """Delete all checkpoint rows for *target*."""
        with self._transaction() as conn:
            conn.execute("DELETE FROM checkpoints WHERE target = ?", (target,))
