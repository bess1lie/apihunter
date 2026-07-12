"""Tests for :class:`apihunter.core.db.Database` and :class:`apihunter.core.queries.Queries`."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from apihunter.core.db import Database
from apihunter.core.exceptions import DatabaseClosedError, DatabaseError, MigrationError
from apihunter.core.models import (
    AuthResult,
    Checkpoint,
    Endpoint,
    Finding,
    FuzzResult,
    ScanRun,
    SpecInfo,
)
from apihunter.core.queries import Queries


def _make_db(tmp_path: Path) -> Database:
    """Create an initialised Database in tmp_path."""
    db = Database(tmp_path / "test.db")
    db.connect()
    db.initialize()
    return db


class TestDatabaseConnection:
    """Connection lifecycle: connect, close, context manager."""

    def test_connect_idempotent(self, tmp_path: Path) -> None:
        """Multiple connect() calls return the same connection."""
        db = Database(tmp_path / "t.db")
        c1 = db.connect()
        c2 = db.connect()
        assert c1 is c2
        db.close()

    def test_close_null_safe(self, tmp_path: Path) -> None:
        """Double close does not raise."""
        db = Database(tmp_path / "t.db")
        db.connect()
        db.close()
        db.close()

    def test_context_manager(self, tmp_path: Path) -> None:
        """Context manager opens and closes the connection."""
        with Database(tmp_path / "ctx.db") as db:
            db.initialize()
            assert db._conn is not None
        assert db._conn is None

    def test_closed_error_on_write(self, tmp_path: Path) -> None:
        """Calling a write method before connect raises DatabaseClosedError."""
        db = Database(tmp_path / "t.db")
        with pytest.raises(DatabaseClosedError):
            db.set_metadata("k", "v")

    def test_closed_error_on_get_metadata(self, tmp_path: Path) -> None:
        """Calling get_metadata before connect raises DatabaseClosedError."""
        db = Database(tmp_path / "t.db")
        with pytest.raises(DatabaseClosedError):
            db.get_metadata("k")

    def test_database_error_is_base(self) -> None:
        """DatabaseClosedError is a subclass of DatabaseError."""
        assert issubclass(DatabaseClosedError, DatabaseError)


class TestDatabaseInit:
    """Schema initialisation and versioning."""

    def test_initialize_creates_all_tables(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        conn = db.connect()
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        expected = {
            "scan_runs",
            "endpoints",
            "spec_info",
            "auth_results",
            "security_findings",
            "fuzz_results",
            "metadata",
            "checkpoints",
        }
        assert expected.issubset(tables)
        db.close()

    def test_initialize_idempotent(self, tmp_path: Path) -> None:
        """Calling initialize() twice does not raise and preserves data."""
        db = _make_db(tmp_path)
        db.initialize()
        assert db.get_schema_version() == 1
        db.close()

    def test_schema_version_is_set(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        assert db.get_schema_version() == 1
        db.close()

    def test_tool_version_is_set(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        assert db.get_metadata("tool_version") == "0.1.0"
        db.close()


class TestDatabaseMetadata:
    """Metadata key/value store."""

    def test_set_and_get(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        db.set_metadata("custom_key", "custom_value")
        assert db.get_metadata("custom_key") == "custom_value"
        db.close()

    def test_upsert_overwrites(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        db.set_metadata("k", "v1")
        db.set_metadata("k", "v2")
        assert db.get_metadata("k") == "v2"
        db.close()

    def test_get_missing_returns_none(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        assert db.get_metadata("nonexistent") is None
        db.close()


class TestScanRuns:
    """scan_runs CRUD."""

    def test_create_scan_run(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        run_id = db.create_scan_run("https://api.example.com")
        assert run_id > 0
        db.close()

    def test_finish_scan_run(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.finish_scan_run(run_id)
        run = q.get_latest_scan_run()
        assert run is not None
        assert run.status == "completed"
        assert run.finished_at is not None
        db.close()

    def test_get_latest_returns_none_when_empty(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        assert q.get_latest_scan_run() is None
        db.close()

    def test_get_latest_returns_dataclass(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        db.create_scan_run("https://api.example.com")
        run = q.get_latest_scan_run()
        assert isinstance(run, ScanRun)
        assert run.endpoint == "https://api.example.com"
        assert run.status == "running"
        db.close()


class TestEndpoints:
    """endpoints save + upsert + UNIQUE."""

    def test_save_endpoint_inserts(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        ep_id = db.save_endpoint(run_id, "/users", "GET", 200, "required")
        assert ep_id > 0
        eps = q.get_endpoints(run_id)
        assert len(eps) == 1
        assert isinstance(eps[0], Endpoint)
        assert eps[0].path == "/users"
        assert eps[0].method == "GET"
        assert eps[0].status_code == 200
        assert eps[0].auth_required == "required"
        db.close()

    def test_save_endpoint_upserts(self, tmp_path: Path) -> None:
        """Saving the same (run, path, method) updates the row."""
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        ep_id = db.save_endpoint(run_id, "/users", "GET", 200)
        ep_id2 = db.save_endpoint(run_id, "/users", "GET", 401)
        assert ep_id == ep_id2
        eps = q.get_endpoints(run_id)
        assert len(eps) == 1
        assert eps[0].status_code == 401
        db.close()

    def test_unique_constraint_direct_insert(self, tmp_path: Path) -> None:
        """Direct INSERT violating UNIQUE raises IntegrityError."""
        db = _make_db(tmp_path)
        run_id = db.create_scan_run("https://api.example.com")
        conn = db.connect()
        conn.execute(
            "INSERT INTO endpoints (scan_run_id, path, method) VALUES (?, ?, ?)",
            (run_id, "/users", "GET"),
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO endpoints (scan_run_id, path, method) VALUES (?, ?, ?)",
                (run_id, "/users", "GET"),
            )
        db.close()

    def test_foreign_key_enforcement(self, tmp_path: Path) -> None:
        """Inserting an endpoint with a non-existent run_id raises IntegrityError."""
        db = _make_db(tmp_path)
        with pytest.raises(sqlite3.IntegrityError):
            db.save_endpoint(99999, "/test", "GET")
        db.close()


class TestSpecInfo:
    """spec_info save + get."""

    def test_save_and_get(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_spec_info(run_id, "Test API", "1.0.0", 42, "https://api.example.com/openapi.json")
        si = q.get_spec_info(run_id)
        assert isinstance(si, SpecInfo)
        assert si.title == "Test API"
        assert si.version == "1.0.0"
        assert si.endpoints_count == 42
        db.close()

    def test_get_returns_none_when_absent(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        assert q.get_spec_info(1) is None
        db.close()


class TestAuthResults:
    """auth_results save + redaction + get."""

    def test_save_and_get(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_auth(run_id, None, "GET", "Bearer eyJhbG", 200, 401, "auth_required")
        ars = q.get_auth_results(run_id)
        assert len(ars) == 1
        assert isinstance(ars[0], AuthResult)
        assert ars[0].classification == "auth_required"
        assert ars[0].status_with == 200
        assert ars[0].status_without == 401
        db.close()

    def test_auth_type_is_redacted(self, tmp_path: Path) -> None:
        """The auth_type field must be redacted in the database."""
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_auth(run_id, None, "GET", "Bearer eyJhbGciOi", 200, 401, "auth_required")
        ars = q.get_auth_results(run_id)
        assert ars[0].auth_type == "Bearer ****"
        db.close()

    def test_auth_type_none_stays_none(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_auth(run_id, None, "GET", None, 200, 200, "public")
        ars = q.get_auth_results(run_id)
        assert ars[0].auth_type is None
        db.close()

    def test_invalid_classification_raises(self, tmp_path: Path) -> None:
        """A classification not in the CHECK constraint raises."""
        db = _make_db(tmp_path)
        run_id = db.create_scan_run("https://api.example.com")
        with pytest.raises(sqlite3.IntegrityError):
            db.save_auth(run_id, None, "GET", None, 200, 200, "bogus")
        db.close()


class TestFindings:
    """security_findings save + get + CHECK constraints."""

    def test_save_and_get(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_finding(
            run_id,
            None,
            "headers",
            "medium",
            "high",
            "Missing HSTS",
            "No HSTS header",
            "Enable HSTS",
        )
        fs = q.get_findings(run_id)
        assert len(fs) == 1
        assert isinstance(fs[0], Finding)
        assert fs[0].check_type == "headers"
        assert fs[0].severity == "medium"
        assert fs[0].confidence == "high"
        assert fs[0].title == "Missing HSTS"
        assert fs[0].detail == "No HSTS header"
        assert fs[0].remediation == "Enable HSTS"
        db.close()

    def test_invalid_severity_raises(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        run_id = db.create_scan_run("https://api.example.com")
        with pytest.raises(sqlite3.IntegrityError):
            db.save_finding(run_id, None, "headers", "critical", "high", "Title")
        db.close()

    def test_invalid_confidence_raises(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        run_id = db.create_scan_run("https://api.example.com")
        with pytest.raises(sqlite3.IntegrityError):
            db.save_finding(run_id, None, "headers", "medium", "ultimate", "Title")
        db.close()

    def test_findings_ordered_by_severity(self, tmp_path: Path) -> None:
        """Findings are returned high → medium → low → info."""
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_finding(run_id, None, "c", "info", "high", "Info finding")
        db.save_finding(run_id, None, "c", "high", "high", "High finding")
        db.save_finding(run_id, None, "c", "low", "high", "Low finding")
        db.save_finding(run_id, None, "c", "medium", "high", "Medium finding")
        fs = q.get_findings(run_id)
        assert [f.severity for f in fs] == ["high", "medium", "low", "info"]
        db.close()


class TestFuzzResults:
    """fuzz_results save + get."""

    def test_save_and_get(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_fuzz_result(run_id, None, "user_id", "query", "1,2,3", is_idor=True)
        frs = q.get_fuzz_results(run_id)
        assert len(frs) == 1
        assert isinstance(frs[0], FuzzResult)
        assert frs[0].param_name == "user_id"
        assert frs[0].param_in == "query"
        assert frs[0].variants == "1,2,3"
        assert frs[0].is_idor_candidate == 1
        db.close()

    def test_is_idor_false(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_fuzz_result(run_id, None, "page", "query", is_idor=False)
        frs = q.get_fuzz_results(run_id)
        assert frs[0].is_idor_candidate == 0
        db.close()


class TestCheckpoints:
    """checkpoints save + upsert + get + clear."""

    def test_save_and_get(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        db.save_checkpoint("https://api.example.com", "auth", "in_progress")
        cps = q.get_checkpoints("https://api.example.com")
        assert len(cps) == 1
        assert isinstance(cps[0], Checkpoint)
        assert cps[0].module == "auth"
        assert cps[0].status == "in_progress"
        db.close()

    def test_upsert_on_conflict(self, tmp_path: Path) -> None:
        """Saving the same (target, module) with a new status updates the row."""
        db = _make_db(tmp_path)
        q = Queries(db)
        db.save_checkpoint("https://api.example.com", "auth", "in_progress")
        db.save_checkpoint("https://api.example.com", "auth", "completed")
        cps = q.get_checkpoints("https://api.example.com")
        assert len(cps) == 1
        assert cps[0].status == "completed"
        assert cps[0].completed_at is not None
        db.close()

    def test_clear_checkpoints(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        db.save_checkpoint("https://api.example.com", "auth", "in_progress")
        db.clear_checkpoints("https://api.example.com")
        assert len(q.get_checkpoints("https://api.example.com")) == 0
        db.close()

    def test_clear_only_target(self, tmp_path: Path) -> None:
        """Clearing one target does not affect another."""
        db = _make_db(tmp_path)
        q = Queries(db)
        db.save_checkpoint("target_a", "auth", "in_progress")
        db.save_checkpoint("target_b", "auth", "in_progress")
        db.clear_checkpoints("target_a")
        assert len(q.get_checkpoints("target_a")) == 0
        assert len(q.get_checkpoints("target_b")) == 1
        db.close()


class TestMigrations:
    """Schema migration mechanism."""

    def test_migrate_noop_when_current(self, tmp_path: Path) -> None:
        """migrate() on a database already at the current version is a no-op."""
        db = _make_db(tmp_path)
        db.migrate()
        assert db.get_schema_version() == 1
        db.close()

    def test_migrate_applies_pending(self, tmp_path: Path, monkeypatch) -> None:
        """A registered migration is applied and schema_version is bumped."""
        import apihunter.core.db as dbmod

        db = _make_db(tmp_path)
        monkeypatch.setitem(dbmod.MIGRATIONS, 2, "CREATE TABLE IF NOT EXISTS _test_v2 (id INTEGER)")
        monkeypatch.setattr(dbmod, "CURRENT_SCHEMA_VERSION", 2)

        db.migrate()
        assert db.get_schema_version() == 2

        conn = db.connect()
        conn.execute("SELECT * FROM _test_v2").fetchall()
        db.close()

    def test_migrate_raises_on_invalid_sql(self, tmp_path: Path, monkeypatch) -> None:
        """A migration with invalid SQL raises MigrationError."""
        import apihunter.core.db as dbmod

        db = _make_db(tmp_path)
        monkeypatch.setitem(dbmod.MIGRATIONS, 2, "THIS IS NOT VALID SQL")
        monkeypatch.setattr(dbmod, "CURRENT_SCHEMA_VERSION", 2)

        with pytest.raises(MigrationError) as exc_info:
            db.migrate()
        assert exc_info.value.from_version == 1
        assert exc_info.value.to_version == 2
        db.close()

    def test_migration_error_is_database_error(self) -> None:
        assert issubclass(MigrationError, DatabaseError)

    def test_migrate_on_uninitialised_db(self, tmp_path: Path, monkeypatch) -> None:
        """migrate() on a database with no schema_version treats it as 0."""
        import apihunter.core.db as dbmod

        db = Database(tmp_path / "fresh.db")
        db.connect()
        # Create only the metadata table so get_schema_version works
        db.connect().execute(
            "CREATE TABLE IF NOT EXISTS metadata "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, value TEXT NOT NULL)"
        )
        db.connect().commit()
        assert db.get_schema_version() is None

        monkeypatch.setitem(dbmod.MIGRATIONS, 1, dbmod.SCHEMA_SQL)
        monkeypatch.setattr(dbmod, "CURRENT_SCHEMA_VERSION", 1)

        db.migrate()
        assert db.get_schema_version() == 1
        db.close()


class TestRollback:
    """Database remains operational after a failed write."""

    def test_db_works_after_exception(self, tmp_path: Path) -> None:
        """After a CHECK constraint violation, subsequent writes succeed."""
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")

        # This should fail (invalid severity)
        with pytest.raises(sqlite3.IntegrityError):
            db.save_finding(run_id, None, "headers", "critical", "high", "Bad")

        # This should succeed
        db.save_finding(run_id, None, "headers", "medium", "high", "Good")
        fs = q.get_findings(run_id)
        assert len(fs) == 1
        assert fs[0].title == "Good"
        db.close()

    def test_db_works_after_fk_exception(self, tmp_path: Path) -> None:
        """After an FK violation, subsequent writes succeed."""
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")

        with pytest.raises(sqlite3.IntegrityError):
            db.save_endpoint(99999, "/bad", "GET")

        db.save_endpoint(run_id, "/good", "GET", 200)
        assert len(q.get_endpoints(run_id)) == 1
        db.close()


class TestQueriesReturnTypes:
    """Queries methods return typed dataclasses, not dicts."""

    def test_get_endpoints_returns_endpoint_list(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_endpoint(run_id, "/users", "GET", 200)
        eps = q.get_endpoints(run_id)
        assert all(isinstance(e, Endpoint) for e in eps)
        db.close()

    def test_get_findings_returns_finding_list(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        run_id = db.create_scan_run("https://api.example.com")
        db.save_finding(run_id, None, "c", "info", "high", "T")
        fs = q.get_findings(run_id)
        assert all(isinstance(f, Finding) for f in fs)
        db.close()

    def test_get_checkpoints_returns_checkpoint_list(self, tmp_path: Path) -> None:
        db = _make_db(tmp_path)
        q = Queries(db)
        db.save_checkpoint("t", "m", "in_progress")
        cps = q.get_checkpoints("t")
        assert all(isinstance(c, Checkpoint) for c in cps)
        db.close()
