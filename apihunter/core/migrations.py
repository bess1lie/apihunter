"""Schema migrations for apihunter.

Each migration is a mapping ``{version: sql}`` where *sql* is a string
of DDL/DML statements executed via ``executescript``.  Migrations are
applied in ascending order by :meth:`apihunter.core.db.Database.migrate`.

To add a migration in a future release:

1.  Add an entry to :data:`MIGRATIONS` with the next version number.
2.  Bump :data:`apihunter.core.schema.CURRENT_SCHEMA_VERSION`.
3.  Add a test in ``tests/test_db.py`` covering the migration path.
"""

from __future__ import annotations

MIGRATIONS: dict[int, str] = {}
