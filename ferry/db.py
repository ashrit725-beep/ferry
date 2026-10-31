"""SQLite storage and schema migrations.

Each Ferry installation keeps one SQLite file (<data_dir>/ferry.db). Every write
runs inside `write_tx`, which issues BEGIN IMMEDIATE so concurrent writers (the
server and a CLI import, for example) serialize instead of interleaving; the
audit hash chain depends on that ordering.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .util import ensure_private_dir, rfc3339

# Timestamps are RFC 3339 UTC strings (see util.rfc3339). JSON columns hold
# canonical JSON text. Booleans are 0/1 integers.
SCHEMA_V1 = """
CREATE TABLE admin_users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'auditor')),
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_login_at TEXT
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE principals (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'app' CHECK (kind IN ('app')),
  environment TEXT NOT NULL DEFAULT 'test' CHECK (environment IN ('test', 'pilot', 'production')),
  description TEXT NOT NULL DEFAULT '',
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE api_keys (
  key_id TEXT PRIMARY KEY,
  principal_id INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  secret_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  last_used_at TEXT
);

CREATE TABLE backends (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('llamacpp', 'ollama', 'openai')),
  base_url TEXT NOT NULL,
  auth_token_file TEXT,
  timeout_s REAL NOT NULL DEFAULT 120,
  max_concurrency INTEGER NOT NULL DEFAULT 4,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_status TEXT,
  last_checked_at TEXT
);

CREATE TABLE routes (
  id INTEGER PRIMARY KEY,
  model TEXT NOT NULL UNIQUE,
  backend_id INTEGER NOT NULL REFERENCES backends(id),
  upstream_model TEXT NOT NULL,
  artifact_digest TEXT,
  require_verified INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE policies (
  version INTEGER PRIMARY KEY,
  document TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  comment TEXT NOT NULL DEFAULT ''
);

CREATE TABLE active_policy (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL REFERENCES policies(version),
  activated_at TEXT NOT NULL,
  activated_by TEXT NOT NULL
);

CREATE TABLE bundles (
  bundle_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  manifest TEXT NOT NULL,
  signers TEXT NOT NULL,
  report TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  imported_by TEXT NOT NULL,
  source_name TEXT NOT NULL
);

CREATE TABLE artifacts (
  digest TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  kind TEXT NOT NULL,
  format TEXT NOT NULL,
  model_name TEXT,
  metadata TEXT NOT NULL,
  first_bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
  imported_at TEXT NOT NULL
);

CREATE TABLE bundle_artifacts (
  bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
  digest TEXT NOT NULL REFERENCES artifacts(digest),
  path TEXT NOT NULL,
  PRIMARY KEY (bundle_id, path)
);

CREATE TABLE verifications (
  id INTEGER PRIMARY KEY,
  source_name TEXT NOT NULL,
  bundle_id TEXT,
  bundle_name TEXT,
  bundle_version TEXT,
  verdict TEXT NOT NULL CHECK (verdict IN ('accepted', 'rejected')),
  mode TEXT NOT NULL CHECK (mode IN ('verify', 'import')),
  report TEXT NOT NULL,
  created_at TEXT NOT NULL,
  actor TEXT NOT NULL
);

CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  outcome TEXT NOT NULL,
  correlation_id TEXT,
  policy_version INTEGER,
  details TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);

CREATE INDEX idx_audit_ts ON audit_events(ts);
CREATE INDEX idx_audit_action ON audit_events(action);
CREATE INDEX idx_audit_outcome ON audit_events(outcome);
CREATE INDEX idx_audit_actor ON audit_events(actor_id);
CREATE INDEX idx_audit_correlation ON audit_events(correlation_id);
CREATE INDEX idx_verifications_created ON verifications(created_at);
CREATE INDEX idx_api_keys_principal ON api_keys(principal_id);
"""

# v2: indexes for the reads the console repeats against a log that only grows.
# (action, ts) serves the Overview traffic window. idx_audit_action stays: as an index on
# (action, rowid) it gives action-filtered, newest-first pages without a sort, which
# (action, ts) cannot. (resource, seq) and (actor_type, seq) do the same for those
# filters, and actor_type's index also serves the facet skip-scan.
SCHEMA_V2 = """
CREATE INDEX idx_audit_action_ts ON audit_events(action, ts);
CREATE INDEX idx_audit_resource_seq ON audit_events(resource, seq);
CREATE INDEX idx_audit_actor_type_seq ON audit_events(actor_type, seq);
"""

MIGRATIONS: list[tuple[int, str]] = [(1, SCHEMA_V1), (2, SCHEMA_V2)]
LATEST_VERSION = MIGRATIONS[-1][0]


def connect(path: Path) -> sqlite3.Connection:
    """Open a connection in autocommit mode; use write_tx() for writes."""
    conn = sqlite3.connect(str(path), timeout=30.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


@contextmanager
def write_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT, rolling back on any exception. Does not nest."""
    if conn.in_transaction:
        raise RuntimeError("write_tx does not nest; this connection already has an open transaction")
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _statements(sql: str) -> list[str]:
    # The schema contains no semicolons inside literals, so a plain split is safe.
    return [s.strip() for s in sql.split(";") if s.strip()]


def current_version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return int(row["v"] or 0)


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations, each in its own transaction. Returns the schema version."""
    version = current_version(conn)
    if version > LATEST_VERSION:
        raise RuntimeError(
            f"database schema v{version} is newer than this Ferry build supports (v{LATEST_VERSION}); refusing to run"
        )
    for target, sql in MIGRATIONS:
        if target <= version:
            continue
        with write_tx(conn):
            for statement in _statements(sql):
                conn.execute(statement)
            conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (target, rfc3339()))
        version = target
    return version


class Database:
    """Opens short-lived connections to one SQLite file.

    SQLite connections are cheap; each request or CLI command opens its own so
    that transactions from different threads never interleave on one connection.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def init(self) -> int:
        ensure_private_dir(self.path.parent)
        conn = connect(self.path)
        try:
            version = migrate(conn)
        finally:
            conn.close()
        self.path.chmod(0o600)
        return version

    def connect(self) -> sqlite3.Connection:
        return connect(self.path)

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        conn = connect(self.path)
        try:
            yield conn
        finally:
            conn.close()
