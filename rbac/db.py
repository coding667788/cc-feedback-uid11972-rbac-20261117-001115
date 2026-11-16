"""SQLite schema, connection helpers, and preset bootstrap data."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_meta (
    tenant_id       INTEGER PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    authz_version   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    department      TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_tenants (
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);

-- child inherits every permission attached to parent
CREATE TABLE IF NOT EXISTS role_parents (
    tenant_id   INTEGER NOT NULL,
    child_id    INTEGER NOT NULL,
    parent_id   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, child_id, parent_id),
    FOREIGN KEY (tenant_id, child_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, parent_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_roles (
    tenant_id   INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    role_id     INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id, role_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES user_tenants(tenant_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL,
    role_id     INTEGER NOT NULL,
    effect      TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    action      TEXT NOT NULL CHECK (action IN ('read', 'write')),
    condition   TEXT NOT NULL CHECK (condition IN ('any', 'own', 'same_department')),
    created_at  TEXT NOT NULL,
    UNIQUE (tenant_id, role_id, effect, action, condition),
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    file_id         TEXT NOT NULL,
    owner_user_id   INTEGER NOT NULL,
    department      TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (tenant_id, file_id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, owner_user_id)
        REFERENCES user_tenants(tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_files_tenant_file ON files(tenant_id, file_id);
CREATE INDEX IF NOT EXISTS idx_rules_tenant_role ON rules(tenant_id, role_id);
CREATE INDEX IF NOT EXISTS idx_role_parents_parent ON role_parents(tenant_id, parent_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def now_epoch() -> int:
    return int(time.time())


def hash_password(password: str, *, iterations: int = 120_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations_s, salt_hex, expected_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def connect(db_path: str | os.PathLike[str]) -> sqlite3.Connection:
    """Open a connection with per-connection safety pragmas.

    WAL is configured once by :func:`init_database`; issuing it on every
    connection would take a brief exclusive lock and is unnecessary.
    """
    conn = sqlite3.connect(
        str(db_path),
        timeout=30.0,
        isolation_level=None,  # explicit BEGIN/COMMIT
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def read_tx(db_path: str | os.PathLike[str]) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        conn.execute("BEGIN")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def _begin_immediate(conn: sqlite3.Connection) -> None:
    """Acquire SQLite's single writer slot, waiting transparently if busy.

    This is a storage-level serialization only for writers -- readers never
    take it -- and it is what makes "recheck then update" atomic across
    processes without any application-wide mutex.
    """
    last: sqlite3.OperationalError | None = None
    for attempt in range(8):
        try:
            conn.execute("BEGIN IMMEDIATE")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            last = exc
            time.sleep(min(0.02 * (attempt + 1), 0.25))
    assert last is not None
    raise last


def _commit(conn: sqlite3.Connection) -> None:
    last: sqlite3.OperationalError | None = None
    for attempt in range(8):
        try:
            conn.execute("COMMIT")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            last = exc
            time.sleep(min(0.02 * (attempt + 1), 0.25))
    assert last is not None
    raise last


@contextmanager
def write_tx(db_path: str | os.PathLike[str]) -> Iterator[sqlite3.Connection]:
    """Serializable writer transaction shared by all service processes."""
    conn = connect(db_path)
    try:
        _begin_immediate(conn)
        yield conn
        _commit(conn)
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def _remove_sqlite_files(db_path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            Path(str(db_path) + suffix).unlink()
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Low-level bootstrap helpers. They assume the caller owns the transaction.
# Production mutations go through rbac.service so the authz version is bumped.
# ---------------------------------------------------------------------------


def create_tenant(conn: sqlite3.Connection, name: str, *, version: int = 1) -> int:
    cur = conn.execute(
        "INSERT INTO tenants(name, created_at) VALUES (?, ?)", (name, utcnow_iso())
    )
    tenant_id = int(cur.lastrowid)
    conn.execute(
        "INSERT INTO tenant_meta(tenant_id, authz_version) VALUES (?, ?)",
        (tenant_id, version),
    )
    return tenant_id


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    department: str,
    *,
    is_admin: bool = False,
    is_active: bool = True,
    iterations: int = 120_000,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO users(username, department, password_hash, is_admin, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            department,
            hash_password(password, iterations=iterations),
            int(is_admin),
            int(is_active),
            utcnow_iso(),
        ),
    )
    return int(cur.lastrowid)


def add_membership(conn: sqlite3.Connection, tenant_id: int, user_id: int) -> None:
    conn.execute(
        "INSERT INTO user_tenants(tenant_id, user_id, created_at) VALUES (?, ?, ?)",
        (tenant_id, user_id, utcnow_iso()),
    )


def get_tenant_id(conn: sqlite3.Connection, name: str) -> int:
    row = conn.execute("SELECT id FROM tenants WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise KeyError(f"unknown tenant: {name}")
    return int(row["id"])


def create_role(conn: sqlite3.Connection, tenant_id: int, name: str) -> int:
    cur = conn.execute(
        "INSERT INTO roles(tenant_id, name, created_at) VALUES (?, ?, ?)",
        (tenant_id, name, utcnow_iso()),
    )
    return int(cur.lastrowid)


def set_role_parents_raw(
    conn: sqlite3.Connection, tenant_id: int, role_id: int, parent_ids: list[int]
) -> None:
    conn.execute(
        "DELETE FROM role_parents WHERE tenant_id = ? AND child_id = ?",
        (tenant_id, role_id),
    )
    for parent_id in sorted(set(parent_ids)):
        conn.execute(
            "INSERT INTO role_parents(tenant_id, child_id, parent_id) VALUES (?, ?, ?)",
            (tenant_id, role_id, parent_id),
        )


def set_user_roles_raw(
    conn: sqlite3.Connection, tenant_id: int, user_id: int, role_ids: list[int]
) -> None:
    conn.execute(
        "DELETE FROM user_roles WHERE tenant_id = ? AND user_id = ?",
        (tenant_id, user_id),
    )
    for role_id in sorted(set(role_ids)):
        conn.execute(
            "INSERT INTO user_roles(tenant_id, user_id, role_id) VALUES (?, ?, ?)",
            (tenant_id, user_id, role_id),
        )


def add_rule_raw(
    conn: sqlite3.Connection,
    tenant_id: int,
    role_id: int,
    effect: str,
    action: str,
    condition: str,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO rules(tenant_id, role_id, effect, action, condition, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (tenant_id, role_id, effect, action, condition, utcnow_iso()),
    )
    return int(cur.lastrowid)


def add_file_raw(
    conn: sqlite3.Connection,
    tenant_id: int,
    file_id: str,
    owner_user_id: int,
    department: str,
) -> int:
    now = utcnow_iso()
    cur = conn.execute(
        """
        INSERT INTO files(tenant_id, file_id, owner_user_id, department, version, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
        """,
        (tenant_id, file_id, owner_user_id, department, now, now),
    )
    return int(cur.lastrowid)


def bump_version(
    conn: sqlite3.Connection, tenant_id: int, *, by: int = 1
) -> int:
    row = conn.execute(
        """
        UPDATE tenant_meta
           SET authz_version = authz_version + ?
         WHERE tenant_id = ?
        RETURNING authz_version
        """,
        (by, tenant_id),
    ).fetchone()
    if row is None:
        raise KeyError(f"unknown tenant id: {tenant_id}")
    return int(row["authz_version"])


# ---------------------------------------------------------------------------
# Preset fixture
# ---------------------------------------------------------------------------

PRESET_CREDENTIALS: dict[str, str] = {
    "admin": "AdminPass1!",
    "alice": "AlicePass1!",
    "bob": "BobPass1!",
    "carol": "CarolPass1!",
    "dave": "DavePass1!",
}

# Deliberately includes a cycle: cycle-a <-> cycle-b, and cycle-b -> reader.
PRESET_ROLES: dict[str, dict[str, list[str]]] = {
    "acme": {
        "tenant-admin": [],
        "reader": [],
        "developer": ["reader"],
        "reviewer": ["reader"],
        "sales-writer": [],
        "suspended": [],
        "cycle-a": ["cycle-b"],
        "cycle-b": ["cycle-a", "reader"],
    },
    "globex": {
        "tenant-admin": [],
        "reader": [],
        "developer": ["reader"],
        "auditor": [],
    },
    "umbrella": {
        "tenant-admin": [],
        "guest": [],
        "manager": ["guest"],
    },
}

# (tenant, role, effect, action, condition)
PRESET_RULES: list[tuple[str, str, str, str, str]] = [
    ("acme", "tenant-admin", "allow", "read", "any"),
    ("acme", "tenant-admin", "allow", "write", "any"),
    ("acme", "reader", "allow", "read", "any"),
    ("acme", "developer", "allow", "write", "own"),
    ("acme", "reviewer", "allow", "read", "same_department"),
    ("acme", "sales-writer", "allow", "read", "same_department"),
    ("acme", "sales-writer", "allow", "write", "same_department"),
    ("acme", "suspended", "deny", "read", "any"),
    ("acme", "suspended", "deny", "write", "any"),
    # same role names in another tenant, intentionally different powers
    ("globex", "tenant-admin", "allow", "read", "any"),
    ("globex", "tenant-admin", "allow", "write", "any"),
    ("globex", "reader", "allow", "read", "any"),
    ("globex", "developer", "allow", "write", "any"),
    ("globex", "auditor", "allow", "read", "any"),
    ("globex", "auditor", "deny", "write", "any"),
    # umbrella reuses the "tenant-admin" name but with different rule rows;
    # guest stays deliberately narrow (own resources only).
    ("umbrella", "tenant-admin", "allow", "read", "any"),
    ("umbrella", "tenant-admin", "allow", "write", "any"),
    ("umbrella", "guest", "allow", "read", "own"),
    ("umbrella", "manager", "allow", "read", "any"),
    ("umbrella", "manager", "allow", "write", "any"),
]

PRESET_ASSIGNMENTS: dict[str, dict[str, list[str]]] = {
    "acme": {
        "admin": ["tenant-admin"],
        "alice": ["developer", "cycle-a"],
        "bob": ["reader", "reviewer"],
        "carol": ["sales-writer"],
        "dave": ["reader", "suspended"],
    },
    "globex": {
        "admin": ["tenant-admin"],
        "alice": ["developer"],
        "bob": ["auditor"],
    },
    "umbrella": {
        "admin": ["tenant-admin"],
        "alice": ["guest"],
        "bob": ["manager"],
    },
}

PRESET_MEMBERSHIPS: dict[str, list[str]] = {
    "acme": ["admin", "alice", "bob", "carol", "dave"],
    "globex": ["admin", "alice", "bob"],
    "umbrella": ["admin", "alice", "bob"],
}

PRESET_DEPARTMENTS: dict[str, str] = {
    "admin": "platform",
    "alice": "engineering",
    "bob": "engineering",
    "carol": "sales",
    "dave": "engineering",
}

PRESET_FILES: list[tuple[str, str, str, str]] = [
    ("acme", "A-100", "alice", "engineering"),
    ("acme", "A-101", "bob", "engineering"),
    ("acme", "A-102", "carol", "sales"),
    ("acme", "A-103", "dave", "engineering"),
    ("acme", "A-104", "alice", "sales"),
    ("acme", "A-105", "bob", "finance"),
    ("acme", "A-106", "carol", "marketing"),
    ("globex", "G-200", "alice", "engineering"),
    ("globex", "G-201", "bob", "engineering"),
    ("globex", "G-202", "bob", "sales"),
    ("umbrella", "U-300", "alice", "engineering"),
    ("umbrella", "U-301", "bob", "sales"),
]


def seed_preset(conn: sqlite3.Connection) -> None:
    """Insert preset tenants/users/roles/rules/files in the caller's txn."""
    tenant_ids: dict[str, int] = {}
    user_ids: dict[str, int] = {}
    role_ids: dict[tuple[str, str], int] = {}

    for tenant_name in PRESET_MEMBERSHIPS:
        tenant_ids[tenant_name] = create_tenant(conn, tenant_name)

    for username, password in PRESET_CREDENTIALS.items():
        user_ids[username] = create_user(
            conn,
            username,
            password,
            PRESET_DEPARTMENTS[username],
            is_admin=(username == "admin"),
        )

    for tenant_name, members in PRESET_MEMBERSHIPS.items():
        for username in members:
            add_membership(conn, tenant_ids[tenant_name], user_ids[username])

    for tenant_name, roles in PRESET_ROLES.items():
        for role_name in roles:
            role_ids[(tenant_name, role_name)] = create_role(
                conn, tenant_ids[tenant_name], role_name

            )
        for role_name, parents in roles.items():
            set_role_parents_raw(
                conn,
                tenant_ids[tenant_name],
                role_ids[(tenant_name, role_name)],
                [role_ids[(tenant_name, p)] for p in parents],
            )

    for tenant_name, role_name, effect, action, condition in PRESET_RULES:
        add_rule_raw(
            conn,
            tenant_ids[tenant_name],
            role_ids[(tenant_name, role_name)],
            effect,
            action,
            condition,
        )

    for tenant_name, assignments in PRESET_ASSIGNMENTS.items():
        for username, roles in assignments.items():
            set_user_roles_raw(
                conn,
                tenant_ids[tenant_name],
                user_ids[username],
                [role_ids[(tenant_name, r)] for r in roles],
            )

    for tenant_name, file_id, owner, department in PRESET_FILES:
        add_file_raw(
            conn,
            tenant_ids[tenant_name],
            file_id,
            user_ids[owner],
            department,
        )


def init_database(
    db_path: str | os.PathLike[str], *, force: bool = False, seed: bool = True
) -> dict[str, Any]:
    """Create (and by default seed) the database.

    Refuses to overwrite unless ``force=True``.  ``seed=False`` creates the
    schema only, which the differential tests use to build random fixtures.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not force:
            raise FileExistsError(f"database already exists: {path}")
        _remove_sqlite_files(path)

    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(SCHEMA_SQL)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        if seed:
            conn.execute("BEGIN IMMEDIATE")
            try:
                seed_preset(conn)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
    finally:
        conn.close()

    result: dict[str, Any] = {
        "database": str(path),
        "schema_version": SCHEMA_VERSION,
        "seeded": bool(seed),
    }
    if seed:
        result.update(
            {
                "tenants": sorted(PRESET_MEMBERSHIPS),
                "credentials": dict(PRESET_CREDENTIALS),
                "files": len(PRESET_FILES),
                "roles": sum(len(v) for v in PRESET_ROLES.values()),
                "rules": len(PRESET_RULES),
            }
        )
    return result


def check_schema(db_path: str | os.PathLike[str]) -> str:
    """Cheap startup validation; returns normalized absolute path."""
    path = Path(db_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"database does not exist: {path}")
    conn = connect(path)
    try:
        row = conn.execute("PRAGMA user_version").fetchone()
        version = int(row[0]) if row else 0
        if version != SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {version} does not match {SCHEMA_VERSION}"
            )
        tenant = conn.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()
        if tenant is None or int(tenant["n"]) == 0:
            raise RuntimeError("database has no tenants")
    finally:
        conn.close()
    return str(path)
