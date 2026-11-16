"""Bearer-token authentication backed entirely by the shared database.

Authentication is a *read* operation and uses a read transaction, so ordinary
requests never contend for SQLite's single writer slot.  Tokens are stored as
SHA-256 hashes; the raw token never touches the database.

Password verification (PBKDF2) is deliberately performed *outside* any write
transaction: otherwise every login would hold SQLite's single writer slot for
tens of milliseconds and serialize unrelated management writes.
"""

from __future__ import annotations

import secrets

from .db import (
    hash_password,
    now_epoch,
    read_tx,
    token_hash,
    verify_password,
    write_tx,
)
from .errors import Unauthorized

SESSION_TTL_SECONDS = 8 * 60 * 60

# A real hash so unknown usernames cost the same PBKDF2 work as known ones.
_DUMMY_HASH = hash_password("dummy-password-for-timing-equalization", iterations=120_000)


def create_session(db_path: str, username: str, password: str) -> tuple[str, dict]:
    with read_tx(db_path) as conn:
        row = conn.execute(
            "SELECT id, username, department, password_hash, is_active "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row is None:
        verify_password(password, _DUMMY_HASH)  # equalize timing
        raise Unauthorized("invalid credentials")
    if not verify_password(password, row["password_hash"]):
        raise Unauthorized("invalid credentials")
    if not int(row["is_active"]):
        raise Unauthorized("invalid credentials")

    token = secrets.token_urlsafe(32)
    now = now_epoch()
    expires = now + SESSION_TTL_SECONDS
    with write_tx(db_path) as conn:
        conn.execute(
            "INSERT INTO sessions(token_hash, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token_hash(token), int(row["id"]), now, expires),
        )
        # opportunistic cleanup; keeps the table bounded without a cron job
        conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
            (now - 24 * 60 * 60,),
        )
    return token, {
        "user_id": int(row["id"]),
        "username": str(row["username"]),
        "expires_at": expires,
    }


def authenticate(db_path: str, token: str) -> dict:
    if not token:
        raise Unauthorized("missing bearer token")
    with read_tx(db_path) as conn:
        row = conn.execute(
            """
            SELECT s.id AS session_id, s.expires_at, s.revoked_at,
                   u.id AS user_id, u.username, u.department, u.is_admin, u.is_active
              FROM sessions s
              JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ?
            """,
            (token_hash(token),),
        ).fetchone()
        if row is None:
            raise Unauthorized("invalid or expired session")
        if row["revoked_at"] is not None:
            raise Unauthorized("session revoked")
        if int(row["expires_at"]) <= now_epoch():
            raise Unauthorized("invalid or expired session")
        if not int(row["is_active"]):
            raise Unauthorized("user disabled")
        return {
            "user_id": int(row["user_id"]),
            "username": str(row["username"]),
            "department": str(row["department"]),
            "is_admin": bool(row["is_admin"]),
        }


def revoke_session(db_path: str, token: str) -> None:
    with write_tx(db_path) as conn:
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (now_epoch(), token_hash(token)),
        )


def revoke_all_sessions(db_path: str, user_id: int) -> int:
    with write_tx(db_path) as conn:
        cur = conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (now_epoch(), user_id),
        )
        return int(cur.rowcount or 0)


def purge_expired_sessions(db_path: str) -> int:
    with write_tx(db_path) as conn:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_epoch(),))
        return int(cur.rowcount or 0)
