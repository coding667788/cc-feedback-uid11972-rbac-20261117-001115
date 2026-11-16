"""Command-line interface: init / serve / admin commands / snapshot export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .auth import create_session
from .authz import Authorizer
from .db import check_schema, init_database, read_tx
from .errors import ApiError, Forbidden, Unprocessable
from .service import Service


def _print(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _service(db: str) -> Service:
    return Service(check_schema(db), Authorizer(db))


def _admin_principal(db: str, username: str):
    with read_tx(db) as conn:
        row = conn.execute(
            "SELECT id, username, department, is_admin, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        raise Unprocessable(f"unknown user: {username}")
    if not int(row["is_admin"]):
        raise Forbidden(f"user is not an administrator: {username}")
    from .authz import Principal

    return Principal(
        user_id=int(row["id"]),
        username=str(row["username"]),
        department=str(row["department"]),
        is_admin=True,
    )


def cmd_init(args: argparse.Namespace) -> int:
    result = init_database(args.db, force=args.force)
    _print(result)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .http import serve_forever

    serve_forever(args.db, args.host, args.port)
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    token, info = create_session(args.db, args.username, args.password)
    _print({"token": token, "username": info["username"], "expires_at": info["expires_at"]})
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    service = _service(args.db)
    principal = _admin_principal(args.db, args.admin)
    _print(service.admin_state(principal, args.tenant))
    return 0


def cmd_create_role(args: argparse.Namespace) -> int:
    service = _service(args.db)
    principal = _admin_principal(args.db, args.admin)
    _print(service.create_role(principal, args.tenant, args.role))
    return 0


def cmd_set_user_roles(args: argparse.Namespace) -> int:
    service = _service(args.db)
    principal = _admin_principal(args.db, args.admin)
    _print(
        service.set_user_roles(principal, args.tenant, args.username, args.roles)
    )
    return 0


def cmd_set_parents(args: argparse.Namespace) -> int:
    service = _service(args.db)
    principal = _admin_principal(args.db, args.admin)
    _print(service.set_role_parents(principal, args.tenant, args.role, args.parents))
    return 0


def cmd_set_rules(args: argparse.Namespace) -> int:
    service = _service(args.db)
    principal = _admin_principal(args.db, args.admin)
    _print(service.set_role_rules(principal, args.tenant, args.role, args.rules))
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    """Consistent full snapshot for tests/comparisons (single read txn)."""
    db = check_schema(args.db)
    with read_tx(db) as conn:
        tenants = conn.execute("SELECT id, name FROM tenants ORDER BY id").fetchall()
        users = conn.execute(
            "SELECT id, username, department, is_admin, is_active FROM users ORDER BY id"
        ).fetchall()
        memberships = conn.execute(
            "SELECT tenant_id, user_id FROM user_tenants ORDER BY tenant_id, user_id"
        ).fetchall()
        roles = conn.execute(
            "SELECT id, tenant_id, name FROM roles ORDER BY tenant_id, id"
        ).fetchall()
        parents = conn.execute(
            "SELECT tenant_id, child_id, parent_id FROM role_parents ORDER BY tenant_id, child_id, parent_id"
        ).fetchall()
        rules = conn.execute(
            "SELECT id, tenant_id, role_id, effect, action, condition FROM rules ORDER BY tenant_id, id"
        ).fetchall()
        assignments = conn.execute(
            """
            SELECT ur.tenant_id, ur.user_id, u.username, ur.role_id, r.name AS role
              FROM user_roles ur
              JOIN users u ON u.id = ur.user_id
              JOIN roles r ON r.id = ur.role_id
             ORDER BY ur.tenant_id, ur.user_id, ur.role_id
            """
        ).fetchall()
        files = conn.execute(
            "SELECT tenant_id, file_id, owner_user_id, department, version FROM files ORDER BY tenant_id, file_id"
        ).fetchall()
        versions = conn.execute(
            "SELECT tenant_id, authz_version FROM tenant_meta ORDER BY tenant_id"
        ).fetchall()
        payload = {
            "tenants": [dict(r) for r in tenants],
            "users": [dict(r) for r in users],
            "memberships": [dict(r) for r in memberships],
            "roles": [dict(r) for r in roles],
            "parents": [dict(r) for r in parents],
            "rules": [dict(r) for r in rules],
            "assignments": [dict(r) for r in assignments],
            "files": [dict(r) for r in files],
            "authz_versions": [dict(r) for r in versions],
        }
    _print(payload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m rbac",
        description="Multi-tenant file-metadata service with RBAC inheritance.",
    )
    parser.add_argument("--db", default="data/rbac.db", help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create and seed the database")
    p_init.add_argument("--force", action="store_true", help="delete an existing database first")
    p_init.set_defaults(func=cmd_init)

    p_serve = sub.add_parser("serve", help="run the HTTP server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.set_defaults(func=cmd_serve)

    p_login = sub.add_parser("login", help="mint a bearer token")
    p_login.add_argument("username")
    p_login.add_argument("password")
    p_login.set_defaults(func=cmd_login)

    p_state = sub.add_parser("state", help="show tenant authorization state")
    p_state.add_argument("tenant")
    p_state.add_argument("--admin", default="admin")
    p_state.set_defaults(func=cmd_state)

    p_cr = sub.add_parser("create-role", help="create a role in a tenant")
    p_cr.add_argument("tenant")
    p_cr.add_argument("role")
    p_cr.add_argument("--admin", default="admin")
    p_cr.set_defaults(func=cmd_create_role)

    p_ur = sub.add_parser("set-user-roles", help="replace a user's direct roles")
    p_ur.add_argument("tenant")
    p_ur.add_argument("username")
    p_ur.add_argument("roles", nargs="*")
    p_ur.add_argument("--admin", default="admin")
    p_ur.set_defaults(func=cmd_set_user_roles)

    p_rp = sub.add_parser("set-role-parents", help="replace a role's parents")
    p_rp.add_argument("tenant")
    p_rp.add_argument("role")
    p_rp.add_argument("parents", nargs="*")
    p_rp.add_argument("--admin", default="admin")
    p_rp.set_defaults(func=cmd_set_parents)

    p_rr = sub.add_parser("set-role-rules", help="replace a role's rules")
    p_rr.add_argument("tenant")
    p_rr.add_argument("role")
    p_rr.add_argument(
        "rules",
        nargs="?",
        help="JSON list of {effect, action, condition}",
    )
    p_rr.add_argument("--rules-file", help="read rules JSON from a file instead")
    p_rr.add_argument("--admin", default="admin")
    p_rr.set_defaults(func=cmd_set_rules)

    p_dump = sub.add_parser("dump", help="print a consistent full snapshot as JSON")
    p_dump.set_defaults(func=cmd_dump)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "set-role-rules":
        raw = args.rules
        if args.rules_file:
            raw = Path(args.rules_file).read_text(encoding="utf-8")
        if raw is None:
            parser.error("set-role-rules needs rules JSON or --rules-file")
        try:
            args.rules = json.loads(raw)
        except json.JSONDecodeError as exc:
            parser.error(f"rules must be valid JSON: {exc}")
    try:
        return int(args.func(args))
    except ApiError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": exc.message}}), file=sys.stderr)
        return 2
    except (FileNotFoundError, FileExistsError, RuntimeError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
