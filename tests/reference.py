"""Independent, deliberately naive reference implementation.

This module shares *no code* with ``rbac``.  It reads a single SQLite snapshot
and answers authorization/list queries with recursive DFS and a straightforward
filter-then-sort-then-paginate pipeline.  Tests compare production results
against it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable

ACTION_READ = "read"
ACTION_WRITE = "write"


@dataclass(frozen=True)
class RefResource:
    tenant_id: int
    file_id: str
    owner_user_id: int
    owner_username: str
    department: str
    version: int


class Snapshot:
    def __init__(self, db_path: str) -> None:
        conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN")
            self.tenants = {int(r["id"]): str(r["name"]) for r in conn.execute("SELECT id, name FROM tenants")}
            self.tenant_by_name = {v: k for k, v in self.tenants.items()}
            self.users = {
                int(r["id"]): {
                    "username": str(r["username"]),
                    "department": str(r["department"]),
                    "is_active": int(r["is_active"]),
                }
                for r in conn.execute("SELECT id, username, department, is_active FROM users")
            }
            self.user_by_name = {v["username"]: k for k, v in self.users.items()}
            self.memberships = {
                (int(r["tenant_id"]), int(r["user_id"]))
                for r in conn.execute("SELECT tenant_id, user_id FROM user_tenants")
            }
            self.roles = {
                int(r["id"]): (int(r["tenant_id"]), str(r["name"]))
                for r in conn.execute("SELECT id, tenant_id, name FROM roles")
            }
            self.role_id_by_name = {
                (tid, name): rid for rid, (tid, name) in self.roles.items()
            }
            self.parents: dict[int, list[int]] = {rid: [] for rid in self.roles}
            for r in conn.execute("SELECT child_id, parent_id FROM role_parents"):
                self.parents[int(r["child_id"])].append(int(r["parent_id"]))
            self.user_roles: dict[tuple[int, int], list[int]] = {}
            for r in conn.execute("SELECT tenant_id, user_id, role_id FROM user_roles"):
                self.user_roles.setdefault(
                    (int(r["tenant_id"]), int(r["user_id"])), []
                ).append(int(r["role_id"]))
            self.rules: dict[int, list[dict[str, str]]] = {rid: [] for rid in self.roles}
            for r in conn.execute(
                "SELECT tenant_id, role_id, effect, action, condition FROM rules"
            ):
                self.rules[int(r["role_id"])].append(
                    {
                        "effect": str(r["effect"]),
                        "action": str(r["action"]),
                        "condition": str(r["condition"]),
                    }
                )
            self.files: list[RefResource] = [
                RefResource(
                    tenant_id=int(r["tenant_id"]),
                    file_id=str(r["file_id"]),
                    owner_user_id=int(r["owner_user_id"]),
                    owner_username=str(r["owner"]),
                    department=str(r["department"]),
                    version=int(r["version"]),
                )
                for r in conn.execute(
                    """
                    SELECT f.tenant_id, f.file_id, f.owner_user_id, f.department,
                           f.version, u.username AS owner
                      FROM files f JOIN users u ON u.id = f.owner_user_id
                    """
                )
            ]
            self.authz_versions = {
                int(r["tenant_id"]): int(r["authz_version"])
                for r in conn.execute("SELECT tenant_id, authz_version FROM tenant_meta")
            }
            conn.execute("COMMIT")
        finally:
            conn.close()

    # ------------------------------------------------------------------ core

    def closure(self, tenant_id: int, user_id: int) -> set[int]:
        """Recursive DFS, cycle-safe by revisiting guard (visited set)."""
        visited: set[int] = set()

        def walk(role_id: int) -> None:
            if role_id in visited:
                return
            if role_id not in self.roles or self.roles[role_id][0] != tenant_id:
                return  # a role from another tenant is never usable here
            visited.add(role_id)
            for parent in self.parents.get(role_id, []):
                walk(parent)

        for role_id in self.user_roles.get((tenant_id, user_id), []):
            walk(role_id)
        return visited

    def role_names(self, tenant_id: int, user_id: int) -> list[str]:
        names = [self.roles[r][1] for r in self.closure(tenant_id, user_id)]
        return sorted(names)

    def is_member(self, tenant_id: int, user_id: int) -> bool:
        return (tenant_id, user_id) in self.memberships

    def decide(
        self, tenant: str, username: str, file_id: str, action: str
    ) -> bool:
        tenant_id = self.tenant_by_name[tenant]
        user_id = self.user_by_name[username]
        return self.decide_ids(tenant_id, user_id, file_id, action)

    def decide_ids(
        self, tenant_id: int, user_id: int, file_id: str, action: str
    ) -> bool:
        if not self.is_member(tenant_id, user_id):
            return False
        file = next(
            f for f in self.files if f.tenant_id == tenant_id and f.file_id == file_id
        )
        return self._decide_resource(tenant_id, user_id, file, action)

    def _decide_resource(
        self, tenant_id: int, user_id: int, file: RefResource, action: str
    ) -> bool:
        user = self.users.get(user_id)
        if user is None or not user["is_active"]:
            return False
        closure = self.closure(tenant_id, user_id)
        saw_allow = False
        for role_id in closure:
            for rule in self.rules.get(role_id, []):
                if rule["action"] != action:
                    continue
                cond = rule["condition"]
                if cond == "any":
                    matches = True
                elif cond == "own":
                    matches = file.owner_user_id == user_id
                elif cond == "same_department":
                    matches = file.department == user["department"]
                else:
                    raise AssertionError(f"bad condition {cond}")
                if not matches:
                    continue
                if rule["effect"] == "deny":
                    return False
                if rule["effect"] == "allow":
                    saw_allow = True
                else:
                    raise AssertionError(f"bad effect {rule['effect']}")
        return saw_allow

    # ---------------------------------------------------------------- listing

    def authorized_files(
        self, tenant: str, username: str, action: str = "read"
    ) -> list[RefResource]:
        tenant_id = self.tenant_by_name[tenant]
        user_id = self.user_by_name[username]
        if not self.is_member(tenant_id, user_id):
            return []
        rows = [f for f in self.files if f.tenant_id == tenant_id]
        rows = [
            f for f in rows if self._decide_resource(tenant_id, user_id, f, action)
        ]
        rows.sort(key=lambda f: f.file_id)
        return rows

    def list_page(
        self,
        tenant: str,
        username: str,
        *,
        page: int = 1,
        page_size: int = 20,
        action: str = "read",
    ) -> dict[str, Any]:
        rows = self.authorized_files(tenant, username, action)
        total = len(rows)
        start = (page - 1) * page_size
        page_rows = rows[start : start + page_size]
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": [
                {
                    "tenant": tenant,
                    "file_id": f.file_id,
                    "owner": f.owner_username,
                    "department": f.department,
                    "version": f.version,
                }
                for f in page_rows
            ],
        }
