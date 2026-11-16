"""Business operations: reads, authorized listing, safe updates, admin edits.

The service layer is transport-agnostic; the HTTP layer only parses/validates
input and maps :class:`ApiError` to responses.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable

from .authz import (
    Authorizer,
    EffectiveRoles,
    Principal,
    Resource,
    load_authz_version,
)
from .db import (
    add_rule_raw,
    bump_version,
    create_role,
    read_tx,
    utcnow_iso,
    write_tx,
)
from .errors import BadRequest, Conflict, Forbidden, NotFound, Unprocessable
from .hooks import TestHooks

MAX_PAGE_SIZE = 100
SORT_FIELDS = ("file_id", "owner", "department")
MAX_ROLES_PER_USER = 64
MAX_PARENTS_PER_ROLE = 64
MAX_RULES_PER_ROLE = 64
MAX_DEPARTMENT_LEN = 100


@dataclass(frozen=True)
class FileRecord:
    tenant_id: int
    tenant: str
    file_id: str
    owner_user_id: int
    owner: str
    department: str
    version: int
    updated_at: str

    def as_resource(self) -> Resource:
        return Resource(
            tenant_id=self.tenant_id,
            tenant=self.tenant,
            file_id=self.file_id,
            owner_user_id=self.owner_user_id,
            owner_username=self.owner,
            department=self.department,
            version=self.version,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "file_id": self.file_id,
            "owner": self.owner,
            "department": self.department,
            "version": self.version,
            "updated_at": self.updated_at,
        }


class Service:
    def __init__(
        self,
        db_path: str,
        authorizer: Authorizer | None = None,
        hooks: TestHooks | None = None,
    ) -> None:
        self.db_path = db_path
        self.authorizer = authorizer or Authorizer(db_path)
        self.hooks = hooks or TestHooks()

    # ------------------------------------------------------------------ util

    @staticmethod
    def _tenant(conn: sqlite3.Connection, name: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT id, name FROM tenants WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise NotFound(f"unknown tenant: {name}")
        return row

    @staticmethod
    def _membership(
        conn: sqlite3.Connection, tenant_id: int, user_id: int
    ) -> None:
        row = conn.execute(
            "SELECT 1 FROM user_tenants WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        if row is None:
            raise Forbidden("not a member of this tenant")

    @staticmethod
    def _principal(conn: sqlite3.Connection, user_id: int) -> Principal:
        row = conn.execute(
            "SELECT id, username, department, is_admin, is_active FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None or not int(row["is_active"]):
            raise Forbidden("user is no longer active")
        return Principal(
            user_id=int(row["id"]),
            username=str(row["username"]),
            department=str(row["department"]),
            is_admin=bool(row["is_admin"]),
        )

    @staticmethod
    def _require_admin(principal: Principal) -> None:
        if not principal.is_admin:
            raise Forbidden("administrator privileges required")

    @staticmethod
    def _file(
        conn: sqlite3.Connection, tenant_id: int, tenant_name: str, file_id: str
    ) -> FileRecord:
        row = conn.execute(
            """
            SELECT f.id, f.tenant_id, f.file_id, f.owner_user_id, f.department,
                   f.version, f.updated_at, u.username AS owner
              FROM files f
              JOIN users u ON u.id = f.owner_user_id
             WHERE f.tenant_id = ? AND f.file_id = ?
            """,
            (tenant_id, file_id),
        ).fetchone()
        if row is None:
            raise NotFound(f"file not found: {file_id}")
        return FileRecord(
            tenant_id=int(row["tenant_id"]),
            tenant=tenant_name,
            file_id=str(row["file_id"]),
            owner_user_id=int(row["owner_user_id"]),
            owner=str(row["owner"]),
            department=str(row["department"]),
            version=int(row["version"]),
            updated_at=str(row["updated_at"]),
        )

    @staticmethod
    def _list_file_rows(
        conn: sqlite3.Connection, tenant_id: int, tenant_name: str
    ) -> list[FileRecord]:
        rows = conn.execute(
            """
            SELECT f.id, f.tenant_id, f.file_id, f.owner_user_id, f.department,
                   f.version, f.updated_at, u.username AS owner
              FROM files f
              JOIN users u ON u.id = f.owner_user_id
             WHERE f.tenant_id = ?
            """,
            (tenant_id,),
        ).fetchall()
        return [
            FileRecord(
                tenant_id=int(r["tenant_id"]),
                tenant=tenant_name,
                file_id=str(r["file_id"]),
                owner_user_id=int(r["owner_user_id"]),
                owner=str(r["owner"]),
                department=str(r["department"]),
                version=int(r["version"]),
                updated_at=str(r["updated_at"]),
            )
            for r in rows
        ]

    def _effective(
        self,
        conn: sqlite3.Connection,
        tenant_id: int,
        principal: Principal,
        *,
        version: int | None = None,
    ) -> EffectiveRoles:
        return self.authorizer.effective_roles(
            conn, tenant_id, principal.user_id, version=version
        )

    # ----------------------------------------------------------- identity API

    def me(self, token_principal: Principal) -> dict[str, Any]:
        with read_tx(self.db_path) as conn:
            principal = self._principal(conn, token_principal.user_id)
            tenants = conn.execute(
                """
                SELECT t.id, t.name
                  FROM tenants t
                  JOIN user_tenants ut ON ut.tenant_id = t.id
                 WHERE ut.user_id = ?
                 ORDER BY t.name
                """,
                (principal.user_id,),
            ).fetchall()
            return {
                "user": {
                    "username": principal.username,
                    "department": principal.department,
                    "is_admin": principal.is_admin,
                },
                "tenants": [
                    {"tenant": str(r["name"]), "tenant_id": int(r["id"])}
                    for r in tenants
                ],
            }

    # ---------------------------------------------------------------- reads

    def get_file(self, token_principal: Principal, tenant_name: str, file_id: str,
                 sync_spec: tuple[str, str | None] | None = None) -> dict[str, Any]:
        with read_tx(self.db_path) as conn:
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            principal = self._principal(conn, token_principal.user_id)
            self._membership(conn, tenant_id, principal.user_id)
            record = self._file(conn, tenant_id, tenant_name, file_id)
            version = load_authz_version(conn, tenant_id)
            effective = self._effective(conn, tenant_id, principal, version=version)
            decision = self.authorizer.decide(
                principal,
                tenant_id,
                record.as_resource(),
                "read",
                conn=conn,
                effective=effective,
            )
            if sync_spec:
                self.hooks.sync("after_read_authz", sync_spec)
            if not decision.allowed:
                raise Forbidden("read denied", decision=decision.to_json())
            return {
                "resource": record.to_json(),
                "authz_version": version,
            }

    def list_files(
        self,
        token_principal: Principal,
        tenant_name: str,
        *,
        page: int = 1,
        page_size: int = 20,
        sort: str = "file_id",
        order: str = "asc",
        sync_spec: tuple[str, str | None] | None = None,
    ) -> dict[str, Any]:
        if sort not in SORT_FIELDS:
            raise BadRequest(f"sort must be one of {', '.join(SORT_FIELDS)}")
        if order not in ("asc", "desc"):
            raise BadRequest("order must be asc or desc")
        if page < 1:
            raise BadRequest("page must be >= 1")
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise BadRequest(f"page_size must be between 1 and {MAX_PAGE_SIZE}")

        with read_tx(self.db_path) as conn:
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            principal = self._principal(conn, token_principal.user_id)
            self._membership(conn, tenant_id, principal.user_id)

            # One snapshot: version, closure/rules, and every candidate row are
            # read inside this single read transaction.  Pagination happens
            # only after per-resource authorization.
            version = load_authz_version(conn, tenant_id)
            effective = self._effective(conn, tenant_id, principal, version=version)
            rows = self._list_file_rows(conn, tenant_id, tenant_name)

            if sync_spec:
                self.hooks.sync("after_list_snapshot", sync_spec)

            authorized: list[FileRecord] = []
            for record in rows:
                decision = self.authorizer.decide(
                    principal,
                    tenant_id,
                    record.as_resource(),
                    "read",
                    conn=conn,
                    effective=effective,
                )
                if decision.allowed:
                    authorized.append(record)

            reverse = order == "desc"
            # Sort key is (primary, file_id); reversing the whole tuple keeps
            # the ordering total and deterministic for equal primary values.
            if sort == "file_id":
                authorized.sort(key=lambda r: r.file_id, reverse=reverse)
            elif sort == "owner":
                authorized.sort(key=lambda r: (r.owner, r.file_id), reverse=reverse)
            else:
                authorized.sort(key=lambda r: (r.department, r.file_id), reverse=reverse)

            total = len(authorized)
            start = (page - 1) * page_size
            end = start + page_size
            page_rows = authorized[start:end]
            return {
                "items": [r.to_json() for r in page_rows],
                "page": page,
                "page_size": page_size,
                "total": total,
                "has_next": end < total,
                "authz_version": version,
            }

    # --------------------------------------------------------------- updates

    def update_file(
        self,
        token_principal: Principal,
        tenant_name: str,
        file_id: str,
        *,
        owner: str | None = None,
        department: str | None = None,
        sync_spec: tuple[str, str | None] | None = None,
    ) -> dict[str, Any]:
        if owner is None and department is None:
            raise BadRequest("provide owner and/or department")
        if owner is not None and not 1 <= len(owner) <= 100:
            raise BadRequest("owner must be 1..100 characters")
        if department is not None:
            if not department.strip():
                raise BadRequest("department must not be empty")
            if len(department) > MAX_DEPARTMENT_LEN:
                raise BadRequest(
                    f"department must be at most {MAX_DEPARTMENT_LEN} characters"
                )

        # Phase 1: authorization against a read snapshot.  This is where a
        # request can pause; a revocation committed meanwhile must not be
        # bypassed by the later write.
        with read_tx(self.db_path) as conn:
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            principal = self._principal(conn, token_principal.user_id)
            self._membership(conn, tenant_id, principal.user_id)
            current = self._file(conn, tenant_id, tenant_name, file_id)
            version = load_authz_version(conn, tenant_id)
            effective = self._effective(conn, tenant_id, principal, version=version)
            pre_decision = self.authorizer.decide(
                principal,
                tenant_id,
                current.as_resource(),
                "write",
                conn=conn,
                effective=effective,
            )
            if not pre_decision.allowed:
                raise Forbidden("write denied on current resource",
                                decision=pre_decision.to_json())
            target_owner_id = self._resolve_owner(
                conn, tenant_id, owner if owner is not None else current.owner
            )
            target_department = (
                department if department is not None else current.department
            )
            target_resource = Resource(
                tenant_id=tenant_id,
                tenant=tenant_name,
                file_id=file_id,
                owner_user_id=target_owner_id,
                owner_username=owner if owner is not None else current.owner,
                department=target_department,
                version=current.version,
            )
            target_decision = self.authorizer.decide(
                principal,
                tenant_id,
                target_resource,
                "write",
                conn=conn,
                effective=effective,
            )
            if not target_decision.allowed:
                raise Forbidden("write denied on target resource",
                                decision=target_decision.to_json())
            pre_version = version

        if sync_spec:
            self.hooks.sync("after_authz", sync_spec)

        # Phase 2: take the single SQLite writer slot, re-read *everything*
        # that matters (version, closure, current row, target owner) and
        # re-authorize against the fresh state.  Authorization and mutation
        # share one transaction, so no other writer can interleave.
        with write_tx(self.db_path) as conn:
            if sync_spec:
                # Test-only: pause while holding SQLite's writer slot.  Reads
                # in other processes must still proceed (WAL); other writers
                # wait, which is SQLite's own serialization, not an app lock.
                self.hooks.sync("after_write_begin", sync_spec)
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            principal = self._principal(conn, token_principal.user_id)
            self._membership(conn, tenant_id, principal.user_id)
            fresh_version = load_authz_version(conn, tenant_id)
            effective = self._effective(conn, tenant_id, principal, version=fresh_version)
            current = self._file(conn, tenant_id, tenant_name, file_id)

            pre_decision = self.authorizer.decide(
                principal,
                tenant_id,
                current.as_resource(),
                "write",
                conn=conn,
                effective=effective,
            )
            target_owner_id = self._resolve_owner(
                conn, tenant_id, owner if owner is not None else current.owner
            )
            target_department = (
                department if department is not None else current.department
            )
            target_resource = Resource(
                tenant_id=tenant_id,
                tenant=tenant_name,
                file_id=file_id,
                owner_user_id=target_owner_id,
                owner_username=owner if owner is not None else current.owner,
                department=target_department,
                version=current.version,
            )
            target_decision = self.authorizer.decide(
                principal,
                tenant_id,
                target_resource,
                "write",
                conn=conn,
                effective=effective,
            )
            if not pre_decision.allowed or not target_decision.allowed:
                denied = pre_decision if not pre_decision.allowed else target_decision
                raise Forbidden(
                    "write denied after revalidation (authorization changed)",
                    decision=denied.to_json(),
                    pre_version=pre_version,
                    current_version=fresh_version,
                )

            updated_at = utcnow_iso()
            conn.execute(
                """
                UPDATE files
                   SET owner_user_id = ?, department = ?, version = version + 1,
                       updated_at = ?
                 WHERE tenant_id = ? AND file_id = ?
                """,
                (target_owner_id, target_department, updated_at, tenant_id, file_id),
            )
            record = self._file(conn, tenant_id, tenant_name, file_id)
            return {
                "resource": record.to_json(),
                "previous": current.to_json(),
                "authz_version": fresh_version,
                "decisions": {
                    "pre": pre_decision.to_json(),
                    "target": target_decision.to_json(),
                },
            }

    @staticmethod
    def _resolve_owner(conn: sqlite3.Connection, tenant_id: int, username: str) -> int:
        row = conn.execute(
            """
            SELECT u.id, u.username
              FROM users u
              JOIN user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = ?
             WHERE u.username = ? AND u.is_active = 1
            """,
            (tenant_id, username),
        ).fetchone()
        if row is None:
            raise Unprocessable(f"owner must be an active member of the tenant: {username}")
        return int(row["id"])

    # --------------------------------------------------------- admin: state

    def admin_state(self, token_principal: Principal, tenant_name: str) -> dict[str, Any]:
        with read_tx(self.db_path) as conn:
            principal = self._principal(conn, token_principal.user_id)
            self._require_admin(principal)
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            version = load_authz_version(conn, tenant_id)
            roles = conn.execute(
                "SELECT id, name FROM roles WHERE tenant_id = ? ORDER BY name",
                (tenant_id,),
            ).fetchall()
            parents = conn.execute(
                """
                SELECT child_id, parent_id FROM role_parents
                 WHERE tenant_id = ? ORDER BY child_id, parent_id
                """,
                (tenant_id,),
            ).fetchall()
            rules = conn.execute(
                """
                SELECT id, role_id, effect, action, condition FROM rules
                 WHERE tenant_id = ? ORDER BY role_id, effect, action, condition
                """,
                (tenant_id,),
            ).fetchall()
            assignments = conn.execute(
                """
                SELECT ur.user_id, ur.role_id, u.username
                  FROM user_roles ur JOIN users u ON u.id = ur.user_id
                 WHERE ur.tenant_id = ? ORDER BY u.username, ur.role_id
                """,
                (tenant_id,),
            ).fetchall()
            members = conn.execute(
                """
                SELECT u.username, u.department FROM user_tenants ut
                  JOIN users u ON u.id = ut.user_id
                 WHERE ut.tenant_id = ? ORDER BY u.username
                """,
                (tenant_id,),
            ).fetchall()
            return {
                "tenant": tenant_name,
                "authz_version": version,
                "roles": [
                    {"id": int(r["id"]), "name": str(r["name"])} for r in roles
                ],
                "parents": [
                    {"child_id": int(r["child_id"]), "parent_id": int(r["parent_id"])}
                    for r in parents
                ],
                "rules": [
                    {
                        "id": int(r["id"]),
                        "role_id": int(r["role_id"]),
                        "effect": str(r["effect"]),
                        "action": str(r["action"]),
                        "condition": str(r["condition"]),
                    }
                    for r in rules
                ],
                "assignments": [
                    {
                        "username": str(r["username"]),
                        "role_id": int(r["role_id"]),
                    }
                    for r in assignments
                ],
                "members": [
                    {"username": str(r["username"]), "department": str(r["department"])}
                    for r in members
                ],
            }

    # --------------------------------------------------------- admin: writes

    def create_role(
        self, token_principal: Principal, tenant_name: str, name: str
    ) -> dict[str, Any]:
        if not isinstance(name, str) or not 1 <= len(name) <= 80:
            raise BadRequest("role name must be 1..80 characters")
        with write_tx(self.db_path) as conn:
            principal = self._principal(conn, token_principal.user_id)
            self._require_admin(principal)
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            try:
                role_id = create_role(conn, tenant_id, name)
            except sqlite3.IntegrityError as exc:
                raise Conflict(f"role already exists: {name}") from exc
            version = bump_version(conn, tenant_id)
            self.authorizer.cache.invalidate_tenant(tenant_id)
            return {"role": {"id": role_id, "name": name}, "authz_version": version}

    def set_user_roles(
        self,
        token_principal: Principal,
        tenant_name: str,
        username: str,
        role_names: Iterable[str],
    ) -> dict[str, Any]:
        roles = list(dict.fromkeys(role_names))
        if len(roles) > MAX_ROLES_PER_USER:
            raise BadRequest(f"at most {MAX_ROLES_PER_USER} roles per user")
        if any(not isinstance(r, str) or not r for r in roles):
            raise BadRequest("role names must be non-empty strings")
        with write_tx(self.db_path) as conn:
            principal = self._principal(conn, token_principal.user_id)
            self._require_admin(principal)
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            user = conn.execute(
                """
                SELECT u.id FROM users u
                  JOIN user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = ?
                 WHERE u.username = ? AND u.is_active = 1
                """,
                (tenant_id, username),
            ).fetchone()
            if user is None:
                raise Unprocessable(f"user is not an active tenant member: {username}")
            role_ids = self._role_ids(conn, tenant_id, roles)
            conn.execute(
                "DELETE FROM user_roles WHERE tenant_id = ? AND user_id = ?",
                (tenant_id, int(user["id"])),
            )
            for role_id in role_ids:
                conn.execute(
                    "INSERT INTO user_roles(tenant_id, user_id, role_id) VALUES (?, ?, ?)",
                    (tenant_id, int(user["id"]), role_id),
                )
            version = bump_version(conn, tenant_id)
            self.authorizer.cache.invalidate_tenant(tenant_id)
            return {
                "username": username,
                "roles": sorted(roles),
                "authz_version": version,
            }

    def set_role_parents(
        self,
        token_principal: Principal,
        tenant_name: str,
        role_name: str,
        parent_names: Iterable[str],
    ) -> dict[str, Any]:
        parents = list(dict.fromkeys(parent_names))
        if len(parents) > MAX_PARENTS_PER_ROLE:
            raise BadRequest(f"at most {MAX_PARENTS_PER_ROLE} parents per role")
        if any(not isinstance(p, str) or not p for p in parents):
            raise BadRequest("parent names must be non-empty strings")
        with write_tx(self.db_path) as conn:
            principal = self._principal(conn, token_principal.user_id)
            self._require_admin(principal)
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            role_id = self._role_id(conn, tenant_id, role_name)
            parent_ids = self._role_ids(conn, tenant_id, parents)
            # Cycles (including self-inheritance) are intentionally allowed:
            # the closure algorithm is cycle-safe.  Parent ids are resolved
            # within this tenant only, so identically named roles elsewhere
            # can never be attached.
            conn.execute(
                "DELETE FROM role_parents WHERE tenant_id = ? AND child_id = ?",
                (tenant_id, role_id),
            )
            for parent_id in parent_ids:
                conn.execute(
                    "INSERT INTO role_parents(tenant_id, child_id, parent_id) VALUES (?, ?, ?)",
                    (tenant_id, role_id, parent_id),
                )
            version = bump_version(conn, tenant_id)
            self.authorizer.cache.invalidate_tenant(tenant_id)
            return {
                "role": role_name,
                "parents": sorted(parents),
                "authz_version": version,
            }

    def set_role_rules(
        self,
        token_principal: Principal,
        tenant_name: str,
        role_name: str,
        rules: Iterable[dict[str, str]],
    ) -> dict[str, Any]:
        prepared = self._validate_rules(rules)
        with write_tx(self.db_path) as conn:
            principal = self._principal(conn, token_principal.user_id)
            self._require_admin(principal)
            tenant = self._tenant(conn, tenant_name)
            tenant_id = int(tenant["id"])
            role_id = self._role_id(conn, tenant_id, role_name)
            conn.execute(
                "DELETE FROM rules WHERE tenant_id = ? AND role_id = ?",
                (tenant_id, role_id),
            )
            for effect, action, condition in prepared:
                add_rule_raw(conn, tenant_id, role_id, effect, action, condition)
            version = bump_version(conn, tenant_id)
            self.authorizer.cache.invalidate_tenant(tenant_id)
            return {
                "role": role_name,
                "rules": [
                    {"effect": e, "action": a, "condition": c}
                    for e, a, c in prepared
                ],
                "authz_version": version,
            }

    @staticmethod
    def _validate_rules(
        rules: Iterable[dict[str, str]]
    ) -> list[tuple[str, str, str]]:
        if not isinstance(rules, (list, tuple)):
            raise BadRequest("rules must be a list")
        if len(rules) > MAX_RULES_PER_ROLE:
            raise BadRequest(f"at most {MAX_RULES_PER_ROLE} rules per role")
        prepared: list[tuple[str, str, str]] = []
        for item in rules:
            if not isinstance(item, dict):
                raise BadRequest("each rule must be an object")
            effect = item.get("effect")
            action = item.get("action")
            condition = item.get("condition")
            if effect not in ("allow", "deny"):
                raise Unprocessable("effect must be allow or deny")
            if action not in ("read", "write"):
                raise Unprocessable("action must be read or write")
            if condition not in ("any", "own", "same_department"):
                raise Unprocessable(
                    "condition must be any, own or same_department"
                )
            prepared.append((effect, action, condition))
        # duplicate combos are rejected by the UNIQUE constraint; dedupe here
        return sorted(set(prepared))

    @staticmethod
    def _role_id(conn: sqlite3.Connection, tenant_id: int, name: str) -> int:
        row = conn.execute(
            "SELECT id FROM roles WHERE tenant_id = ? AND name = ?",
            (tenant_id, name),
        ).fetchone()
        if row is None:
            raise Unprocessable(f"unknown role in this tenant: {name}")
        return int(row["id"])

    def _role_ids(
        self, conn: sqlite3.Connection, tenant_id: int, names: Iterable[str]
    ) -> list[int]:
        names = list(dict.fromkeys(names))
        if not names:
            return []
        placeholders = ",".join("?" for _ in names)
        rows = conn.execute(
            f"SELECT id, name FROM roles WHERE tenant_id = ? AND name IN ({placeholders})",
            (tenant_id, *names),
        ).fetchall()
        found = {str(r["name"]): int(r["id"]) for r in rows}
        missing = [n for n in names if n not in found]
        if missing:
            raise Unprocessable(f"unknown role(s) in this tenant: {', '.join(missing)}")
        return [found[n] for n in names]
