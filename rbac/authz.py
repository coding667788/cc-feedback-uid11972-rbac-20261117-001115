"""Authorization engine: identity resolution, cycle-safe closure, deny-first.

Design notes
------------
* Effective roles are the *reachable set* of the tenant-local inheritance graph
  starting at the user's direct roles.  Because the graph may contain cycles we
  use an explicit worklist + visited set; recursion depth is bounded by the
  number of distinct roles, never by path length.
* Role/Rule lookups are always keyed by ``(tenant_id, ...)``.  Roles with the
  same *name* in different tenants can never alias: caches are keyed by tenant
  id and the closure query is tenant-scoped.
* The per-(user, tenant) cache is stamped with the tenant's ``authz_version``.
  Every management mutation that can change authorization increments that
  version in the same SQLite transaction, so a stale cache entry is detected
  on the very next request -- within a process and across processes.
* Permission decisions combine a *matching* rule predicate: at least one
  matching ``allow`` and zero matching ``deny``.  Default deny.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Iterable, Literal

import sqlite3

from .db import read_tx

Action = Literal["read", "write"]
Condition = Literal["any", "own", "same_department"]
Effect = Literal["allow", "deny"]

ACTIONS = ("read", "write")
CONDITIONS = ("any", "own", "same_department")
EFFECTS = ("allow", "deny")


@dataclass(frozen=True)
class Resource:
    tenant_id: int
    tenant: str
    file_id: str
    owner_user_id: int
    owner_username: str
    department: str
    version: int


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    department: str
    is_admin: bool


@dataclass(frozen=True)
class RuleRow:
    role_id: int
    effect: str
    action: str
    condition: str


@dataclass(frozen=True)
class EffectiveRoles:
    version: int
    direct_role_ids: frozenset[int]
    reachable_role_ids: frozenset[int]
    rules: tuple[RuleRow, ...]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    matched_allow: tuple[str, ...]
    matched_deny: tuple[str, ...]
    role_ids: tuple[int, ...]
    version: int

    def to_json(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "matched_allow": list(self.matched_allow),
            "matched_deny": list(self.matched_deny),
            "role_ids": list(self.role_ids),
            "version": self.version,
        }


def role_closure(
    direct_ids: Iterable[int], edges: dict[int, Iterable[int]]
) -> frozenset[int]:
    """Cycle-safe reachable closure.  Iterative; each role visited once."""
    seen: set[int] = set()
    stack: list[int] = [r for r in direct_ids if r not in seen]
    seen.update(stack)
    while stack:
        current = stack.pop()
        for parent in edges.get(current, ()):
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return frozenset(seen)


def condition_matches(condition: str, principal: Principal, resource: Resource) -> bool:
    if condition == "any":
        return True
    if condition == "own":
        return resource.owner_user_id == principal.user_id
    if condition == "same_department":
        return resource.department == principal.department
    raise ValueError(f"unknown condition: {condition}")


def evaluate_rules(
    rules: Iterable[RuleRow],
    action: Action,
    principal: Principal,
    resource: Resource,
    role_ids: frozenset[int],
) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
    """Pure decision function; deny beats allow, absence of allow denies."""
    allow_hits: list[str] = []
    deny_hits: list[str] = []
    for rule in rules:
        if rule.action != action:
            continue
        if rule.role_id not in role_ids:
            continue
        if not condition_matches(rule.condition, principal, resource):
            continue
        label = f"{rule.effect}:{rule.action}:{rule.condition}"
        if rule.effect == "deny":
            deny_hits.append(label)
        else:
            allow_hits.append(label)
    allowed = bool(allow_hits) and not deny_hits
    return allowed, tuple(sorted(allow_hits)), tuple(sorted(deny_hits))


class AuthzCache:
    """Versioned per-(user,tenant) cache.

    The cache stores the *closure* keyed by (tenant_id, user_id) and validates
    it against the tenant authz_version read from the database.  It therefore
    cannot serve data across tenants or survive a management transaction.
    """

    def __init__(self, max_entries: int = 4096) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[int, int], EffectiveRoles] = {}
        self._max = max_entries
        self.hits = 0
        self.misses = 0
        self.stale = 0

    def get(self, tenant_id: int, user_id: int, version: int) -> EffectiveRoles | None:
        with self._lock:
            entry = self._entries.get((tenant_id, user_id))
            if entry is None:
                self.misses += 1
                return None
            if entry.version != version:
                self.stale += 1
                self._entries.pop((tenant_id, user_id), None)
                return None
            self.hits += 1
            return entry

    def put(self, tenant_id: int, user_id: int, entry: EffectiveRoles) -> None:
        with self._lock:
            if len(self._entries) >= self._max:
                # simple bounded eviction: drop an arbitrary older entry
                self._entries.pop(next(iter(self._entries)), None)
            self._entries[(tenant_id, user_id)] = entry

    def invalidate_tenant(self, tenant_id: int) -> None:
        with self._lock:
            for key in [k for k in self._entries if k[0] == tenant_id]:
                self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "entries": len(self._entries),
                "hits": self.hits,
                "misses": self.misses,
                "stale": self.stale,
            }


def load_authz_version(conn: sqlite3.Connection, tenant_id: int) -> int:
    row = conn.execute(
        "SELECT authz_version FROM tenant_meta WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()
    if row is None:
        raise KeyError(f"unknown tenant id: {tenant_id}")
    return int(row["authz_version"])


def load_effective_roles(
    conn: sqlite3.Connection, tenant_id: int, user_id: int, version: int
) -> EffectiveRoles:
    direct_rows = conn.execute(
        "SELECT role_id FROM user_roles WHERE tenant_id = ? AND user_id = ?",
        (tenant_id, user_id),
    ).fetchall()
    direct = frozenset(int(r["role_id"]) for r in direct_rows)

    edge_rows = conn.execute(
        "SELECT child_id, parent_id FROM role_parents WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()
    edges: dict[int, list[int]] = {}
    for row in edge_rows:
        edges.setdefault(int(row["child_id"]), []).append(int(row["parent_id"]))
    closure = role_closure(direct, edges)

    if closure:
        placeholders = ",".join("?" for _ in closure)
        rule_rows = conn.execute(
            f"""
            SELECT role_id, effect, action, condition
              FROM rules
             WHERE tenant_id = ?
               AND role_id IN ({placeholders})
             ORDER BY role_id, effect, action, condition
            """,
            (tenant_id, *sorted(closure)),
        ).fetchall()
    else:
        rule_rows = []
    rules = tuple(
        RuleRow(
            role_id=int(r["role_id"]),
            effect=str(r["effect"]),
            action=str(r["action"]),
            condition=str(r["condition"]),
        )
        for r in rule_rows
    )
    return EffectiveRoles(
        version=version,
        direct_role_ids=direct,
        reachable_role_ids=closure,
        rules=rules,
    )


class Authorizer:
    """Combines DB reads, closure computation and the versioned cache."""

    def __init__(self, db_path: str, cache: AuthzCache | None = None) -> None:
        self.db_path = db_path
        self.cache = cache if cache is not None else AuthzCache()

    def effective_roles(
        self,
        conn: sqlite3.Connection,
        tenant_id: int,
        user_id: int,
        *,
        version: int | None = None,
    ) -> EffectiveRoles:
        if version is None:
            version = load_authz_version(conn, tenant_id)
        cached = self.cache.get(tenant_id, user_id, version)
        if cached is not None:
            return cached
        entry = load_effective_roles(conn, tenant_id, user_id, version)
        self.cache.put(tenant_id, user_id, entry)
        return entry

    def decide(
        self,
        principal: Principal,
        tenant_id: int,
        resource: Resource,
        action: Action,
        *,
        conn: sqlite3.Connection | None = None,
        effective: EffectiveRoles | None = None,
    ) -> Decision:
        if conn is None:
            # Use an explicit read transaction so all reads share one snapshot;
            # the callers in the service layer already pass their connection.
            with read_tx(self.db_path) as tx:
                return self.decide(
                    principal,
                    tenant_id,
                    resource,
                    action,
                    conn=tx,
                    effective=effective,
                )
        if effective is None:
            effective = self.effective_roles(conn, tenant_id, principal.user_id)
        allowed, allows, denies = evaluate_rules(
            effective.rules,
            action,
            principal,
            resource,
            effective.reachable_role_ids,
        )
        return Decision(
            allowed=allowed,
            matched_allow=allows,
            matched_deny=denies,
            role_ids=tuple(sorted(effective.reachable_role_ids)),
            version=effective.version,
        )

    def allows(
        self,
        principal: Principal,
        tenant_id: int,
        resource: Resource,
        action: Action,
        *,
        conn: sqlite3.Connection | None = None,
        effective: EffectiveRoles | None = None,
    ) -> bool:
        return self.decide(
            principal, tenant_id, resource, action, conn=conn, effective=effective
        ).allowed


def naive_closure(
    direct_ids: Iterable[int], edges: dict[int, list[int]]
) -> set[int]:
    """Independent reference: naive recursive DFS with a path guard.

    Provided for differential tests.  It intentionally uses recursion and
    raises on unbounded depth; the production implementation is iterative.
    """
    result: set[int] = set()

    def walk(role: int, path: frozenset[int]) -> None:
        if role in path:  # cycle guard: stop re-entering an ancestor
            result.add(role)
            return
        result.add(role)
        for parent in edges.get(role, []):
            walk(parent, path | {role})

    for role in direct_ids:
        walk(role, frozenset())
    return result
