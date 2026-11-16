"""Fixture builders used by the tests (schema only + explicit rows)."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from rbac.db import (
    add_file_raw,
    add_membership,
    add_rule_raw,
    create_role,
    create_tenant,
    create_user,
    init_database,
    set_role_parents_raw,
    set_user_roles_raw,
    write_tx,
)

TEST_PASSWORD = "TestPass1!"
TEST_ITERATIONS = 1000  # fast hashing; production preset uses 120k


def empty_db(path: str | Path) -> str:
    target = str(path)
    init_database(target, force=True, seed=False)
    return target


def build_race_fixture(path: str | Path) -> dict[str, Any]:
    """Small deterministic tenant used by the concurrency tests.

    Role graph contains a deliberate cycle child <-> parent; ``parent`` holds
    the only read permission for ``child``, so removing the inheritance edge
    must withdraw read access.
    """
    db = empty_db(path)
    ids: dict[str, Any] = {"users": {}, "roles": {}, "files": {}}
    with write_tx(db) as conn:
        race = create_tenant(conn, "race")
        ids["tenant"] = race
        for name, dept, admin in [
            ("admin", "platform", True),
            ("alice", "engineering", False),
            ("bob", "sales", False),
            ("carol", "sales", False),
        ]:
            uid = create_user(
                conn, name, TEST_PASSWORD, dept,
                is_admin=admin, iterations=TEST_ITERATIONS,
            )
            ids["users"][name] = uid
            add_membership(conn, race, uid)
        for name in ["t-admin", "child", "parent", "ownwrite", "deptwrite", "none"]:
            ids["roles"][name] = create_role(conn, race, name)
        set_role_parents_raw(conn, race, ids["roles"]["child"], [ids["roles"]["parent"]])
        set_role_parents_raw(conn, race, ids["roles"]["parent"], [ids["roles"]["child"]])
        add_rule_raw(conn, race, ids["roles"]["t-admin"], "allow", "read", "any")
        add_rule_raw(conn, race, ids["roles"]["t-admin"], "allow", "write", "any")
        add_rule_raw(conn, race, ids["roles"]["parent"], "allow", "read", "any")
        add_rule_raw(conn, race, ids["roles"]["ownwrite"], "allow", "write", "own")
        add_rule_raw(conn, race, ids["roles"]["deptwrite"], "allow", "read", "same_department")
        add_rule_raw(conn, race, ids["roles"]["deptwrite"], "allow", "write", "same_department")
        set_user_roles_raw(conn, race, ids["users"]["admin"], [ids["roles"]["t-admin"]])
        set_user_roles_raw(
            conn, race, ids["users"]["alice"],
            [ids["roles"]["child"], ids["roles"]["ownwrite"]],
        )
        set_user_roles_raw(conn, race, ids["users"]["bob"], [ids["roles"]["deptwrite"]])
        set_user_roles_raw(conn, race, ids["users"]["carol"], [ids["roles"]["deptwrite"]])
        files = [
            ("R-1", "alice", "sales"),
            ("R-2", "carol", "sales"),
            ("R-3", "bob", "sales"),
            ("R-4", "carol", "sales"),
            ("R-5", "alice", "sales"),
            ("R-6", "alice", "finance"),
            ("R-7", "carol", "finance"),
            ("R-8", "alice", "sales"),
            ("R-9", "bob", "engineering"),
            ("R-10", "carol", "engineering"),
        ]
        for file_id, owner, dept in files:
            add_file_raw(conn, race, file_id, ids["users"][owner], dept)
            ids["files"][file_id] = dept
    ids["db"] = db
    return ids


def build_random_fixture(
    path: str | Path, seed: int
) -> tuple[str, dict[str, Any]]:
    """Random multi-tenant fixture with cyclic inheritance and reused names.

    Returns ``(db_path, meta)`` where meta maps tenant name -> role names and
    user names so tests can address rows without querying blindly.
    """
    rng = random.Random(seed)
    db = empty_db(path)
    tenant_names = ["alpha", "beta"]
    role_names = [f"r{i}" for i in range(6)]  # identical names in both tenants
    user_names = [f"u{i}" for i in range(8)]
    departments = ["eng", "sales", "ops"]
    meta: dict[str, Any] = {
        "tenants": tenant_names,
        "roles": role_names,
        "users": user_names,
        "departments": {},
        "memberships": {},
    }
    with write_tx(db) as conn:
        tenant_ids: dict[str, int] = {
            name: create_tenant(conn, name) for name in tenant_names
        }
        user_ids: dict[str, int] = {}
        for name in user_names:
            dept = rng.choice(departments)
            meta["departments"][name] = dept
            user_ids[name] = create_user(
                conn, name, TEST_PASSWORD, dept, iterations=TEST_ITERATIONS
            )
        role_ids: dict[tuple[str, str], int] = {}
        for tenant in tenant_names:
            for role in role_names:
                role_ids[(tenant, role)] = create_role(conn, tenant_ids[tenant], role)

        for tenant in tenant_names:
            meta["memberships"][tenant] = []
            for user in user_names:
                if rng.random() < 0.75:
                    add_membership(conn, tenant_ids[tenant], user_ids[user])
                    meta["memberships"][tenant].append(user)

        for tenant in tenant_names:
            for role in role_names:
                # random parent set; self-loop and longer cycles are allowed
                parents = [
                    p for p in role_names if rng.random() < 0.22
                ]
                set_role_parents_raw(
                    conn,
                    tenant_ids[tenant],
                    role_ids[(tenant, role)],
                    [role_ids[(tenant, p)] for p in parents],
                )
                combos = [
                    (effect, action, condition)
                    for effect in ("allow", "deny")
                    for action in ("read", "write")
                    for condition in ("any", "own", "same_department")
                ]
                rng.shuffle(combos)
                keep = combos[: rng.randint(0, 4)]
                for effect, action, condition in keep:
                    add_rule_raw(
                        conn,
                        tenant_ids[tenant],
                        role_ids[(tenant, role)],
                        effect,
                        action,
                        condition,
                    )

        for tenant in tenant_names:
            members = meta["memberships"][tenant]
            if not members:
                add_membership(conn, tenant_ids[tenant], user_ids[user_names[0]])
                members.append(user_names[0])
            for user in user_names:
                if user not in members:
                    continue
                assigned = [r for r in role_names if rng.random() < 0.45]
                set_user_roles_raw(
                    conn,
                    tenant_ids[tenant],
                    user_ids[user],
                    [role_ids[(tenant, r)] for r in assigned],
                )
            for i in range(14):
                owner = rng.choice(members)
                dept = rng.choice(departments)
                add_file_raw(
                    conn,
                    tenant_ids[tenant],
                    f"{tenant[0].upper()}-{i:03d}",
                    user_ids[owner],
                    dept,
                )
    return db, meta
