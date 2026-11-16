"""Unit and differential tests for the authorization core."""

from __future__ import annotations

import random
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rbac.authz import (
    AuthzCache,
    Authorizer,
    Principal,
    Resource,
    evaluate_rules,
    load_authz_version,
    naive_closure,
    role_closure,
    RuleRow,
)
from rbac.db import (
    add_file_raw,
    add_membership,
    add_rule_raw,
    bump_version,
    connect,
    create_role,
    create_tenant,
    create_user,
    init_database,
    read_tx,
    set_role_parents_raw,
    set_user_roles_raw,
    write_tx,
)

from tests.fixtures import TEST_ITERATIONS, TEST_PASSWORD, build_race_fixture, empty_db


class ClosureTests(unittest.TestCase):
    def test_self_loop_and_two_cycle_terminate(self) -> None:
        edges = {1: [1], 2: [3], 3: [2], 4: [2, 4]}
        self.assertEqual(role_closure([1], edges), frozenset({1}))
        self.assertEqual(role_closure([2], edges), frozenset({2, 3}))
        self.assertEqual(role_closure([4], edges), frozenset({4, 2, 3}))

    def test_long_cycle_terminates(self) -> None:
        n = 5000
        edges = {i: [(i + 1) % n] for i in range(n)}
        result = role_closure([0], edges)
        self.assertEqual(len(result), n)

    def test_naive_and_iterative_agree_on_random_graphs(self) -> None:
        rng = random.Random(1234)
        for trial in range(300):
            n = rng.randint(1, 12)
            edges = {
                node: [other for other in range(n) if rng.random() < 0.25]
                for node in range(n)
            }
            direct = [node for node in range(n) if rng.random() < 0.4]
            iterative = role_closure(direct, edges)
            reference = naive_closure(direct, edges)
            self.assertEqual(
                set(iterative),
                set(reference),
                msg=f"trial={trial} direct={direct} edges={edges}",
            )

    def test_disconnected_roles_are_not_reachable(self) -> None:
        edges = {1: [2], 2: [1], 3: [4], 4: [3]}
        self.assertEqual(role_closure([1], edges), frozenset({1, 2}))
        self.assertNotIn(3, role_closure([1], edges))


class DenyPriorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.principal = Principal(1, "alice", "eng", False)
        self.resource = Resource(1, "t", "F-1", 1, "alice", "eng", 1)

    def test_allow_only(self) -> None:
        rules = [RuleRow(5, "allow", "read", "any")]
        allowed, allows, denies = evaluate_rules(
            rules, "read", self.principal, self.resource, frozenset({5})
        )
        self.assertTrue(allowed)
        self.assertEqual(denies, ())

    def test_deny_overrides_allow(self) -> None:
        rules = [
            RuleRow(5, "allow", "read", "any"),
            RuleRow(6, "deny", "read", "any"),
        ]
        allowed, _, denies = evaluate_rules(
            rules, "read", self.principal, self.resource, frozenset({5, 6})
        )
        self.assertFalse(allowed)
        self.assertTrue(denies)

    def test_no_rule_defaults_to_deny(self) -> None:
        allowed, allows, denies = evaluate_rules(
            [], "read", self.principal, self.resource, frozenset()
        )
        self.assertFalse(allowed)
        self.assertEqual(allows, ())

    def test_condition_own_and_department(self) -> None:
        other = Resource(1, "t", "F-2", 2, "bob", "sales", 1)
        rules = [RuleRow(7, "allow", "write", "own")]
        self.assertTrue(
            evaluate_rules(rules, "write", self.principal, self.resource, frozenset({7}))[0]
        )
        self.assertFalse(
            evaluate_rules(rules, "write", self.principal, other, frozenset({7}))[0]
        )
        dept_rules = [RuleRow(8, "allow", "read", "same_department")]
        self.assertTrue(
            evaluate_rules(dept_rules, "read", self.principal, self.resource, frozenset({8}))[0]
        )
        self.assertFalse(
            evaluate_rules(dept_rules, "read", self.principal, other, frozenset({8}))[0]
        )

    def test_rule_of_non_effective_role_is_ignored(self) -> None:
        rules = [RuleRow(99, "allow", "read", "any")]
        allowed, _, _ = evaluate_rules(
            rules, "read", self.principal, self.resource, frozenset({5})
        )
        self.assertFalse(allowed)

    def test_action_isolation(self) -> None:
        rules = [RuleRow(5, "allow", "write", "any")]
        self.assertFalse(
            evaluate_rules(rules, "read", self.principal, self.resource, frozenset({5}))[0]
        )


class AuthorizerDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "unit.db")
        empty_db(self.db)
        with write_tx(self.db) as conn:
            self.ta = create_tenant(conn, "alpha")
            self.tb = create_tenant(conn, "beta")
            self.ua = create_user(conn, "alice", TEST_PASSWORD, "eng", iterations=TEST_ITERATIONS)
            add_membership(conn, self.ta, self.ua)
            add_membership(conn, self.tb, self.ua)
            # same role name in both tenants, different powers
            self.role_a = create_role(conn, self.ta, "reader")
            self.role_b = create_role(conn, self.tb, "reader")
            add_rule_raw(conn, self.ta, self.role_a, "allow", "read", "any")
            add_rule_raw(conn, self.tb, self.role_b, "deny", "read", "any")
            set_user_roles_raw(conn, self.ta, self.ua, [self.role_a])
            set_user_roles_raw(conn, self.tb, self.ua, [self.role_b])
            add_file_raw(conn, self.ta, "F-1", self.ua, "eng")
            add_file_raw(conn, self.tb, "F-1", self.ua, "eng")
        self.principal = Principal(self.ua, "alice", "eng", False)
        self.authorizer = Authorizer(self.db)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _resource(self, tenant_id: int) -> Resource:
        return Resource(tenant_id, "x", "F-1", self.ua, "alice", "eng", 1)

    def test_same_role_name_does_not_alias_across_tenants(self) -> None:
        self.assertTrue(
            self.authorizer.allows(self.principal, self.ta, self._resource(self.ta), "read")
        )
        self.assertFalse(
            self.authorizer.allows(self.principal, self.tb, self._resource(self.tb), "read")
        )

    def test_cache_is_keyed_by_tenant_and_version(self) -> None:
        cache = self.authorizer.cache
        self.assertTrue(
            self.authorizer.allows(self.principal, self.ta, self._resource(self.ta), "read")
        )
        self.assertFalse(
            self.authorizer.allows(self.principal, self.tb, self._resource(self.tb), "read")
        )
        stats = cache.stats()
        self.assertGreaterEqual(stats["entries"], 2)

        # revoke in alpha by bumping the version in a management transaction
        with write_tx(self.db) as conn:
            set_user_roles_raw(conn, self.ta, self.ua, [])
            bump_version(conn, self.ta)
        self.assertFalse(
            self.authorizer.allows(self.principal, self.ta, self._resource(self.ta), "read")
        )
        # beta cache entry is untouched and still denies
        self.assertFalse(
            self.authorizer.allows(self.principal, self.tb, self._resource(self.tb), "read")
        )

    def test_inheritance_cycle_via_database(self) -> None:
        with write_tx(self.db) as conn:
            role_x = create_role(conn, self.ta, "x")
            role_y = create_role(conn, self.ta, "y")
            set_role_parents_raw(conn, self.ta, role_x, [role_y])
            set_role_parents_raw(conn, self.ta, role_y, [role_x])
            set_user_roles_raw(conn, self.ta, self.ua, [role_x])
            add_rule_raw(conn, self.ta, role_y, "allow", "write", "any")
            bump_version(conn, self.ta)
        decision = self.authorizer.decide(
            self.principal, self.ta, self._resource(self.ta), "write"
        )
        self.assertTrue(decision.allowed, decision)
        self.assertEqual(len(decision.role_ids), 2)
        # read is still granted by the untouched "reader" direct role? no:
        # assignment was replaced, and x/y grant only write.
        read_decision = self.authorizer.decide(
            self.principal, self.ta, self._resource(self.ta), "read"
        )
        self.assertFalse(read_decision.allowed)

    def test_cycle_depth_is_bounded_not_recursive(self) -> None:
        # A 4000-role cycle must not RecursionError in the production engine.
        with write_tx(self.db) as conn:
            role_ids = [create_role(conn, self.ta, f"c{i}") for i in range(4000)]
            for i, rid in enumerate(role_ids):
                set_role_parents_raw(conn, self.ta, rid, [role_ids[(i + 1) % 4000]])
            set_user_roles_raw(conn, self.ta, self.ua, [role_ids[0]])
            bump_version(conn, self.ta)
        decision = self.authorizer.decide(
            self.principal, self.ta, self._resource(self.ta), "read"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(len(decision.role_ids), 4000)


class CacheEvictionTests(unittest.TestCase):
    def test_bounded_cache(self) -> None:
        cache = AuthzCache(max_entries=2)
        from rbac.authz import EffectiveRoles

        entry = EffectiveRoles(1, frozenset(), frozenset(), ())
        cache.put(1, 1, entry)
        cache.put(1, 2, entry)
        cache.put(1, 3, entry)
        self.assertEqual(cache.stats()["entries"], 2)

    def test_stale_entries_counted(self) -> None:
        cache = AuthzCache()
        from rbac.authz import EffectiveRoles

        cache.put(1, 1, EffectiveRoles(1, frozenset(), frozenset(), ()))
        self.assertIsNone(cache.get(1, 1, 2))
        self.assertEqual(cache.stats()["stale"], 1)


if __name__ == "__main__":
    unittest.main()
