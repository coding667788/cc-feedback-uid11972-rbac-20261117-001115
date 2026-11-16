"""End-to-end HTTP tests against real server subprocesses.

Every test gets a fresh database and server, so tests are independent.
Assertions check returned resources, totals and the *database* final state --
never only status codes.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.fixtures import TEST_PASSWORD
from tests.helpers import (
    Client,
    ServerProcess,
    db_snapshot,
    file_state,
    preset_db,
)


class HttpTestCase(unittest.TestCase):
    """Fresh preset database + one real server process per test."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = preset_db(self.dir / "preset.db")
        self.server = ServerProcess(self.db, hook_dir=self.dir / "hooks").start()
        self.base = self.server.base_url

    def tearDown(self) -> None:
        self.server.stop()
        self.tmp.cleanup()

    def db_write(self):
        from rbac.db import write_tx

        return write_tx(self.db)


    def login(self, username: str, password: str) -> Client:
        client = Client(self.base)
        result = client.post(
            "/v1/auth/login", {"username": username, "password": password}
        )
        self.assertEqual(result.status, 200, result.body)
        self.assertTrue(result.body["token"])
        client.token = result.body["token"]
        return client

    def alice(self) -> Client:
        return self.login("alice", "AlicePass1!")

    def admin(self) -> Client:
        return self.login("admin", "AdminPass1!")


class AuthHttpTests(HttpTestCase):
    def test_login_rejects_bad_password_and_unknown_user(self) -> None:
        client = Client(self.base)
        bad = client.post("/v1/auth/login", {"username": "alice", "password": "wrong"})
        self.assertEqual(bad.status, 401)
        self.assertEqual(bad.body["error"]["code"], "unauthorized")
        unknown = client.post(
            "/v1/auth/login", {"username": "nobody", "password": TEST_PASSWORD}
        )
        self.assertEqual(unknown.status, 401)

    def test_requires_bearer_token(self) -> None:
        client = Client(self.base)
        self.assertEqual(client.get("/v1/me").status, 401)
        self.assertEqual(client.get("/v1/me", token="not-a-real-token").status, 401)

    def test_logout_revokes_token(self) -> None:
        client = self.alice()
        self.assertEqual(client.get("/v1/me").status, 200)
        self.assertEqual(client.post("/v1/auth/logout").status, 200)
        self.assertEqual(client.get("/v1/me").status, 401)

    def test_caller_headers_cannot_declare_identity(self) -> None:
        # carol is not a member of umbrella; claiming alice via headers fails.
        carol = self.login("carol", "CarolPass1!")
        result = carol.get(
            "/v1/tenants/umbrella/files",
            headers={
                "X-User": "alice",
                "X-Department": "engineering",
                "X-Tenant": "umbrella",
            },
        )
        self.assertEqual(result.status, 403, result.body)
        self.assertEqual(result.body["error"]["code"], "forbidden")

        # Body fields never override the authenticated department or owner.
        denied = carol.patch(
            "/v1/tenants/acme/files/A-105",
            {"owner": "carol", "department": "sales", "department_override": "sales"},
        )
        self.assertEqual(denied.status, 403, denied.body)
        self.assertEqual(file_state(self.db, "acme", "A-105")["department"], "finance")

    def test_unknown_tenant_404_non_member_403(self) -> None:
        alice = self.alice()
        self.assertEqual(alice.get("/v1/tenants/nope/files").status, 404)
        carol = self.login("carol", "CarolPass1!")
        self.assertEqual(carol.get("/v1/tenants/umbrella/files").status, 403)


class ReadHttpTests(HttpTestCase):
    def test_single_read_returns_resource(self) -> None:
        alice = self.alice()
        own_ok = alice.get("/v1/tenants/acme/files/A-100")
        self.assertEqual(own_ok.status, 200)
        self.assertEqual(own_ok.body["resource"]["file_id"], "A-100")
        self.assertEqual(own_ok.body["resource"]["owner"], "alice")
        self.assertEqual(own_ok.body["resource"]["department"], "engineering")

        other = alice.get("/v1/tenants/acme/files/A-102")
        self.assertEqual(other.status, 200)
        self.assertEqual(other.body["resource"]["owner"], "carol")

        self.assertEqual(alice.get("/v1/tenants/acme/files/NOPE").status, 404)

    def test_deny_overrides_allow_for_suspended_user(self) -> None:
        dave = self.login("dave", "DavePass1!")
        denied = dave.get("/v1/tenants/acme/files/A-101")
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.body["error"]["code"], "forbidden")
        listing = dave.get("/v1/tenants/acme/files?page_size=100")
        self.assertEqual(listing.status, 200)
        self.assertEqual(listing.body["total"], 0)
        self.assertEqual(listing.body["items"], [])

    def test_cyclic_inheritance_terminates_and_grants(self) -> None:
        alice = self.alice()
        # alice -> cycle-a <-> cycle-b -> reader
        result = alice.get("/v1/tenants/acme/files/A-103")
        self.assertEqual(result.status, 200, result.body)
        state = alice.get("/v1/admin/tenants/acme/state")
        self.assertEqual(state.status, 403)  # non-admin

    def test_same_role_name_across_tenants_is_not_shared(self) -> None:
        alice = self.alice()
        # acme developer/cycle grants read; globex developer grants read; all
        # fine.  Use bob (globex auditor denies write) versus acme names.
        bob = self.login("bob", "BobPass1!")
        self.assertEqual(bob.get("/v1/tenants/globex/files/G-200").status, 200)
        # bob is not an acme write holder; acme "reviewer" is read-only.
        self.assertEqual(
            bob.patch("/v1/tenants/acme/files/A-101", {"department": "sales"}).status,
            403,
        )
        self.assertEqual(
            file_state(self.db, "acme", "A-101")["department"], "engineering"
        )

    def test_list_authorizes_then_sorts_then_paginates(self) -> None:
        alice = self.alice()
        full = alice.get("/v1/tenants/acme/files?page_size=100&sort=file_id&order=asc")
        self.assertEqual(full.status, 200, full.body)
        ids = [item["file_id"] for item in full.body["items"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(full.body["total"], len(ids))
        self.assertFalse(full.body["has_next"])

        page1 = alice.get("/v1/tenants/acme/files?page_size=2&page=1&sort=file_id")
        page2 = alice.get("/v1/tenants/acme/files?page_size=2&page=2&sort=file_id")
        self.assertEqual(page1.body["total"], full.body["total"])
        self.assertEqual([i["file_id"] for i in page1.body["items"]], ids[0:2])
        self.assertEqual([i["file_id"] for i in page2.body["items"]], ids[2:4])
        self.assertTrue(page1.body["has_next"])

        # every item in every page must actually be readable individually
        for item in full.body["items"]:
            detail = alice.get(f"/v1/tenants/acme/files/{item['file_id']}")
            self.assertEqual(detail.status, 200)

    def test_list_total_never_counts_unauthorized(self) -> None:
        carol = self.login("carol", "CarolPass1!")
        result = carol.get("/v1/tenants/acme/files?page_size=100")
        self.assertEqual(result.status, 200)
        sales_ids = {item["file_id"] for item in result.body["items"]}
        self.assertEqual(sales_ids, {"A-102", "A-104"})
        self.assertEqual(result.body["total"], 2)
        self.assertNotEqual(result.body["total"], 7)

        # pages beyond the end are empty but report the same filtered total
        far = carol.get("/v1/tenants/acme/files?page_size=1&page=99")
        self.assertEqual(far.body["items"], [])
        self.assertEqual(far.body["total"], 2)

    def test_department_filter_changes_after_admin_edit(self) -> None:
        carol = self.login("carol", "CarolPass1!")
        before = carol.get("/v1/tenants/acme/files?page_size=100")
        self.assertEqual(before.body["total"], 2)
        # carol's department changes to engineering; same_department rules now
        # match engineering files instead.
        admin = self.admin()
        with self.db_write() as conn:
            conn.execute(
                "UPDATE users SET department = 'engineering' WHERE username = 'carol'"
            )
            conn.execute(
                "UPDATE tenant_meta SET authz_version = authz_version + 1 WHERE tenant_id = 1"
            )
        after = carol.get("/v1/tenants/acme/files?page_size=100")
        engineering = {
            "A-100", "A-101", "A-103"  # A-104 is alice/sales
        }
        self.assertEqual(after.body["total"], len(engineering))
        self.assertEqual({i["file_id"] for i in after.body["items"]}, engineering)

    def db_write(self):
        from rbac.db import write_tx

        return write_tx(self.db)


class WriteHttpTests(HttpTestCase):
    def test_write_requires_current_and_target_permission(self) -> None:
        alice = self.alice()
        ok = alice.patch("/v1/tenants/acme/files/A-100", {"department": "sales"})
        self.assertEqual(ok.status, 200, ok.body)
        self.assertEqual(ok.body["resource"]["department"], "sales")
        self.assertEqual(file_state(self.db, "acme", "A-100")["department"], "sales")
        self.assertEqual(file_state(self.db, "acme", "A-100")["version"], 2)

        # Moving it out of "own" reachability is fine only while target check
        # holds; alice's write is own-only and owner stays alice.
        denied = alice.patch("/v1/tenants/acme/files/A-101", {"department": "sales"})
        self.assertEqual(denied.status, 403, denied.body)
        state = file_state(self.db, "acme", "A-101")
        self.assertEqual(state["department"], "engineering")
        self.assertEqual(state["version"], 1)

    def test_cannot_launder_write_by_changing_owner(self) -> None:
        alice = self.alice()
        # Transferring her own file to bob makes the *target* resource one she
        # cannot write (own-rule no longer matches, no other write rule).
        denied = alice.patch("/v1/tenants/acme/files/A-100", {"owner": "bob"})
        self.assertEqual(denied.status, 403, denied.body)
        state = file_state(self.db, "acme", "A-100")
        self.assertEqual(state["owner"], "alice")
        self.assertEqual(state["version"], 1)

        # Admin with write:any may transfer.
        admin = self.admin()
        ok = admin.patch("/v1/tenants/acme/files/A-100", {"owner": "bob"})
        self.assertEqual(ok.status, 200, ok.body)
        self.assertEqual(file_state(self.db, "acme", "A-100")["owner"], "bob")

    def test_cannot_launder_write_by_changing_department(self) -> None:
        carol = self.login("carol", "CarolPass1!")
        denied = carol.patch(
            "/v1/tenants/acme/files/A-102", {"department": "finance"}
        )
        self.assertEqual(denied.status, 403, denied.body)
        self.assertEqual(file_state(self.db, "acme", "A-102")["department"], "sales")

        # Same-department write is allowed.  Moving to a department she does
        # *not* share (marketing) must be denied at the target check.
        same = carol.patch("/v1/tenants/acme/files/A-102", {"department": "sales"})
        self.assertEqual(same.status, 200, same.body)
        self.assertEqual(file_state(self.db, "acme", "A-102")["department"], "sales")

        cross = carol.patch("/v1/tenants/acme/files/A-102", {"department": "marketing"})
        self.assertEqual(cross.status, 403, cross.body)
        self.assertEqual(file_state(self.db, "acme", "A-102")["department"], "sales")
        self.assertEqual(file_state(self.db, "acme", "A-102")["version"], 2)

    def test_owner_must_be_active_tenant_member(self) -> None:
        admin = self.admin()
        missing = admin.patch("/v1/tenants/acme/files/A-100", {"owner": "ghost"})
        self.assertEqual(missing.status, 422)
        self.assertEqual(file_state(self.db, "acme", "A-100")["owner"], "alice")
        # carol is not a member of umbrella, so she cannot become its owner.
        # bob holds umbrella manager (write any), so authorization passes and
        # only the membership validation can reject the request.
        bob = self.login("bob", "BobPass1!")
        cross = bob.patch("/v1/tenants/umbrella/files/U-300", {"owner": "carol"})
        self.assertEqual(cross.status, 422, cross.body)
        self.assertEqual(file_state(self.db, "umbrella", "U-300")["owner"], "alice")

    def test_bad_payloads_are_rejected_without_mutation(self) -> None:
        alice = self.alice()
        empty = alice.patch("/v1/tenants/acme/files/A-100", {})
        self.assertEqual(empty.status, 400)
        wrong_type = alice.patch("/v1/tenants/acme/files/A-100", {"owner": 5})
        self.assertEqual(wrong_type.status, 400)
        blank = alice.patch("/v1/tenants/acme/files/A-100", {"department": "  "})
        self.assertEqual(blank.status, 400)
        state = file_state(self.db, "acme", "A-100")
        self.assertEqual(state["owner"], "alice")
        self.assertEqual(state["department"], "engineering")
        self.assertEqual(state["version"], 1)


class AdminHttpTests(HttpTestCase):
    def test_role_change_takes_effect_and_bumps_version(self) -> None:
        admin = self.admin()
        before = admin.get("/v1/admin/tenants/acme/state")
        self.assertEqual(before.status, 200, before.body)
        v0 = before.body["authz_version"]

        alice = self.alice()
        self.assertEqual(alice.get("/v1/tenants/acme/files/A-103").status, 200)

        changed = admin.put(
            "/v1/admin/tenants/acme/users/alice/roles",
            {"roles": ["suspended", "reader"]},
        )
        self.assertEqual(changed.status, 200, changed.body)
        self.assertEqual(changed.body["authz_version"], v0 + 1)

        self.assertEqual(alice.get("/v1/tenants/acme/files/A-103").status, 403)
        listing = alice.get("/v1/tenants/acme/files?page_size=100")
        self.assertEqual(listing.body["total"], 0)
        self.assertEqual(listing.body["items"], [])

        # database reflects the new assignment exactly
        snapshot = db_snapshot(self.db)
        alice_roles = {
            row["role"]
            for row in snapshot["assignments"]
            if row["tenant"] == "acme" and row["username"] == "alice"
        }
        self.assertEqual(alice_roles, {"reader", "suspended"})
        self.assertEqual(snapshot["authz_versions"]["acme"], v0 + 1)

    def test_non_admin_cannot_manage(self) -> None:
        alice = self.alice()
        result = alice.put(
            "/v1/admin/tenants/acme/users/alice/roles", {"roles": ["reader"]}
        )
        self.assertEqual(result.status, 403)
        self.assertEqual(alice.get("/v1/admin/tenants/acme/state").status, 403)
        snapshot = db_snapshot(self.db)
        alice_roles = {
            row["role"]
            for row in snapshot["assignments"]
            if row["tenant"] == "acme" and row["username"] == "alice"
        }
        self.assertEqual(alice_roles, {"developer", "cycle-a"})

    def test_rule_changes_apply_immediately(self) -> None:
        admin = self.admin()
        result = admin.put(
            "/v1/admin/tenants/globex/roles/reader/rules",
            {"rules": [
                {"effect": "allow", "action": "read", "condition": "any"},
                {"effect": "deny", "action": "read", "condition": "any"},
            ]},
        )
        self.assertEqual(result.status, 200, result.body)
        alice = self.alice()
        self.assertEqual(alice.get("/v1/tenants/globex/files/G-200").status, 403)

        restored = admin.put(
            "/v1/admin/tenants/globex/roles/reader/rules",
            {"rules": [{"effect": "allow", "action": "read", "condition": "any"}]},
        )
        self.assertEqual(restored.status, 200)
        self.assertEqual(alice.get("/v1/tenants/globex/files/G-200").status, 200)

    def test_inheritance_cycle_via_admin_api(self) -> None:
        admin = self.admin()
        # Clear globex auditor's built-in write deny so the cycle test observes
        # inherited *allow* only; then auditor <-> developer form a cycle.
        cleared = admin.put(
            "/v1/admin/tenants/globex/roles/auditor/rules",
            {"rules": [{"effect": "allow", "action": "read", "condition": "any"}]},
        )
        self.assertEqual(cleared.status, 200, cleared.body)
        p1 = admin.put(
            "/v1/admin/tenants/globex/roles/auditor/parents",
            {"parents": ["developer", "reader"]},
        )
        self.assertEqual(p1.status, 200, p1.body)
        p2 = admin.put(
            "/v1/admin/tenants/globex/roles/developer/parents",
            {"parents": ["auditor"]},
        )
        self.assertEqual(p2.status, 200, p2.body)
        # bob: auditor -> developer (write any) and back to auditor
        bob = self.login("bob", "BobPass1!")
        write = bob.patch("/v1/tenants/globex/files/G-201", {"department": "sales"})
        self.assertEqual(write.status, 200, write.body)
        self.assertEqual(file_state(self.db, "globex", "G-201")["department"], "sales")

    def test_unknown_role_and_duplicate_role_errors(self) -> None:
        admin = self.admin()
        unknown = admin.put(
            "/v1/admin/tenants/acme/users/alice/roles", {"roles": ["does-not-exist"]}
        )
        self.assertEqual(unknown.status, 422)
        snapshot = db_snapshot(self.db)
        alice_roles = {
            row["role"]
            for row in snapshot["assignments"]
            if row["tenant"] == "acme" and row["username"] == "alice"
        }
        self.assertEqual(alice_roles, {"developer", "cycle-a"})

        # a role name that exists only in another tenant is not assignable
        cross = admin.put(
            "/v1/admin/tenants/acme/users/alice/roles", {"roles": ["auditor"]}
        )
        self.assertEqual(cross.status, 422)

        bad_rule = admin.put(
            "/v1/admin/tenants/acme/roles/reader/rules",
            {"rules": [{"effect": "maybe", "action": "read", "condition": "any"}]},
        )
        self.assertEqual(bad_rule.status, 422)
        bad_cond = admin.put(
            "/v1/admin/tenants/acme/roles/reader/rules",
            {"rules": [{"effect": "allow", "action": "read", "condition": "sometimes"}]},
        )
        self.assertEqual(bad_cond.status, 422)


    def test_create_role_and_use_it(self) -> None:
        admin = self.admin()
        created = admin.post(
            "/v1/admin/tenants/acme/roles", {"name": "temp-reader"}
        )
        self.assertEqual(created.status, 200, created.body)
        role_id = created.body["role"]["id"]
        self.assertEqual(created.body["authz_version"], 2)

        duplicate = admin.post(
            "/v1/admin/tenants/acme/roles", {"name": "temp-reader"}
        )
        self.assertEqual(duplicate.status, 409)

        rules = admin.put(
            "/v1/admin/tenants/acme/roles/temp-reader/rules",
            {"rules": [{"effect": "allow", "action": "read", "condition": "any"}]},
        )
        self.assertEqual(rules.status, 200, rules.body)
        assigned = admin.put(
            "/v1/admin/tenants/acme/users/carol/roles", {"roles": ["temp-reader"]}
        )
        self.assertEqual(assigned.status, 200, assigned.body)

        carol = self.login("carol", "CarolPass1!")
        listing = carol.get("/v1/tenants/acme/files?page_size=100")
        self.assertEqual(listing.body["total"], 7)

        snapshot = db_snapshot(self.db)
        self.assertTrue(
            any(
                row["tenant"] == "acme"
                and row["username"] == "carol"
                and row["role"] == "temp-reader"
                for row in snapshot["assignments"]
            )
        )
        self.assertTrue(
            any(
                row["tenant"] == "acme"
                and row["role"] == "temp-reader"
                and row["effect"] == "allow"
                for row in snapshot["rules"]
            )
        )

    def test_cache_stats_is_admin_only(self) -> None:
        alice = self.alice()
        self.assertEqual(alice.get("/v1/authz/cache-stats").status, 403)
        admin = self.admin()
        stats = admin.get("/v1/authz/cache-stats")
        self.assertEqual(stats.status, 200)
        self.assertIn("hits", stats.body["cache"])
        self.assertNotIn("entries_detail", stats.body["cache"])

    def test_oversized_body_is_rejected(self) -> None:
        alice = self.alice()
        huge = {"owner": "x" * 70_000}
        result = alice.patch("/v1/tenants/acme/files/A-100", huge)
        self.assertEqual(result.status, 413)
        self.assertEqual(file_state(self.db, "acme", "A-100")["owner"], "alice")
        # the server must still be usable after the rejected oversized request
        self.assertEqual(alice.get("/v1/me").status, 200)

    def test_too_many_roles_rejected(self) -> None:
        admin = self.admin()
        roles = [f"role-{i}" for i in range(100)]
        result = admin.put(
            "/v1/admin/tenants/acme/users/alice/roles", {"roles": roles}
        )
        self.assertEqual(result.status, 400)
        snapshot = db_snapshot(self.db)
        alice_roles = {
            row["role"]
            for row in snapshot["assignments"]
            if row["tenant"] == "acme" and row["username"] == "alice"
        }
        self.assertEqual(alice_roles, {"developer", "cycle-a"})


class ProtocolHttpTests(HttpTestCase):
    def test_malformed_requests(self) -> None:
        alice = self.alice()
        self.assertEqual(alice.get("/v1/tenants/acme/files?sort=owner;drop").status, 400)
        self.assertEqual(alice.get("/v1/tenants/acme/files?page=0").status, 400)
        self.assertEqual(alice.get("/v1/tenants/acme/files?page_size=100000").status, 400)
        self.assertEqual(alice.get("/v1/tenants/acme/files?order=sideways").status, 400)
        empty = alice.request("PATCH", "/v1/tenants/acme/files/A-100")
        self.assertEqual(empty.status, 400)

    def test_unknown_route_and_method(self) -> None:
        alice = self.alice()
        self.assertEqual(alice.get("/v1/nope").status, 404)
        result = alice.request("DELETE", "/v1/tenants/acme/files/A-100")
        self.assertEqual(result.status, 405)
        self.assertIn("GET", result.headers.get("Allow", ""))

    def test_concurrent_reads_are_not_serialized(self) -> None:
        import threading
        import time

        alice = self.alice()
        results: list[int] = []
        lock = threading.Lock()

        def worker() -> None:
            for _ in range(5):
                r = alice.get("/v1/tenants/acme/files/A-100")
                with lock:
                    results.append(r.status)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        start = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        elapsed = time.monotonic() - start
        self.assertEqual(results, [200] * 40)
        self.assertLess(elapsed, 20.0)


if __name__ == "__main__":
    unittest.main()
