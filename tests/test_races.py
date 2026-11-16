"""Multi-process concurrency and revocation races.

Four independent ``python -m rbac serve`` processes share one SQLite database.
Filesystem test hooks create deterministic interleavings inside a chosen
server process; the other processes keep serving normally.

Scenarios
--------
1. Warm caches on all processes, then revoke an inheritance edge: every later
   request, on every process, must observe the revocation.
2. Authorization-then-blocked write: the request pauses after phase-1 authz;
   an admin revokes write; the paused write must revalidate against fresh state
   and be rejected without touching the database.
3. Resource attribute interleaving: another writer moves the target out of the
   paused writer's reach; the paused write must fail and not clobber the change.
4. Reads are not blocked while a writer holds SQLite's writer slot, and all
   four processes serve reads concurrently.
5. List snapshot consistency: a paused list is internally consistent; requests
   started after revocation see the new state.
6. Parallel admin revocations from four processes only ever increase versions.
"""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from rbac.db import bump_version, write_tx
from tests.fixtures import build_race_fixture
from tests.helpers import (
    Client,
    HookDir,
    ServerProcess,
    db_snapshot,
    file_state,
)

TEST_PASSWORD = "TestPass1!"


class RaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    # ------------------------------------------------------------- utilities

    def make_group(self, name: str, count: int = 4):
        ids = build_race_fixture(self.root / name / "race.db")
        db = ids["db"]
        hooks = HookDir(self.root / name / "hooks")
        servers = [
            ServerProcess(
                db,
                hook_dir=hooks.path,
                env_extra={"RBAC_TEST_HOOK_TIMEOUT": "20"},
            ).start()
            for _ in range(count)
        ]
        for server in servers:
            self.addCleanup(server.stop)
        tokens = {}
        for username in ("admin", "alice", "bob", "carol"):
            login = Client(servers[0].base_url).post(
                "/v1/auth/login",
                {"username": username, "password": TEST_PASSWORD},
            )
            self.assertEqual(login.status, 200, login.body)
            tokens[username] = login.body["token"]
        return db, hooks, servers, tokens

    @staticmethod
    def client(server: ServerProcess, token: str) -> Client:
        return Client(server.base_url, token=token)

    # ----------------------------------------------------------------- tests

    def test_revocation_waits_for_inflight_write_then_applies(self) -> None:
        """A revocation cannot overtake a write that already holds the slot."""
        db, hooks, servers, tokens = self.make_group("revoke-during-write")
        writer = self.client(servers[0], tokens["bob"])
        outcome: dict[str, object] = {}
        revoke_outcome: dict[str, object] = {}

        def do_patch() -> None:
            outcome["result"] = writer.patch(
                "/v1/tenants/race/files/R-2",
                {"department": "sales"},
                headers={"X-Test-Sync": "w4:after_write_begin"},
            )

        def do_revoke() -> None:
            admin = self.client(servers[1], tokens["admin"])
            revoke_outcome["result"] = admin.put(
                "/v1/admin/tenants/race/users/bob/roles", {"roles": []}
            )

        thread = threading.Thread(target=do_patch)
        thread.start()
        hooks.wait_paused("w4", "after_write_begin", timeout=20)
        # The writer is holding BEGIN IMMEDIATE.  A revocation must block on
        # SQLite's writer slot rather than sneaking in between authz and write.
        revoke_thread = threading.Thread(target=do_revoke)
        revoke_thread.start()
        time.sleep(0.5)
        self.assertTrue(
            revoke_thread.is_alive(),
            "revocation overtook a write that already held the writer slot",
        )
        self.assertEqual(file_state(db, "race", "R-2")["version"], 1)

        hooks.release("w4", "after_write_begin")
        thread.join(timeout=30)
        revoke_thread.join(timeout=30)
        result = outcome.get("result")
        self.assertEqual(result.status, 200, result.body)
        self.assertEqual(file_state(db, "race", "R-2")["version"], 2)
        revoked = revoke_outcome.get("result")
        self.assertEqual(revoked.status, 200, revoked.body)
        # After the revocation returns, bob can no longer write.
        denied = writer.patch(
            "/v1/tenants/race/files/R-2", {"department": "finance"}
        )
        self.assertEqual(denied.status, 403, denied.body)
        self.assertEqual(file_state(db, "race", "R-2")["department"], "sales")

    def test_revoked_session_is_rejected_immediately(self) -> None:
        db, hooks, servers, tokens = self.make_group("session-revoke")
        # alice logs in separately and gets her own token.
        login = Client(servers[0].base_url).post(
            "/v1/auth/login", {"username": "alice", "password": TEST_PASSWORD}
        )
        self.assertEqual(login.status, 200, login.body)
        extra = Client(servers[0].base_url, token=login.body["token"])
        self.assertEqual(extra.get("/v1/me").status, 200)
        self.assertEqual(extra.post("/v1/auth/logout").status, 200)
        self.assertEqual(extra.get("/v1/me").status, 401)
        # Other processes must agree; the session lives in the database.
        other = Client(servers[2].base_url, token=login.body["token"])
        self.assertEqual(other.get("/v1/me").status, 401)

    def test_paused_reader_does_not_block_other_reads_or_writes(self) -> None:
        """Proves there is no cross-process global mutex around requests."""
        db, hooks, servers, tokens = self.make_group("no-global-lock")
        alice_a = self.client(servers[0], tokens["alice"])
        outcome: dict[str, object] = {}

        def paused_read() -> None:
            outcome["read"] = alice_a.get(
                "/v1/tenants/race/files/R-1",
                headers={"X-Test-Sync": "r1:after_read_authz"},
            )

        thread = threading.Thread(target=paused_read)
        thread.start()
        hooks.wait_paused("r1", "after_read_authz", timeout=20)

        # While server 0 is parked inside a read transaction, reads on the
        # other three processes must complete normally.
        started = time.monotonic()
        for server in servers[1:]:
            c = self.client(server, tokens["alice"])
            self.assertEqual(c.get("/v1/tenants/race/files/R-1").status, 200)
        # A write on another process must also be able to commit (WAL).
        writer = self.client(servers[2], tokens["alice"])
        write = writer.patch("/v1/tenants/race/files/R-1", {"department": "sales"})
        self.assertEqual(write.status, 200, write.body)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0, "a paused reader blocked other requests")

        hooks.release("r1", "after_read_authz")
        thread.join(timeout=30)
        self.assertEqual(outcome["read"].status, 200)
        self.assertEqual(file_state(db, "race", "R-1")["version"], 2)

    def test_revocation_is_visible_to_all_processes_after_return(self) -> None:
        db, hooks, servers, tokens = self.make_group("warm-cache")
        # Warm each process's per-(user, tenant) cache with allowed reads.
        for server in servers:
            c = self.client(server, tokens["alice"])
            for _ in range(3):
                self.assertEqual(c.get("/v1/tenants/race/files/R-1").status, 200)
        # Cache counters are admin-only; check them on each process.
        for server in servers:
            admin_c = self.client(server, tokens["admin"])
            stats = admin_c.get("/v1/authz/cache-stats")
            self.assertEqual(stats.status, 200, stats.body)
            self.assertGreaterEqual(stats.body["cache"]["entries"], 1)

        admin = self.client(servers[0], tokens["admin"])
        # Withdraw inherited read by detaching child from parent.  The reverse
        # edge parent -> child remains, so the graph is still cyclic.
        result = admin.put(
            "/v1/admin/tenants/race/roles/child/parents", {"parents": []}
        )
        self.assertEqual(result.status, 200, result.body)
        revoked_version = result.body["authz_version"]

        for server in servers:
            c = self.client(server, tokens["alice"])
            denied = c.get("/v1/tenants/race/files/R-1")
            self.assertEqual(denied.status, 403, (server.port, denied.body))
            listing = c.get("/v1/tenants/race/files?page_size=100")
            self.assertEqual(listing.status, 200)
            self.assertEqual(listing.body["items"], [])
            self.assertEqual(listing.body["total"], 0)

        snapshot = db_snapshot(db)
        self.assertEqual(snapshot["authz_versions"]["race"], revoked_version)
        # The cycle still exists in the database (parent -> child).
        parents = {
            (row["child"], row["parent"]) for row in snapshot["parents"]
        }
        self.assertIn(("parent", "child"), parents)
        self.assertNotIn(("child", "parent"), parents)

    def test_blocked_write_revalidates_after_revocation(self) -> None:
        db, hooks, servers, tokens = self.make_group("blocked-write")
        writer = self.client(servers[1], tokens["alice"])
        self.assertEqual(writer.get("/v1/tenants/race/files/R-1").status, 200)
        before = file_state(db, "race", "R-1")
        self.assertEqual(before["department"], "sales")
        self.assertEqual(before["version"], 1)

        outcome: dict[str, object] = {}

        def do_patch() -> None:
            try:
                outcome["result"] = writer.patch(
                    "/v1/tenants/race/files/R-1",
                    {"department": "finance"},
                    headers={"X-Test-Sync": "w1:after_authz"},
                )
            except Exception as exc:  # pragma: no cover - diagnostic
                outcome["error"] = exc

        thread = threading.Thread(target=do_patch)
        thread.start()
        hooks.wait_paused("w1", "after_authz", timeout=20)
        # Phase-1 authorization passed.  Revoke write and commit before the
        # paused request may proceed.
        admin = self.client(servers[0], tokens["admin"])
        revoked = admin.put(
            "/v1/admin/tenants/race/users/alice/roles",
            {"roles": ["child"]},  # drops ownwrite
        )
        self.assertEqual(revoked.status, 200, revoked.body)
        hooks.release("w1", "after_authz")
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive())
        result = outcome.get("result")
        self.assertIsNotNone(result, outcome)
        self.assertEqual(result.status, 403, result.body)
        self.assertEqual(result.body["error"]["code"], "forbidden")
        self.assertIn("revalidation", result.body["error"]["message"])

        after = file_state(db, "race", "R-1")
        self.assertEqual(after["department"], before["department"])
        self.assertEqual(after["version"], before["version"])
        self.assertEqual(after["owner"], "alice")
        # No trace of a committed change in the response or the database.
        self.assertEqual(
            file_state(db, "race", "R-1")["updated_at"], before["updated_at"]
        )

    def test_resource_attribute_change_interleaving_rejects_write(self) -> None:
        db, hooks, servers, tokens = self.make_group("attr-change")
        # bob (sales) may write sales resources such as R-2.
        writer = self.client(servers[2], tokens["bob"])
        self.assertEqual(writer.get("/v1/tenants/race/files/R-2").status, 200)
        before = file_state(db, "race", "R-2")
        self.assertEqual(before["department"], "sales")

        outcome: dict[str, object] = {}

        def do_patch() -> None:
            outcome["result"] = writer.patch(
                "/v1/tenants/race/files/R-2",
                {"owner": "bob"},
                headers={"X-Test-Sync": "w2:after_authz"},
            )

        thread = threading.Thread(target=do_patch)
        thread.start()
        hooks.wait_paused("w2", "after_authz", timeout=20)
        # Move the resource out of bob's department; commit under the writer
        # slot before the paused request is released.
        admin = self.client(servers[0], tokens["admin"])
        moved = admin.patch(
            "/v1/tenants/race/files/R-2", {"department": "finance"}
        )
        self.assertEqual(moved.status, 200, moved.body)
        hooks.release("w2", "after_authz")
        thread.join(timeout=30)
        result = outcome.get("result")
        self.assertIsNotNone(result)
        self.assertEqual(result.status, 403, result.body)
        after = file_state(db, "race", "R-2")
        self.assertEqual(after["department"], "finance")  # admin's change won
        self.assertEqual(after["owner"], "carol")        # bob's write never ran
        self.assertEqual(after["version"], 2)            # only the admin write

    def test_reads_proceed_while_writer_holds_write_lock(self) -> None:
        db, hooks, servers, tokens = self.make_group("read-concurrency")
        writer = self.client(servers[3], tokens["bob"])
        outcome: dict[str, object] = {}

        def do_patch() -> None:
            outcome["result"] = writer.patch(
                "/v1/tenants/race/files/R-3",
                {"department": "sales"},
                headers={"X-Test-Sync": "w3:after_write_begin"},
            )

        thread = threading.Thread(target=do_patch)
        thread.start()
        hooks.wait_paused("w3", "after_write_begin", timeout=20)

        started = time.monotonic()
        reads = []
        for server in servers:
            c = self.client(server, tokens["bob"])
            reads.append(c.get("/v1/tenants/race/files/R-1"))
        elapsed = time.monotonic() - started
        for read in reads:
            self.assertEqual(read.status, 200, read.body)
            self.assertEqual(read.body["resource"]["file_id"], "R-1")
        self.assertLess(elapsed, 5.0, "reads were blocked by the writer")

        hooks.release("w3", "after_write_begin")
        thread.join(timeout=30)
        result = outcome.get("result")
        self.assertEqual(result.status, 200, result.body)
        self.assertEqual(file_state(db, "race", "R-3")["department"], "sales")
        self.assertEqual(file_state(db, "race", "R-3")["version"], 2)

    def test_parallel_admin_revocations_are_serialized_by_sqlite_only(self) -> None:
        db, hooks, servers, tokens = self.make_group("parallel-revoke")
        admin_clients = [
            self.client(server, tokens["admin"]) for server in servers
        ]
        errors: list[Exception] = []
        stop = threading.Event()

        def reader() -> None:
            c = self.client(servers[0], tokens["alice"])
            try:
                while not stop.is_set():
                    c.get("/v1/tenants/race/files/R-1")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(6)]
        for t in threads:
            t.start()
        versions = []
        try:
            for i, admin_client in enumerate(admin_clients):
                roles = ["child", "ownwrite"] if i % 2 == 0 else ["child"]
                result = admin_client.put(
                    "/v1/admin/tenants/race/users/alice/roles", {"roles": roles}
                )
                self.assertEqual(result.status, 200, result.body)
                versions.append(result.body["authz_version"])
        finally:
            stop.set()
            for t in threads:
                t.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(versions, sorted(set(versions)))
        self.assertEqual(len(versions), 4)
        snapshot = db_snapshot(db)
        self.assertEqual(snapshot["authz_versions"]["race"], versions[-1])

    def test_cache_warm_then_inheritance_edit(self) -> None:
        db, hooks, servers, tokens = self.make_group("inherit-edit")
        for server in servers:
            c = self.client(server, tokens["alice"])
            self.assertEqual(c.get("/v1/tenants/race/files/R-1").status, 200)

        admin = self.client(servers[0], tokens["admin"])
        result = admin.put(
            "/v1/admin/tenants/race/roles/child/parents", {"parents": []}
        )
        self.assertEqual(result.status, 200, result.body)
        for server in servers:
            c = self.client(server, tokens["alice"])
            self.assertEqual(c.get("/v1/tenants/race/files/R-1").status, 403)

        # Reattach through direct SQL (mirrors an external management path)
        # and bump the version; all caches must pick it up again.
        with write_tx(db) as conn:
            tid = conn.execute(
                "SELECT id FROM tenants WHERE name='race'"
            ).fetchone()["id"]
            parent = conn.execute(
                "SELECT id FROM roles WHERE tenant_id=? AND name='parent'", (tid,)
            ).fetchone()["id"]
            child = conn.execute(
                "SELECT id FROM roles WHERE tenant_id=? AND name='child'", (tid,)
            ).fetchone()["id"]
            conn.execute(
                """
                INSERT OR IGNORE INTO role_parents(tenant_id, child_id, parent_id)
                VALUES (?, ?, ?)
                """,
                (int(tid), int(child), int(parent)),
            )
            bump_version(conn, int(tid))
        for server in servers:
            c = self.client(server, tokens["alice"])
            self.assertEqual(c.get("/v1/tenants/race/files/R-1").status, 200)

    def test_list_snapshot_is_internally_consistent(self) -> None:
        db, hooks, servers, tokens = self.make_group("list-snapshot")
        alice = self.client(servers[0], tokens["alice"])
        outcome: dict[str, object] = {}

        def do_list() -> None:
            outcome["result"] = alice.get(
                "/v1/tenants/race/files?page_size=100&sort=file_id",
                headers={"X-Test-Sync": "l1:after_list_snapshot"},
            )

        thread = threading.Thread(target=do_list)
        thread.start()
        hooks.wait_paused("l1", "after_list_snapshot", timeout=20)
        admin = self.client(servers[1], tokens["admin"])
        revoked = admin.put(
            "/v1/admin/tenants/race/users/alice/roles", {"roles": ["ownwrite"]}
        )
        self.assertEqual(revoked.status, 200, revoked.body)
        hooks.release("l1", "after_list_snapshot")
        thread.join(timeout=30)
        result = outcome.get("result")
        self.assertIsNotNone(result)
        self.assertEqual(result.status, 200, result.body)
        returned = [i["file_id"] for i in result.body["items"]]
        # Per-request snapshot consistency is what is required; the in-flight
        # list may still reflect its pre-revocation snapshot, but must be
        # internally consistent and leak no unauthorized count.
        self.assertEqual(returned, sorted(returned))
        self.assertEqual(result.body["total"], len(returned))
        for file_id in returned:
            self.assertEqual(file_state(db, "race", file_id)["file_id"], file_id)

        # A request started after revocation must see the new (empty) state.
        after = alice.get("/v1/tenants/race/files?page_size=100")
        self.assertEqual(after.status, 200)
        self.assertEqual(after.body["total"], 0)
        self.assertEqual(after.body["items"], [])


if __name__ == "__main__":
    unittest.main()
