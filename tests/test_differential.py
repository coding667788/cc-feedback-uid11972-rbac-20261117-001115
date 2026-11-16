"""Differential tests: production HTTP service vs independent reference.

For each random fixture we compare
* every (user, tenant, file, action) permission decision,
* the full read listing, totals and every page,
between the service and ``tests.reference.Snapshot`` (recursive DFS + naive
filter/sort/paginate using a separate SQLite connection).

All results are checked against resources and DB state, not just status codes.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests import helpers
from tests.fixtures import TEST_PASSWORD, build_random_fixture
from tests.helpers import Client, ServerProcess, db_snapshot, file_state
from tests.reference import Snapshot


class DifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def _serve(self, name: str, db: str) -> Client:
        server = ServerProcess(db, hook_dir=self.dir / f"{name}-hooks").start()
        self.addCleanup(server.stop)
        return Client(server.base_url)

    def _token(self, client: Client, username: str) -> str:
        result = client.post(
            "/v1/auth/login", {"username": username, "password": TEST_PASSWORD}
        )
        self.assertEqual(result.status, 200, result.body)
        return result.body["token"]

    def test_random_cyclic_fixture_matches_reference(self) -> None:
        for seed in range(5):
            with self.subTest(seed=seed):
                db, meta = build_random_fixture(self.dir / f"rand-{seed}.db", seed)
                client = self._serve(f"rand-{seed}", db)
                reference = Snapshot(db)
                snapshot = db_snapshot(db)

                for tenant in meta["tenants"]:
                    members = set(meta["memberships"][tenant])
                    files = [
                        row["file_id"]
                        for row in snapshot["files"]
                        if row["tenant"] == tenant
                    ]
                    for user in meta["users"]:
                        token = self._token(client, user)
                        is_member = user in members
                        for file_id in files:
                            ref_read = (
                                reference.decide(tenant, user, file_id, "read")
                                if is_member
                                else False
                            )
                            got_read = client.get(
                                f"/v1/tenants/{tenant}/files/{file_id}", token=token
                            )
                            expect_status = 200 if ref_read else 403
                            self.assertEqual(
                                got_read.status,
                                expect_status,
                                msg=(
                                    f"read {tenant}/{user}/{file_id} "
                                    f"member={is_member} ref={ref_read} got={got_read.body}"
                                ),
                            )
                            if ref_read:
                                self.assertEqual(
                                    got_read.body["resource"]["file_id"], file_id
                                )
                                self.assertEqual(
                                    got_read.body["resource"]["tenant"], tenant
                                )

                        # listing equals filter -> sort -> paginate
                        expected = reference.list_page(
                            tenant, user, page=1, page_size=100
                        )
                        listing = client.get(
                            f"/v1/tenants/{tenant}/files?page_size=100&sort=file_id",
                            token=token,
                        )
                        if not is_member:
                            self.assertEqual(listing.status, 403, listing.body)
                            continue
                        self.assertEqual(listing.status, 200, listing.body)
                        self.assertEqual(
                            [i["file_id"] for i in listing.body["items"]],
                            [i["file_id"] for i in expected["items"]],
                            msg=f"list {tenant}/{user}",
                        )
                        self.assertEqual(listing.body["total"], expected["total"])
                        self.assertEqual(
                            {i["file_id"]: i["owner"] for i in listing.body["items"]},
                            {
                                i["file_id"]: i["owner"]
                                for i in expected["items"]
                            },
                        )

                        # page-by-page equality
                        for page in range(1, 3):
                            expected_page = reference.list_page(
                                tenant, user, page=page, page_size=3
                            )
                            got_page = client.get(
                                f"/v1/tenants/{tenant}/files?page_size=3&page={page}",
                                token=token,
                            )
                            self.assertEqual(
                                [i["file_id"] for i in got_page.body["items"]],
                                [i["file_id"] for i in expected_page["items"]],
                                msg=f"page {page} {tenant}/{user}",
                            )
                            self.assertEqual(
                                got_page.body["total"], expected_page["total"]
                            )

    def test_department_change_shifts_listing_like_reference(self) -> None:
        """Move a file to another department; both sides must agree again."""
        db, meta = build_random_fixture(self.dir / "shift.db", 99)
        client = self._serve("shift", db)
        reference = Snapshot(db)
        tenant = meta["tenants"][0]
        admin_token = None
        # build_random_fixture has no admin; use a direct DB write + version bump
        from rbac.db import bump_version, write_tx

        with write_tx(db) as conn:
            row = conn.execute(
                """
                SELECT f.id, f.tenant_id, f.file_id FROM files f
                  JOIN tenants t ON t.id = f.tenant_id
                 WHERE t.name = ? ORDER BY f.file_id LIMIT 1
                """,
                (tenant,),
            ).fetchone()
            conn.execute(
                "UPDATE files SET department = ? WHERE id = ?",
                ("changed-dept", int(row["id"])),
            )
            bump_version(conn, int(row["tenant_id"]))
            moved_file = str(row["file_id"])
        fresh_reference = Snapshot(db)
        # verify DB reflects the move
        moved = file_state(db, tenant, moved_file)
        self.assertEqual(moved["department"], "changed-dept")

        members = set(meta["memberships"][tenant])
        for user in meta["users"]:
            token = self._token(client, user)
            expected = fresh_reference.list_page(tenant, user, page=1, page_size=100)
            listing = client.get(
                f"/v1/tenants/{tenant}/files?page_size=100&sort=file_id", token=token
            )
            if user not in members:
                self.assertEqual(listing.status, 403, listing.body)
                continue
            self.assertEqual(listing.status, 200, listing.body)
            self.assertEqual(
                [i["file_id"] for i in listing.body["items"]],
                [i["file_id"] for i in expected["items"]],
                msg=f"after move {tenant}/{user}",
            )
            self.assertEqual(listing.body["total"], expected["total"])

    def test_deny_wins_and_cross_tenant_names_in_preset(self) -> None:
        db = helpers.preset_db(self.dir / "preset-diff.db")
        client = self._serve("preset", db)
        reference = Snapshot(db)
        passwords = {
            "admin": "AdminPass1!",
            "alice": "AlicePass1!",
            "bob": "BobPass1!",
            "carol": "CarolPass1!",
            "dave": "DavePass1!",
        }

        checks = [
            ("dave", "acme", "A-101", "read"),
            ("alice", "acme", "A-103", "read"),
            ("bob", "globex", "G-200", "read"),
            ("bob", "globex", "G-201", "write"),
            ("alice", "globex", "G-200", "write"),
            ("alice", "umbrella", "U-300", "read"),
            ("bob", "umbrella", "U-301", "write"),
            ("alice", "acme", "A-100", "write"),
        ]
        for user, tenant, file_id, action in checks:
            result = client.post(
                "/v1/auth/login",
                {"username": user, "password": passwords[user]},
            )
            self.assertEqual(result.status, 200, result.body)
            token = result.body["token"]
            ref = reference.decide(tenant, user, file_id, action)
            if action == "read":
                got = client.get(f"/v1/tenants/{tenant}/files/{file_id}", token=token)
            else:
                current = file_state(db, tenant, file_id)
                got = client.patch(
                    f"/v1/tenants/{tenant}/files/{file_id}",
                    {"department": current["department"]},
                    token=token,
                )
            self.assertEqual(
                got.status,
                200 if ref else 403,
                msg=f"{tenant}/{user}/{file_id}/{action} ref={ref} got={got.body}",
            )
            # a denied write must leave the row exactly as it was
            if action == "write" and not ref:
                after = file_state(db, tenant, file_id)
                self.assertEqual(after["department"], current["department"])
                self.assertEqual(after["version"], current["version"])


if __name__ == "__main__":
    unittest.main()
