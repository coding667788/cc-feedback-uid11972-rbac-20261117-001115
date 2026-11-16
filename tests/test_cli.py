"""CLI, initialization and schema tests exercised via subprocesses."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import ROOT, file_state, preset_db


def run_cli(*args: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "rbac", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


class InitAndCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_init_creates_seeded_database_and_refuses_overwrite(self) -> None:
        db = self.dir / "new" / "rbac.db"
        result = run_cli("--db", str(db), "init")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["tenants"], ["acme", "globex", "umbrella"])
        self.assertEqual(payload["files"], 12)
        self.assertIn("alice", payload["credentials"])
        self.assertTrue(db.exists())

        again = run_cli("--db", str(db), "init")
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("already exists", again.stderr)

        forced = run_cli("--db", str(db), "init", "--force")
        self.assertEqual(forced.returncode, 0, forced.stderr)

    def test_dump_is_consistent_and_contains_preset(self) -> None:
        db = preset_db(self.dir / "dump.db")
        result = run_cli("--db", db, "dump")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        tenants = {t["name"] for t in payload["tenants"]}
        self.assertEqual(tenants, {"acme", "globex", "umbrella"})
        files = {(f["tenant_id"], f["file_id"]) for f in payload["files"]}
        self.assertEqual(len(files), 12)
        # cycle edges present: child/parent cycle in acme
        names = {r["id"]: r for r in payload["roles"]}
        edges = {(p["child_id"], p["parent_id"]) for p in payload["parents"]}
        cycle_a = next(r["id"] for r in payload["roles"] if r["name"] == "cycle-a")
        cycle_b = next(r["id"] for r in payload["roles"] if r["name"] == "cycle-b")
        self.assertIn((cycle_a, cycle_b), edges)
        self.assertIn((cycle_b, cycle_a), edges)

    def test_login_and_state_commands(self) -> None:
        db = preset_db(self.dir / "cli.db")
        login = run_cli("--db", db, "login", "alice", "AlicePass1!")
        self.assertEqual(login.returncode, 0, login.stderr)
        token = json.loads(login.stdout)["token"]
        self.assertIsInstance(token, str)

        bad = run_cli("--db", db, "login", "alice", "wrong")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("invalid credentials", bad.stderr)

        state = run_cli("--db", db, "state", "acme", "--admin", "admin")
        self.assertEqual(state.returncode, 0, state.stderr)
        payload = json.loads(state.stdout)
        self.assertEqual(payload["tenant"], "acme")
        self.assertGreaterEqual(payload["authz_version"], 1)
        self.assertTrue(any(r["name"] == "cycle-a" for r in payload["roles"]))

    def test_management_commands_mutate_and_bump_version(self) -> None:
        db = preset_db(self.dir / "manage.db")
        version_before = json.loads(
            run_cli("--db", db, "state", "acme").stdout
        )["authz_version"]

        set_roles = run_cli(
            "--db", db, "set-user-roles", "acme", "alice", "reader"
        )
        self.assertEqual(set_roles.returncode, 0, set_roles.stderr)
        payload = json.loads(set_roles.stdout)
        self.assertEqual(payload["authz_version"], version_before + 1)
        self.assertEqual(payload["roles"], ["reader"])

        parents = run_cli(
            "--db", db, "set-role-parents", "acme", "reader", "cycle-a"
        )
        self.assertEqual(parents.returncode, 0, parents.stderr)
        self.assertEqual(
            json.loads(parents.stdout)["authz_version"], version_before + 2
        )

        rules_json = json.dumps(
            [
                {"effect": "allow", "action": "read", "condition": "any"},
                {"effect": "deny", "action": "write", "condition": "any"},
            ]
        )
        rules = run_cli(
            "--db", db, "set-role-rules", "acme", "reader", rules_json
        )
        self.assertEqual(rules.returncode, 0, rules.stderr)
        self.assertEqual(
            json.loads(rules.stdout)["authz_version"], version_before + 3
        )

        dump = json.loads(run_cli("--db", db, "dump").stdout)
        acme_id = next(t["id"] for t in dump["tenants"] if t["name"] == "acme")
        alice_roles = {
            r["role"]
            for r in dump["assignments"]
            if r["username"] == "alice" and r["tenant_id"] == acme_id
        }
        self.assertEqual(alice_roles, {"reader"})

    def test_management_rejects_unknown_roles_and_non_admin(self) -> None:
        db = preset_db(self.dir / "reject.db")
        unknown = run_cli(
            "--db", db, "set-user-roles", "acme", "alice", "no-such-role"
        )
        self.assertNotEqual(unknown.returncode, 0)
        self.assertIn("unknown role", unknown.stderr)

        not_admin = run_cli(
            "--db", db, "set-user-roles", "acme", "alice", "reader",
            "--admin", "alice",
        )
        self.assertNotEqual(not_admin.returncode, 0)
        self.assertIn("administrator", not_admin.stderr)

    def test_create_role_command_and_dump_roundtrip(self) -> None:
        db = preset_db(self.dir / "create.db")
        before = json.loads(run_cli("--db", db, "state", "acme").stdout)
        created = run_cli("--db", db, "create-role", "acme", "ops-reader")
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        self.assertEqual(payload["role"]["name"], "ops-reader")
        self.assertEqual(payload["authz_version"], before["authz_version"] + 1)

        duplicate = run_cli("--db", db, "create-role", "acme", "ops-reader")
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("already exists", duplicate.stderr)

        dump = json.loads(run_cli("--db", db, "dump").stdout)
        acme_id = next(t["id"] for t in dump["tenants"] if t["name"] == "acme")
        self.assertTrue(
            any(
                r["tenant_id"] == acme_id and r["name"] == "ops-reader"
                for r in dump["roles"]
            )
        )

    def test_serve_refuses_missing_or_uninitialized_database(self) -> None:
        missing = run_cli("--db", str(self.dir / "missing.db"), "serve")
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("does not exist", missing.stderr)

        empty = self.dir / "empty.db"
        empty.write_bytes(b"")
        bad = run_cli("--db", str(empty), "serve")
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
