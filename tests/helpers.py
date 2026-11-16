"""Shared test helpers: database building, HTTP client, server lifecycle."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rbac.auth import create_session  # noqa: E402
from rbac.db import (  # noqa: E402
    add_file_raw,
    add_membership,
    add_rule_raw,
    bump_version,
    connect,
    create_role,
    create_tenant,
    create_user,
    init_database,
    set_role_parents_raw,
    set_user_roles_raw,
    write_tx,
)


class HttpResult:
    __slots__ = ("status", "body", "headers")

    def __init__(self, status: int, body: Any, headers: dict[str, str]) -> None:
        self.status = status
        self.body = body
        self.headers = headers

    def __repr__(self) -> str:
        return f"HttpResult({self.status}, {self.body!r})"


class Client:
    def __init__(self, base_url: str, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> HttpResult:
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        bearer = token if token is not None else self.token
        if bearer:
            request.add_header("Authorization", "Bearer " + bearer)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
                parsed = json.loads(payload) if payload else None
                return HttpResult(response.status, parsed, dict(response.headers))
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            parsed = json.loads(payload) if payload else None
            return HttpResult(exc.code, parsed, dict(exc.headers))

    def get(self, path: str, **kw: Any) -> HttpResult:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Any = None, **kw: Any) -> HttpResult:
        return self.request("POST", path, body, **kw)

    def put(self, path: str, body: Any = None, **kw: Any) -> HttpResult:
        return self.request("PUT", path, body, **kw)

    def patch(self, path: str, body: Any = None, **kw: Any) -> HttpResult:
        return self.request("PATCH", path, body, **kw)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ServerProcess:
    """A real ``python -m rbac serve`` subprocess."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        hook_dir: str | Path | None = None,
        env_extra: dict[str, str] | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.port = free_port()
        self.hook_dir = Path(hook_dir) if hook_dir else None
        self.env_extra = dict(env_extra or {})
        self.process: subprocess.Popen[str] | None = None
        self.log_path = Path(self.db_path).parent / f"server-{self.port}.log"

    def start(self, wait: bool = True) -> "ServerProcess":
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["RBAC_TEST_HOOKS"] = "1"
        if self.hook_dir is not None:
            env["RBAC_TEST_HOOK_DIR"] = str(self.hook_dir)
        env.update(self.env_extra)
        self._log_handle = open(self.log_path, "w", encoding="utf-8")
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "rbac",
                "--db",
                self.db_path,
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
            ],
            cwd=str(ROOT),
            env=env,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if wait:
            self.wait_ready()
        return self

    def wait_ready(self, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        client = Client(self.base_url)
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(
                    f"server exited early ({self.process.returncode}):\n{self.log()}"
                )
            try:
                result = client.get("/v1/healthz", timeout=0.5)
                if result.status == 200:
                    return
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                pass
            time.sleep(0.05)
        raise RuntimeError(f"server not ready:\n{self.log()}")

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def log(self) -> str:
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ""

    def stop(self, timeout: float = 10.0) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=timeout)
        try:
            self._log_handle.close()
        except Exception:
            pass
        self.process = None

    def __enter__(self) -> "ServerProcess":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


@contextmanager
def running_server(
    db_path: str | Path,
    *,
    hook_dir: str | Path | None = None,
    env_extra: dict[str, str] | None = None,
) -> Iterator[ServerProcess]:
    server = ServerProcess(db_path, hook_dir=hook_dir, env_extra=env_extra)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def token_for(db_path: str | Path, username: str, password: str) -> str:
    token, _ = create_session(str(db_path), username, password)
    return token


def preset_db(path: str | Path) -> str:
    target = Path(path)
    if target.exists():
        target.unlink()
    init_database(str(target), force=True)
    return str(target)


def db_snapshot(db_path: str | Path) -> dict[str, Any]:
    """Direct SQLite read of the final state, independent of the service."""
    conn = connect(str(db_path))
    try:
        conn.execute("BEGIN")
        files = [
            dict(r)
            for r in conn.execute(
                """
                SELECT f.tenant_id, t.name AS tenant, f.file_id, f.owner_user_id,
                       u.username AS owner, f.department, f.version, f.updated_at
                  FROM files f
                  JOIN tenants t ON t.id = f.tenant_id
                  JOIN users u ON u.id = f.owner_user_id
                 ORDER BY t.name, f.file_id
                """
            )
        ]
        versions = {
            str(r["name"]): int(r["authz_version"])
            for r in conn.execute(
                """
                SELECT t.name, m.authz_version
                  FROM tenant_meta m JOIN tenants t ON t.id = m.tenant_id
                """
            )
        }
        assignments = [
            dict(r)
            for r in conn.execute(
                """
                SELECT t.name AS tenant, u.username, r.name AS role
                  FROM user_roles ur
                  JOIN tenants t ON t.id = ur.tenant_id
                  JOIN users u ON u.id = ur.user_id
                  JOIN roles r ON r.id = ur.role_id
                 ORDER BY t.name, u.username, r.name
                """
            )
        ]
        parents = [
            dict(r)
            for r in conn.execute(
                """
                SELECT t.name AS tenant, c.name AS child, p.name AS parent
                  FROM role_parents rp
                  JOIN tenants t ON t.id = rp.tenant_id
                  JOIN roles c ON c.id = rp.child_id
                  JOIN roles p ON p.id = rp.parent_id
                 ORDER BY t.name, c.name, p.name
                """
            )
        ]
        rules = [
            dict(r)
            for r in conn.execute(
                """
                SELECT t.name AS tenant, r.name AS role, ru.effect, ru.action, ru.condition
                  FROM rules ru
                  JOIN tenants t ON t.id = ru.tenant_id
                  JOIN roles r ON r.id = ru.role_id
                 ORDER BY t.name, r.name, ru.effect, ru.action, ru.condition
                """
            )
        ]
        conn.execute("COMMIT")
        return {
            "files": files,
            "authz_versions": versions,
            "assignments": assignments,
            "parents": parents,
            "rules": rules,
        }
    finally:
        conn.close()


def file_state(db_path: str | Path, tenant: str, file_id: str) -> dict[str, Any] | None:
    conn = connect(str(db_path))
    try:
        row = conn.execute(
            """
            SELECT f.file_id, u.username AS owner, f.department, f.version,
                   f.owner_user_id, f.updated_at
              FROM files f
              JOIN tenants t ON t.id = f.tenant_id
              JOIN users u ON u.id = f.owner_user_id
             WHERE t.name = ? AND f.file_id = ?
            """,
            (tenant, file_id),
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.01) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise TimeoutError("condition not met within timeout")


class HookDir:
    """Coordinates test hooks across processes via marker files."""

    def __init__(self, directory: str | Path) -> None:
        self.path = Path(directory)
        self.path.mkdir(parents=True, exist_ok=True)

    def paused(self, key: str, point: str) -> bool:
        return (self.path / f"{key}.{point}.paused").exists()

    def wait_paused(self, key: str, point: str, timeout: float = 10.0) -> None:
        wait_for(lambda: self.paused(key, point), timeout=timeout)

    def release(self, key: str, point: str) -> None:
        target = self.path / f"{key}.{point}.go"
        deadline = time.monotonic() + 10.0
        while True:
            try:
                target.write_text("go", encoding="utf-8")
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    def clear(self) -> None:
        for item in self.path.iterdir():
            try:
                item.unlink()
            except OSError:
                pass
