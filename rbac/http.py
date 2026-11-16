"""Minimal JSON-over-HTTP server built on http.server (stdlib only).

Concurrency model:
* ``ThreadingHTTPServer`` serves each connection on its own thread.
* Requests *never* take a process-wide lock.  Readers use SQLite read
  transactions (WAL, so they run concurrently with each other and with the
  single writer).  Writers rely on SQLite's ``BEGIN IMMEDIATE`` writer slot.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .auth import authenticate, create_session, revoke_session
from .authz import Authorizer, Principal
from .db import check_schema
from .errors import (
    ApiError,
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    NotFound,
    PayloadTooLarge,
    Unauthorized,
)
from .hooks import TestHooks
from .service import Service

MAX_BODY_BYTES = 64 * 1024


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Router:
    """Tiny explicit route table; path segments may contain ``:name`` params."""

    def __init__(self) -> None:
        self._routes: list[tuple[str, tuple[str, ...], Callable[..., Any]]] = []

    def add(self, method: str, pattern: str, handler: Callable[..., Any]) -> None:
        parts = tuple(p for p in pattern.strip("/").split("/") if p)
        self._routes.append((method.upper(), parts, handler))

    def match(self, method: str, path: str) -> tuple[Callable[..., Any], dict[str, str]]:
        segments = tuple(unquote(p) for p in path.strip("/").split("/") if p)
        allowed_methods: set[str] = set()
        for route_method, pattern, handler in self._routes:
            if len(pattern) != len(segments):
                continue
            params: dict[str, str] = {}
            ok = True
            for expected, actual in zip(pattern, segments):
                if expected.startswith(":"):
                    if not actual:
                        ok = False
                        break
                    params[expected[1:]] = actual
                elif expected != actual:
                    ok = False
                    break
            if not ok:
                continue
            allowed_methods.add(route_method)
            if route_method == method:
                return handler, params
        if allowed_methods:
            raise MethodNotAllowed(
                f"method {method} not allowed", allowed=sorted(allowed_methods)
            )
        raise NotFound(f"no route for {method} {path}")


class Application:
    def __init__(self, db_path: str) -> None:
        self.db_path = check_schema(db_path)
        self.service = Service(self.db_path, Authorizer(self.db_path), TestHooks())
        self.router = Router()
        self._register_routes()

    # -------------------------------------------------------------- helpers

    def principal(self, headers: Any) -> Principal:
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise Unauthorized("missing bearer token")
        identity = authenticate(self.db_path, auth[len("Bearer "):].strip())
        return Principal(
            user_id=identity["user_id"],
            username=identity["username"],
            department=identity["department"],
            is_admin=identity["is_admin"],
        )

    @staticmethod
    def sync_spec(headers: Any) -> tuple[str, str | None] | None:
        return TestHooks.parse_sync(headers.get("X-Test-Sync"))

    @staticmethod
    def _int_param(query: dict[str, list[str]], name: str, default: int) -> int:
        raw = query.get(name, [str(default)])[0]
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise BadRequest(f"{name} must be an integer")

    # --------------------------------------------------------------- routes

    def _register_routes(self) -> None:
        r = self.router
        r.add("POST", "/v1/auth/login", self.handle_login)
        r.add("POST", "/v1/auth/logout", self.handle_logout)
        r.add("GET", "/v1/me", self.handle_me)
        r.add("GET", "/v1/tenants/:tenant/files", self.handle_list)
        r.add("GET", "/v1/tenants/:tenant/files/:file_id", self.handle_get)
        r.add("PATCH", "/v1/tenants/:tenant/files/:file_id", self.handle_update)
        r.add("GET", "/v1/admin/tenants/:tenant/state", self.handle_admin_state)
        r.add("POST", "/v1/admin/tenants/:tenant/roles", self.handle_create_role)
        r.add("PUT", "/v1/admin/tenants/:tenant/users/:username/roles", self.handle_set_user_roles)
        r.add("PUT", "/v1/admin/tenants/:tenant/roles/:role/parents", self.handle_set_parents)
        r.add("PUT", "/v1/admin/tenants/:tenant/roles/:role/rules", self.handle_set_rules)
        r.add("GET", "/v1/healthz", self.handle_health)
        r.add("GET", "/v1/authz/cache-stats", self.handle_cache_stats)

    # ------------------------------------------------------------- handlers

    def handle_health(self, request: "_Request") -> tuple[int, Any]:
        return 200, {"status": "ok"}

    def handle_cache_stats(self, request: "_Request") -> tuple[int, Any]:
        # Admin-only, and exposes only counters -- never cached decisions,
        # role names or cross-tenant data.
        principal = self.principal(request.headers)
        if not principal.is_admin:
            raise Forbidden("administrator privileges required")
        return 200, {"cache": self.service.authorizer.cache.stats()}

    def handle_login(self, request: "_Request") -> tuple[int, Any]:
        body = request.json_body()
        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise BadRequest("username and password are required strings")
        if not 1 <= len(username) <= 100 or not 1 <= len(password) <= 1024:
            raise BadRequest("username or password has an invalid length")
        token, info = create_session(self.db_path, username, password)
        return 200, {
            "token": token,
            "token_type": "Bearer",
            "expires_at": info["expires_at"],
            "username": info["username"],
        }

    def handle_logout(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        auth = request.headers.get("Authorization", "")
        token = auth[len("Bearer "):].strip()
        revoke_session(self.db_path, token)
        return 200, {"revoked": True, "username": principal.username}

    def handle_me(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        return 200, self.service.me(principal)

    def handle_list(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        params = request.params
        query = request.query
        page = self._int_param(query, "page", 1)
        page_size = self._int_param(query, "page_size", 20)
        sort = query.get("sort", ["file_id"])[0]
        order = query.get("order", ["asc"])[0]
        return 200, self.service.list_files(
            principal,
            params["tenant"],
            page=page,
            page_size=page_size,
            sort=sort,
            order=order,
            sync_spec=self.sync_spec(request.headers),
        )

    def handle_get(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        return 200, self.service.get_file(
            principal,
            request.params["tenant"],
            request.params["file_id"],
            sync_spec=self.sync_spec(request.headers),
        )

    def handle_update(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        body = request.json_body()
        owner = body.get("owner")
        department = body.get("department")
        if owner is not None and not isinstance(owner, str):
            raise BadRequest("owner must be a string")
        if department is not None and not isinstance(department, str):
            raise BadRequest("department must be a string")
        if department is not None and not department.strip():
            raise BadRequest("department must not be empty")
        return 200, self.service.update_file(
            principal,
            request.params["tenant"],
            request.params["file_id"],
            owner=owner,
            department=department,
            sync_spec=self.sync_spec(request.headers),
        )

    def handle_admin_state(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        return 200, self.service.admin_state(principal, request.params["tenant"])

    def handle_create_role(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        body = request.json_body()
        name = body.get("name")
        if not isinstance(name, str):
            raise BadRequest("name must be a string")
        return 200, self.service.create_role(principal, request.params["tenant"], name)

    def handle_set_user_roles(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        body = request.json_body()
        roles = body.get("roles")
        if not isinstance(roles, list) or any(not isinstance(r, str) for r in roles):
            raise BadRequest("roles must be a list of strings")
        return 200, self.service.set_user_roles(
            principal, request.params["tenant"], request.params["username"], roles
        )

    def handle_set_parents(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        body = request.json_body()
        parents = body.get("parents")
        if not isinstance(parents, list) or any(not isinstance(p, str) for p in parents):
            raise BadRequest("parents must be a list of strings")
        return 200, self.service.set_role_parents(
            principal, request.params["tenant"], request.params["role"], parents
        )

    def handle_set_rules(self, request: "_Request") -> tuple[int, Any]:
        principal = self.principal(request.headers)
        body = request.json_body()
        rules = body.get("rules")
        if not isinstance(rules, list):
            raise BadRequest("rules must be a list")
        return 200, self.service.set_role_rules(
            principal, request.params["tenant"], request.params["role"], rules
        )

    def dispatch(self, method: str, path: str) -> tuple[Callable[..., Any], dict[str, str]]:
        return self.router.match(method, path)


class _Request:
    """Per-request context passed to handlers."""

    def __init__(
        self,
        headers: Any,
        params: dict[str, str],
        query: dict[str, list[str]],
        body: bytes,
    ) -> None:
        self.headers = headers
        self.params = params
        self.query = query
        self.body = body

    def json_body(self) -> dict[str, Any]:
        if not self.body:
            raise BadRequest("request body must be a JSON object")
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BadRequest(f"invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise BadRequest("request body must be a JSON object")
        return data


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "rbac-files/1.0"
    sys_version = ""

    application: Application  # set on the dynamically created subclass

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        if os.environ.get("RBAC_ACCESS_LOG") == "1":
            sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    # ------------------------------------------------------------- plumbing

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
        except ValueError:
            self.close_connection = True
            raise BadRequest("invalid Content-Length")
        if length < 0:
            self.close_connection = True
            raise BadRequest("invalid Content-Length")
        if length > MAX_BODY_BYTES:
            # Do not read the body; closing avoids desynchronizing the stream.
            self.close_connection = True
            raise PayloadTooLarge("request body too large")
        return self.rfile.read(length) if length else b""

    def _send_json(self, status: int, payload: Any, extra: dict[str, str] | None = None) -> None:
        data = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _error(self, exc: ApiError) -> None:
        details = dict(exc.details)
        if isinstance(exc, Forbidden) and os.environ.get("RBAC_EXPOSE_DECISIONS") != "1":
            # Do not expose internal role ids / matched rule labels to callers.
            details.pop("decision", None)
        payload = {"error": {"code": exc.code, "message": exc.message}}
        if details:
            payload["error"]["details"] = details
        extra = None
        if isinstance(exc, MethodNotAllowed):
            allowed = details.get("allowed", [])
            if allowed:
                extra = {"Allow": ", ".join(allowed)}
        self._send_json(exc.status, payload, extra)

    def _handle(self, method: str) -> None:
        try:
            body = self._read_body()
            split = urlsplit(self.path)
            query = parse_qs(split.query, keep_blank_values=True)
            handler, params = self.application.dispatch(method, split.path)
            request = _Request(self.headers, params, query, body)
            status, payload = handler(request)
            self._send_json(status, payload)
        except ApiError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:  # never leak a traceback to the client
            if os.environ.get("RBAC_DEBUG") == "1":
                import traceback

                traceback.print_exc()
            self._error(ApiError("internal server error", error_type=type(exc).__name__))

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_PATCH(self) -> None:
        self._handle("PATCH")

    def do_DELETE(self) -> None:
        self._handle("DELETE")


def make_server(
    db_path: str, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    application = Application(db_path)
    handler_class = type(
        "BoundHandler", (Handler,), {"application": application}
    )
    server = ThreadingHTTPServer((host, port), handler_class)
    server.daemon_threads = True
    server.request_queue_size = 128
    return server


def serve_forever(db_path: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    server = make_server(db_path, host, port)
    bound_host, bound_port = server.server_address[:2]
    print(f"listening on http://{bound_host}:{bound_port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
