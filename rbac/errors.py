"""Typed API errors mapped to HTTP status codes by the HTTP layer."""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    status = 500
    code = "internal_error"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class BadRequest(ApiError):
    status = 400
    code = "bad_request"


class Unauthorized(ApiError):
    status = 401
    code = "unauthorized"


class Forbidden(ApiError):
    status = 403
    code = "forbidden"


class NotFound(ApiError):
    status = 404
    code = "not_found"


class MethodNotAllowed(ApiError):
    status = 405
    code = "method_not_allowed"


class Conflict(ApiError):
    status = 409
    code = "conflict"


class PayloadTooLarge(ApiError):
    status = 413
    code = "payload_too_large"


class Unprocessable(ApiError):
    status = 422
    code = "unprocessable"


class HookTimeout(ApiError):
    status = 503
    code = "test_hook_timeout"
