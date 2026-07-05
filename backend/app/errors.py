"""
Single error-response envelope for the whole API.

Why: the audit found two competing error conventions in the same codebase —
`raise HTTPException(...)` (proper 4xx/5xx) versus `return {"error": "..."}`
with an implicit HTTP 200 (routers/fraud.py otp_verify, routers/admin.py
set_role). The latter is actively misleading to API consumers: a 200 status
code tells clients "this succeeded," even when the body says otherwise.

This module defines one envelope shape:

    {
        "error": {
            "code": "invalid_credentials",
            "message": "Invalid email or password.",
            "details": null
        }
    }

and wires it to every error path via FastAPI exception handlers, so
individual route handlers only ever need to `raise` a well-known exception
type — they never hand-construct an error dict.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

logger = logging.getLogger("fraudguard.errors")


class AppError(HTTPException):
    """
    Base class for domain-specific API errors that carry a stable machine
    -readable `code` in addition to the human-readable `detail` message.

    Route handlers should raise a subclass (or this directly) instead of
    returning ad hoc dicts, so every failure path — regardless of layer —
    is rendered through the same envelope.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code = code
        self.message = message
        self.details = details


class NotFoundError(AppError):
    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(status.HTTP_404_NOT_FOUND, code, message, details)


class ConflictError(AppError):
    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(status.HTTP_409_CONFLICT, code, message, details)


class ForbiddenError(AppError):
    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(status.HTTP_403_FORBIDDEN, code, message, details)


class UnauthorizedError(AppError):
    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(
            status.HTTP_401_UNAUTHORIZED,
            code,
            message,
            details,
            headers={"WWW-Authenticate": "Bearer"},
        )


class BadRequestError(AppError):
    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(status.HTTP_400_BAD_REQUEST, code, message, details)


def _envelope(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def _code_from_status(status_code: int) -> str:
    return {
        status.HTTP_400_BAD_REQUEST: "bad_request",
        status.HTTP_401_UNAUTHORIZED: "unauthorized",
        status.HTTP_403_FORBIDDEN: "forbidden",
        status.HTTP_404_NOT_FOUND: "not_found",
        status.HTTP_409_CONFLICT: "conflict",
        status.HTTP_422_UNPROCESSABLE_ENTITY: "validation_error",
        status.HTTP_429_TOO_MANY_REQUESTS: "rate_limit_exceeded",
    }.get(status_code, "http_error")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(exc.code, exc.message, exc.details),
            headers=exc.headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(_code_from_status(exc.status_code), message),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Pydantic's exc.errors() can embed the raw exception instance in
        # error["ctx"]["error"] (e.g. the ValueError raised by a
        # @field_validator) — that's not JSON-serializable, so it must be
        # stringified before it reaches JSONResponse's encoder.
        details = []
        for error in exc.errors():
            sanitized = dict(error)
            ctx = sanitized.get("ctx")
            if isinstance(ctx, dict) and "error" in ctx:
                sanitized["ctx"] = {**ctx, "error": str(ctx["error"])}
            details.append(sanitized)

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_envelope(
                "validation_error",
                "One or more fields failed validation.",
                details=details,
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Defensive catch-all: never leak stack traces or internal exception
        # text to the client. Full details go to structured logs only.
        logger.exception(
            "unhandled_exception",
            extra={"path": request.url.path, "method": request.method},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_envelope("internal_error", "An unexpected error occurred."),
        )
