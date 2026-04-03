"""
Audit log middleware — records all mutating requests (POST/PATCH/PUT/DELETE)
to the append-only audit_log table for HIPAA compliance.

HIPAA reference: 164.312(b) — Audit Controls (REQUIRED)
"""

from __future__ import annotations
import json
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError
from ..auth.jwt import decode_token
from ..models.audit_log import AuditLog
from ..database import AsyncSessionLocal

# Methods that mutate state — log these
LOGGED_METHODS = {"POST", "PATCH", "PUT", "DELETE"}

# Keys to strip from request bodies before storing (security)
SENSITIVE_KEYS = {"password", "new_password", "current_password", "token", "secret", "api_key"}

# Paths to skip (health checks, token refresh avoids logging credentials)
SKIP_PATHS = {"/api/health", "/api/docs", "/api/redoc", "/openapi.json"}


def _sanitize_body(body: dict) -> dict:
    """Recursively remove sensitive keys from request body snapshot."""
    if not isinstance(body, dict):
        return body
    return {
        k: ("***" if k.lower() in SENSITIVE_KEYS else _sanitize_body(v) if isinstance(v, dict) else v)
        for k, v in body.items()
    }


def _infer_resource(path: str, method: str) -> tuple[str, str]:
    """
    Infer resource_type and action from path + method.
    Returns (resource_type, action).
    """
    parts = [p for p in path.strip("/").split("/") if p]
    # /api/v1/users/123 → resource_type="user"
    resource = "unknown"
    if len(parts) >= 3:
        resource = parts[2].rstrip("s")  # "users" → "user", "clients" → "client"

    action_map = {
        "POST":   "CREATE",
        "PATCH":  "UPDATE",
        "PUT":    "UPDATE",
        "DELETE": "DELETE",
    }
    verb = action_map.get(method, method)
    return resource, f"{verb}_{resource.upper()}"


def _extract_resource_id(path: str) -> str | None:
    """Extract the last path segment if it looks like a UUID or numeric ID."""
    parts = [p for p in path.strip("/").split("/") if p]
    if parts:
        last = parts[-1]
        # Skip action segments like "rotate", "invite", "upload"
        if len(last) in (36, 32) or last.isdigit():
            return last
    return None


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting common proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class AuditMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that logs mutating HTTP requests to the audit_log table.

    Extracts user identity from Bearer JWT when present.
    Stores sanitized request body snapshot (passwords stripped).
    Records HTTP status code from the response.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only log mutating methods on relevant paths
        if request.method not in LOGGED_METHODS or request.url.path in SKIP_PATHS:
            return await call_next(request)

        # --- Extract identity from JWT (best-effort, no auth enforcement here) ---
        user_id: str | None = None
        user_email: str | None = None
        msp_id: str | None = None

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                payload = decode_token(auth_header[7:])
                user_id = payload.get("sub")
                msp_id = payload.get("msp_id")
                # email not in JWT payload — we'd need a DB lookup, skip for middleware perf
            except JWTError:
                pass

        # --- Capture request body (for JSON endpoints) ---
        request_body: dict | None = None
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                raw = await request.body()
                body_dict = json.loads(raw)
                request_body = _sanitize_body(body_dict)
                # Re-inject body so downstream handlers can still read it
                async def receive():
                    return {"type": "http.request", "body": raw}
                request = Request(request.scope, receive)
            except Exception:
                pass

        # --- Run the actual request ---
        response = await call_next(request)

        # --- Infer resource details ---
        path = request.url.path
        resource_type, action = _infer_resource(path, request.method)
        resource_id = _extract_resource_id(path)

        # --- Write audit record asynchronously ---
        try:
            async with AsyncSessionLocal() as db:
                entry = AuditLog(
                    user_id=user_id,
                    user_email=user_email,
                    msp_id=msp_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    http_method=request.method,
                    path=path,
                    status_code=response.status_code,
                    ip_address=_get_client_ip(request),
                    user_agent=request.headers.get("user-agent"),
                    request_body=request_body,
                )
                db.add(entry)
                await db.commit()
        except Exception:
            # Never let audit failure break the actual request
            pass

        return response
