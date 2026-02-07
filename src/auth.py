"""
JWT authentication for Scan Hub.

- POST /auth/token with {"sub": "..."} generates a signed JWT
- Middleware validates Authorization: Bearer <token> on protected routes
- If jwt_secret is empty, auth is disabled (backward compatible)
"""

from datetime import datetime, timedelta, timezone

import jwt
import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

log = structlog.get_logger()

ALGORITHM = "HS256"

# Routes that never require authentication
PUBLIC_ROUTES = {"/health", "/metrics", "/auth/token", "/docs", "/openapi.json"}


def create_token(secret: str, expire_minutes: int, subject: str = "scanhub") -> dict:
    """Create a signed JWT with expiration."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    token = jwt.encode(payload, secret, algorithm=ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expire_minutes * 60,
    }


def verify_token(secret: str, token: str) -> dict:
    """Verify and decode a JWT. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, secret, algorithms=[ALGORITHM])


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces JWT auth on all routes except PUBLIC_ROUTES."""

    def __init__(self, app, secret: str):
        super().__init__(app)
        self.secret = secret

    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/")

        # Skip auth for public routes and metrics sub-paths
        if path in PUBLIC_ROUTES or path.startswith("/metrics"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"},
            )

        token = auth_header[7:]
        try:
            verify_token(self.secret, token)
        except jwt.ExpiredSignatureError:
            return JSONResponse(
                status_code=401,
                content={"detail": "Token expired"},
            )
        except jwt.PyJWTError as e:
            return JSONResponse(
                status_code=401,
                content={"detail": f"Invalid token: {e}"},
            )

        return await call_next(request)
