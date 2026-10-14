"""JWT creation and role-based request authorization."""

from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, request

from common.config import JWT_ALGORITHM, JWT_SECRET
from common.constants import SERVICE, UNAUTHORIZED_ACCESS
from common.errors import error_response


def _user_value(user, key):
    return user.get(key) if isinstance(user, dict) else getattr(user, key)


def create_token(user):
    """Create a two-hour JWT for a user-like object or mapping."""
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": _user_value(user, "id"),
        "username": _user_value(user, "username"),
        "role": _user_value(user, "role"),
        "iat": now,
        "exp": now + timedelta(hours=2),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def require_roles(*roles):
    """Require a valid bearer token whose role is allowed by the route."""
    def decorator(route_function):
        @wraps(route_function)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token:
                return error_response("Missing or invalid bearer token", 401)
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                if not all(key in payload for key in ("user_id", "username", "role")):
                    raise jwt.InvalidTokenError("Required claims are missing")
            except jwt.PyJWTError:
                return error_response("Invalid or expired token", 401)

            if payload["role"] != SERVICE and payload["role"] not in roles:
                try:
                    from common.service_client import log_event

                    log_event(
                        payload.get("user_id"), UNAUTHORIZED_ACCESS,
                        f"Role {payload['role']} denied access to {request.method} {request.path}",
                        "Warning", request.blueprint or "unknown",
                    )
                except Exception:
                    pass
                return error_response("You do not have permission to access this resource", 403)

            g.user = payload
            return route_function(*args, **kwargs)

        return wrapped
    return decorator
