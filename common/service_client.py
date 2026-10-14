"""HTTP helpers for service-to-service calls."""

import requests

from common.config import SERVICE_URLS
from common.constants import SERVICE


def _service_token():
    from common.auth import create_token

    return create_token({"id": None, "username": "internal-service", "role": SERVICE})


def call_service(method, service, path, json=None, params=None):
    """Call another service with a short-lived internal SERVICE JWT."""
    if service not in SERVICE_URLS:
        raise ValueError(f"Unknown service: {service}")
    url = f"{SERVICE_URLS[service].rstrip('/')}/{path.lstrip('/')}"
    return requests.request(
        method.upper(), url, headers={"Authorization": f"Bearer {_service_token()}"},
        json=json, params=params, timeout=5,
    )


def log_event(user_id, action, description, severity, related_service):
    """Best-effort log submission; logging outages never break the caller."""
    try:
        return call_service("POST", "logs", "/logs", json={
            "user_id": user_id, "action": action, "description": description,
            "severity": severity, "related_service": related_service,
        })
    except Exception:
        return None


def notify(user_id, title, message, notification_type, severity):
    """Best-effort notification submission; outages never break the caller."""
    try:
        return call_service("POST", "notifications", "/notifications", json={
            "user_id": user_id, "title": title, "message": message,
            "notification_type": notification_type, "severity": severity,
        })
    except Exception:
        return None
