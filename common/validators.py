"""Reusable request validation primitives."""

import ipaddress
import re

from flask import request

from common.errors import ValidationError

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_HASH_LENGTHS = {32, 40, 64}


def require_json_body(allowed_fields=None):
    """Return a non-empty JSON object with trimmed string values."""
    if not request.is_json:
        raise ValidationError("Request body must be JSON")
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        raise ValidationError("Request body must be a non-empty JSON object")
    cleaned = {key: value.strip() if isinstance(value, str) else value for key, value in data.items()}
    if allowed_fields is not None:
        unexpected = set(cleaned) - set(allowed_fields)
        if unexpected:
            raise ValidationError(f"Unexpected fields: {', '.join(sorted(unexpected))}")
    return cleaned


def require_fields(data, required, allowed_fields=None):
    """Reject missing required fields and, when specified, unknown fields."""
    missing = [field for field in required if field not in data or data[field] in (None, "")]
    if missing:
        raise ValidationError(f"Missing required fields: {', '.join(missing)}")
    if allowed_fields is not None:
        unexpected = set(data) - set(allowed_fields)
        if unexpected:
            raise ValidationError(f"Unexpected fields: {', '.join(sorted(unexpected))}")
    return data


def valid_email(value):
    return isinstance(value, str) and bool(_EMAIL_RE.fullmatch(value.strip()))


def valid_ipv4(value):
    try:
        return isinstance(value, str) and ipaddress.ip_address(value.strip()).version == 4
    except ValueError:
        return False


def valid_domain(value):
    if not isinstance(value, str):
        return False
    domain = value.strip().rstrip(".")
    labels = domain.split(".")
    return len(domain) <= 253 and len(labels) >= 2 and all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def valid_hash(value):
    return isinstance(value, str) and len(value) in _HASH_LENGTHS and bool(re.fullmatch(r"[0-9a-fA-F]+", value))


def valid_enum(value, values):
    return value in values


def strong_password(value):
    return (
        isinstance(value, str)
        and len(value) >= 8
        and any(char.isupper() for char in value)
        and any(char.islower() for char in value)
        and any(char.isdigit() for char in value)
    )


def valid_cve(value):
    return isinstance(value, str) and bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", value))


def valid_cvss(value):
    if isinstance(value, bool):
        return False
    try:
        score = float(value)
        return 0.0 <= score <= 10.0
    except (TypeError, ValueError):
        return False
