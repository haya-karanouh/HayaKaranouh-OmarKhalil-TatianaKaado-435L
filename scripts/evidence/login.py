"""Login through the users API, falling back to a seeded development token."""

import subprocess
import sys

import requests

from common.config import PROJECT_ROOT, SERVICE_URLS


def login(username, password):
    """Return a real login token or use dev_token while login is unimplemented."""
    response = requests.post(
        f"{SERVICE_URLS['users'].rstrip('/')}/users/login",
        json={"username": username, "password": password}, timeout=10,
    )
    if response.status_code == 404:
        print("Warning: users login route is not implemented; using a development token.", file=sys.stderr)
        result = subprocess.run(
            [sys.executable, "-m", "scripts.dev_token", username],
            cwd=PROJECT_ROOT, check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()
    response.raise_for_status()
    payload = response.json()
    token = payload.get("data", {}).get("token")
    if not token:
        raise ValueError("Login response did not include data.token")
    return token
