"""Environment-backed configuration shared by every service."""

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")

DATABASE_DIR = PROJECT_ROOT / "database"
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_DATABASE_URL = f"sqlite:///{(DATABASE_DIR / 'security_incidents.db').as_posix()}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
JWT_SECRET = os.getenv("JWT_SECRET", "development-only-secret-change-me-435l")
JWT_ALGORITHM = "HS256"

SERVICE_PORTS = {
    "users": 5001,
    "assets": 5002,
    "incidents": 5003,
    "threats": 5004,
    "logs": 5005,
    "reports": 5006,
    "vulnerabilities": 5007,
    "notifications": 5008,
    "playbooks": 5009,
}
SERVICE_URLS = {
    name: os.getenv(f"{name.upper()}_SERVICE_URL", f"http://127.0.0.1:{port}")
    for name, port in SERVICE_PORTS.items()
}
