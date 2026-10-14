# Security Incident Detection and Response Management System

Shared backend foundation for nine independent Flask services. Each service has its own process and port, communicates with peers over HTTP, and uses the same SQLAlchemy models and database. Business endpoints are intentionally not implemented yet; only `GET /health` is available on each service.

## Requirements

- Python 3.11
- pip

## Install

```sh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
```

Set a private random `JWT_SECRET` in `.env` before using shared environments. If `DATABASE_URL` is not set, the database is created at `database/security_incidents.db`. Set `DATABASE_URL` to override it.

Install the Playwright browser once for evidence screenshots:

```sh
python -m playwright install chromium
```

## Seed the database

```sh
python -m database.seed
```

Use `python -m database.seed --reset` to drop and recreate all tables and users. Development credentials are `admin/Admin@1234`, `analyst/Analyst@1234`, `employee/Employee@1234`, `auditor/Auditor@1234`, `analyst2/Analyst@1234`, `employee2/Employee@1234`, and `suspended/Suspended@1234`. Passwords are stored as bcrypt hashes. Keep these development credentials out of deployed environments.

## Run services

```sh
python run_all.py
```

This starts independent apps on `127.0.0.1`: users `5001`, assets `5002`, incidents `5003`, threats `5004`, logs `5005`, reports `5006`, vulnerabilities `5007`, notifications `5008`, and playbooks `5009`. Stop all services with `Ctrl+C`.

For example, check health with `curl http://127.0.0.1:5001/health`. Responses use the shared JSON success/error envelopes. Service URLs can be overridden with `<SERVICE>_SERVICE_URL` environment variables.

## Development tokens

The login route is not implemented yet. Mint a two-hour JWT for a seeded active user with:

```sh
python -m scripts.dev_token analyst
```

The token is printed to standard output. Suspended users cannot receive a development token. Internal service calls use short-lived tokens with the `Service` role.

## Evidence tooling

With all services running, capture a screenshot of each real health request:

```sh
python -m scripts.evidence.self_test "Haya Karanouh"
```

Evidence is written beneath `evidence/<Full_Name_with_underscores>/`; numbered PNGs are accompanied by `captions.md`. `EvidenceRecorder.api` sends a real request before capturing its status, elapsed time, and response. `EvidenceRecorder.db` permits read-only parameterized SQLite queries. `EvidenceRecorder.text` captures supplied command output. No response or query result is synthesized by the recorder.

The `scripts.evidence.login(username, password)` helper uses `POST /users/login` when it exists. For a 404 response only, it warns and falls back to `scripts.dev_token`; this fallback checks that the requested seeded account is active.
