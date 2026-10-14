# Security Incident Detection and Response Management System

Backend foundation for nine independent Flask services. Each service has its own process and port, communicates with peers over HTTP, and uses the same SQLAlchemy models and database. Users, Audit Logs, and Notifications endpoints are implemented; the other services currently expose only `GET /health`.

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

Use the real `POST /users/login` route for normal testing. Mint a two-hour JWT for a seeded active user when testing an isolated service with:

```sh
python -m scripts.dev_token analyst
```

The token is printed to standard output. Suspended users cannot receive a development token. Internal service calls use short-lived tokens with the `Service` role.

## Implemented endpoints

All endpoints use the standard success/error JSON envelopes. Authenticated calls use `Authorization: Bearer <token>`.

Users (`5001`):

- `POST /users/register` and `POST /users/login` are public. Non-admin registrations are always Regular Employee accounts.
- `GET /users` and `GET /users/{username}` are available to Security Administrators and Auditors. Employees may retrieve only their own username record. The collection supports `?role=`.
- `PUT /users/{id}` is available to Administrators for any account and employees for their own profile. `DELETE /users/{id}` is Administrator-only and returns 409 if records still reference the account.

Audit Logs (`5005`):

- `POST /logs` is available to Administrators and internal Service tokens.
- `GET /logs` is available to Administrators and Auditors; `GET /logs/{id}` and `GET /logs/search` also allow Analysts.
- `GET /logs/user/{user_id}` is available to Administrators and Auditors. `DELETE /logs/{id}` is Administrator-only. Logs cannot be updated; PUT/PATCH return 405.
- Search filters are `user_id`, `date` (`YYYY-MM-DD`), `action`, `severity`, and `related_service`; supplied filters combine with AND.

Notifications (`5008`):

- `POST /notifications` is available to Administrators and internal Service tokens; recipients are verified through Users.
- `GET /notifications/user/{user_id}` and `GET /notifications/{id}` allow Administrators/Auditors to access any user and Analysts/Employees to access their own.
- `PUT /notifications/{id}/read` allows Administrators, Analysts, and Employees, subject to owner checks. `GET /notifications/search` allows Administrators, Analysts, and Auditors. `DELETE /notifications/{id}` is Administrator-only.

The Postman collection is [postman/HayaKaranouh.postman_collection.json](postman/HayaKaranouh.postman_collection.json). Run its Authentication and token setup folder first; it saves JWTs as collection variables. Each implemented endpoint has success, validation, not-found/empty-result, wrong-role, and missing-token examples, with explanations where a category does not apply to a collection or bodyless route.

## Evidence tooling

With all services running, capture a screenshot of each real health request:

```sh
python -m scripts.evidence.self_test "Haya Karanouh"
```

To reset and seed the database, verify all nine services, and capture the Users, Audit Logs, Notifications, authentication, and Git history scenarios, run:

```sh
python -m scripts.evidence.haya_karanouh_evidence
```

Evidence is written beneath `evidence/<Full_Name_with_underscores>/`; numbered PNGs are accompanied by `captions.md`. `EvidenceRecorder.api` sends a real request before capturing its status, elapsed time, and response. `EvidenceRecorder.db` permits read-only parameterized SQLite queries. `EvidenceRecorder.text` captures supplied command output. No response or query result is synthesized by the recorder.

The `scripts.evidence.login(username, password)` helper uses `POST /users/login` when it exists. For a 404 response only, it warns and falls back to `scripts.dev_token`; this fallback checks that the requested seeded account is active.
