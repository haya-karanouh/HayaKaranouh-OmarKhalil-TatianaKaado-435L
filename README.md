# Security Incident Detection and Response Management System

Backend foundation for nine independent Flask services. Each service has its own process and port, communicates with peers over HTTP, and uses the same SQLAlchemy models and database. Users, Assets, Incidents, Audit Logs, Notifications, and Playbooks endpoints are implemented; Threats, Reports, and Vulnerabilities currently expose only `GET /health`.

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

### Omar Khalil: Assets, Incidents and Playbooks

Assets (`5002`) support administrator creation, update and deletion; administrator/auditor listing; and administrator/analyst/auditor detail and search. Creation validates IPv4, asset type, criticality and status, and verifies the owner through Users over HTTP. Location is optional and defaults to `Unspecified`. Search supports partial `name` and exact `asset_type`, `ip_address`, `department`, `criticality`, combined with AND. Details retrieve incident IDs and vulnerabilities over HTTP; unavailable related endpoints return empty lists. Deleting a referenced asset returns 409.

Incidents (`5003`) support administrator/employee creation with reporter identity from the JWT, administrator/auditor listing with an optional `asset_id` filter, and details restricted by assignment or reporter ownership. Administrators assign verified Security Analysts with `PUT /incidents/{id}/assign`. Administrators and assigned analysts advance `PUT /incidents/{id}/status` through `Open → Under Investigation → Mitigated → Resolved → Closed`, and add `POST /incidents/{id}/notes`. Skips, backwards moves and terminal-state repeats return 422 with the allowed next status. Resolution sets `resolved_at`; assignment notifies the analyst and transitions notify the reporter.

Playbooks (`5009`) support administrator creation/deletion and administrator/analyst/auditor listing/details. Administrators and analysts add `POST /playbooks/{id}/actions` with positive, unique step numbers (duplicates return 409), and advance `PUT /actions/{id}/status` through `Pending → In Progress → Completed`. Lower steps must be Completed before an action starts, and completion sets `completed_at`. Playbook deletion cascades to actions; audit events preserve execution history.

All mutation routes submit audit events through the shared HTTP logging helper. Seed data includes four assets, incidents at all four severities, and two playbooks with three actions each. Re-running the seed inserts no duplicate sample records.

Import [postman/OmarKhalil.postman_collection.json](postman/OmarKhalil.postman_collection.json) and run its folders in order against the seeded database. It logs in each role, saves fresh IDs, covers all 18 endpoints and includes independent full incident and playbook workflows. Bodyless and collection endpoints explain when an input-validation or missing-record case is inapplicable.

With all services running, run the HTTP regression checks and replay the collection:

```sh
python -m scripts.omar_http_checks --service assets
python -m scripts.omar_http_checks --service incidents
python -m scripts.omar_http_checks --service playbooks
python -m scripts.check_omar_postman
```

Capture Omar's evidence with `python -m scripts.evidence.omar_khalil_evidence`. It checks all nine health endpoints before resetting/seeding the development database, logs in through the real login API, and asserts actual HTTP status codes before continuing. Screenshots and two-sentence explanations are written to `evidence/Omar_Khalil/`, including every table's structure/foreign keys and authored Git history. Repeated captures append numbered images, so use a fresh output folder if only one run is desired.

### Tatiana Kaado: Threat Intelligence, Vulnerabilities and Reports

Threat Intelligence (`5004`) exposes POST/GET `/threats`, GET/PUT/DELETE `/threats/{id}`, and GET `/threats/search`. Administrators mutate indicators; administrators, analysts and auditors read them. IPv4, domain and MD5/SHA1/SHA256 values use the shared validators. Domain and hash values are normalized to lowercase, duplicate type/value pairs return 409, and updates permit only description, severity and source. Search combines exact type/severity/source and literal partial value filters with AND.

Vulnerabilities (`5007`) exposes the equivalent six `/vulnerabilities` endpoints. Administrators create/delete, administrators and analysts update, and administrators/analysts/auditors read. Asset existence, name and status come from the assets API. CVSS must match severity: below 4 Low, below 7 Medium, below 9 High, otherwise Critical through 10. Score 0 uses Low because the shared enum has no None severity. Explicit status updates must advance exactly one step through Open, Under Investigation, In Progress, Resolved and Closed. Entering Resolved automatically sets `resolved_at`; subsequent resolution-date edits accept an ISO timestamp between creation and now, only for Resolved/Closed findings.

Reports (`5006`) exposes GET `/reports/summary`, `/reports/incidents`, `/reports/assets`, `/reports/threats`, `/reports/vulnerabilities` and `/reports/activity` to administrators and auditors only, including rejection of internal Service tokens. Data is collected exclusively through `call_service`; unavailable sources return 503. Summary open incidents include all statuses except Resolved and Closed. Activity counts LOGIN_SUCCESS plus LOGIN_FAILED as attempts and returns the five most frequent actions, with alphabetical tie-breaking. Reports log REPORT_GENERATED after collecting their data, so activity/recent-log results exclude their own generation event.

All mutations use `log_event`. Critical creation or escalation retrieves administrators using the users API's role filter and calls the shared notification helper for each recipient; logging and notification delivery retain the foundation's best-effort behavior. The idempotent Tatiana seed runs after the existing seeds and covers all threat types, severities and vulnerability statuses. No `common/` changes are required.

Import [Tatiana's Postman collection](postman/TatianaKaado.postman_collection.json) and run folders in order. Its 124 requests save role tokens and created IDs, assert expected statuses and cover each endpoint; collection endpoints use unknown child routes for 404 examples because empty collections return 200. Malformed JSON provides 400 validation examples for bodyless threat/vulnerability routes.

```sh
python -m scripts.tatiana_http_checks threats
python -m scripts.tatiana_http_checks vulnerabilities
python -m scripts.tatiana_http_checks reports
python -m scripts.check_tatiana_postman
python -m scripts.evidence.tatiana_kaado_evidence --outage
```

The evidence command requires all services running via `run_all.py`, then resets/seeds the development database, logs in through the real API and creates successful/failed login activity. It saves screenshots and two- or three-sentence explanations in `evidence/Tatiana_Kaado/` and asserts report totals against independent SQL queries. Optional `--outage` briefly pauses the verified local assets process on port 5002 and always resumes it in a finally block to demonstrate a real 503. Captures append numbered images; use a fresh output folder for a single run. The recorder falls back to installed Chrome when bundled Chromium is unavailable.

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
