"""Capture real evidence for the Users, Audit Logs, and Notifications APIs."""

from datetime import datetime, timezone
import subprocess
import sys
import uuid

import requests

from common.config import PROJECT_ROOT, SERVICE_PORTS, SERVICE_URLS
from scripts.evidence import EvidenceRecorder
from scripts.evidence.login import login


RECORDER = EvidenceRecorder("Haya Karanouh")


def caption(title, what):
    return f"Haya Karanouh – {title} – {what}"


def capture_api(title, what, explanation, service, method, path, expected, token=None, body=None, params=None):
    response = RECORDER.api(
        caption(title, what), method,
        f"{SERVICE_URLS[service].rstrip('/')}/{path.lstrip('/')}",
        token=token, json=body, params=params, explanation=explanation,
    )
    if response.status_code != expected:
        raise AssertionError(
            f"{method} {service}/{path}: expected HTTP {expected}, got {response.status_code}: {response.text}"
        )
    return response


def capture_db(title, what, explanation, sql, params=()):
    return RECORDER.db(caption(title, what), sql, params, explanation=explanation)


def token_from_login(role, username, password):
    response = capture_api(
        f"Login - {role}", "authenticate and return a role JWT",
        f"This request authenticates the seeded {role} account through the real login endpoint. Its response contains the live token and account summary used by subsequent API calls.",
        "users", "POST", "/users/login", 200,
        body={"username": username, "password": password},
    )
    token = response.json()["data"]["token"]
    if not token:
        raise AssertionError(f"Login for {role} returned no token")
    return token


def run_health_preflight():
    failures = []
    for service in SERVICE_PORTS:
        try:
            response = requests.get(f"{SERVICE_URLS[service].rstrip('/')}/health", timeout=3)
            if response.status_code != 200:
                failures.append(f"{service}: HTTP {response.status_code}")
        except requests.RequestException as error:
            failures.append(f"{service}: {error}")
    if failures:
        print(
            "Evidence stopped before database reset. Start all nine services with `python run_all.py`; "
            "health checks failed for: " + "; ".join(failures),
            file=sys.stderr,
        )
        return False
    print("All nine service health checks passed.")
    return True


def seed_database():
    result = subprocess.run(
        [sys.executable, "-m", "database.seed", "--reset"],
        cwd=PROJECT_ROOT, check=True, capture_output=True, text=True,
    )
    print(result.stdout.strip())


def run_evidence():
    if not run_health_preflight():
        return 2
    seed_database()

    for service in SERVICE_PORTS:
        response = requests.get(f"{SERVICE_URLS[service].rstrip('/')}/health", timeout=5)
        image_caption = f"Haya Karanouh – Health - {service.title()} – verify a live service after reset"
        RECORDER.api(
            image_caption, "GET", f"{SERVICE_URLS[service].rstrip('/')}/health",
            explanation=f"This real request confirms the {service} service is still available after seeding. The evidence records the live HTTP status and response body.",
        )
        if response.status_code != 200:
            raise AssertionError(f"{service} health changed after seed: HTTP {response.status_code}")

    # The helper itself performs a real POST /users/login; the screenshots below preserve each response too.
    helper_token = login("admin", "Admin@1234")
    if not helper_token:
        raise AssertionError("Evidence login helper returned an empty token")
    tokens = {
        "admin": token_from_login("Security Administrator", "admin", "Admin@1234"),
        "analyst": token_from_login("Security Analyst", "analyst", "Analyst@1234"),
        "employee": token_from_login("Regular Employee", "employee", "Employee@1234"),
        "auditor": token_from_login("Auditor", "auditor", "Auditor@1234"),
    }
    auth = {role: {"Authorization": f"Bearer {value}"} for role, value in tokens.items()}

    # Users: registration, validation, authentication, profile changes, reads, and deletion.
    suffix = uuid.uuid4().hex[:10]
    new_username = f"evidence-{suffix}"
    registration = {
        "full_name": "Evidence Registration",
        "username": new_username,
        "email": f"{new_username}@example.com",
        "password": "EvidencePass1",
        "department": "Evidence Lab",
        "role": "Security Analyst",
    }
    created = capture_api(
        "Users Register", "create a public user and force non-admin role",
        "The request creates a real account through the public registration route. Because no administrator token is supplied, the server assigns Regular Employee instead of the requested analyst role.",
        "users", "POST", "/users/register", 201, body=registration,
    ).json()["data"]
    new_user_id = created["id"]
    user_table = capture_db(
        "Users Table", "verify the new account stores a bcrypt hash",
        "This read-only query retrieves the inserted account from the shared database. The password column contains only the bcrypt hash, never the submitted password.",
        "SELECT id, full_name, username, email, role, account_status, password_hash FROM users WHERE username = ?",
        (new_username,),
    )
    if len(user_table) != 1 or user_table[0]["password_hash"] == registration["password"]:
        raise AssertionError("The registered password was not stored as a hash")

    capture_api(
        "Users Register - Duplicate username", "reject an existing username with 409",
        "This request repeats the successful registration using the same unique username and email. The service checks duplicates before insertion and returns a conflict rather than creating a second account.",
        "users", "POST", "/users/register", 409, body=registration,
    )
    capture_api(
        "Users Register - Invalid email", "reject malformed email input",
        "The email validator rejects this malformed address before a user row is written. The response explains the validation failure with HTTP 422.",
        "users", "POST", "/users/register", 422,
        body={**registration, "username": f"bad-email-{suffix}", "email": "not-an-email"},
    )
    capture_api(
        "Users Register - Weak password", "require a strong password",
        "The supplied password lacks the required strength characteristics. Registration returns a validation error and does not persist the account.",
        "users", "POST", "/users/register", 422,
        body={**registration, "username": f"weak-{suffix}", "email": f"weak-{suffix}@example.com", "password": "weak"},
    )
    capture_api(
        "Users Register - Missing fields", "reject a request missing department",
        "The request omits a required registration field while keeping the remaining values valid. The required-field validator identifies the incomplete payload and returns HTTP 422.",
        "users", "POST", "/users/register", 422,
        body={key: value for key, value in registration.items() if key != "department"},
    )
    capture_api(
        "Users Register - Empty body", "reject a request with no JSON body",
        "This real request has no JSON body, so it cannot satisfy the registration contract. The API rejects it with HTTP 422 rather than creating an empty user.",
        "users", "POST", "/users/register", 422,
    )

    capture_api(
        "Users Login - Wrong password", "reject invalid credentials and log the failure",
        "The username exists, but the supplied password does not match its bcrypt hash. The API returns HTTP 401 and submits a LOGIN_FAILED audit event.",
        "users", "POST", "/users/login", 401,
        body={"username": "admin", "password": "WrongPassword1"},
    )
    capture_api(
        "Users Login - Suspended account", "deny a suspended account",
        "The password is valid for the seeded suspended account, but its account status is not Active. Login is denied with HTTP 403 and recorded as a failed login event.",
        "users", "POST", "/users/login", 403,
        body={"username": "suspended", "password": "Suspended@1234"},
    )

    user_list_response = capture_api(
        "Users List", "return the user collection without password hashes",
        "The collection response is an object containing a users array with public account summaries. Password hashes are excluded from every serialized user record.",
        "users", "GET", "/users", 200, token=tokens["admin"],
    )
    listed_users = user_list_response.json()["data"]["users"]
    user_ids = {user["username"]: user["id"] for user in listed_users}
    if any("password_hash" in user for user in listed_users):
        raise AssertionError("GET /users exposed a password hash")
    admin_id = user_ids["admin"]
    employee_id = user_ids["employee"]
    analyst_id = user_ids["analyst"]
    employee2_id = user_ids["employee2"]

    capture_db(
        "Users Update - Before", "inspect the employee row before the update",
        "This parameterized read captures the real employee profile before mutation. The department value provides a direct database baseline for the following API update.",
        "SELECT id, full_name, email, department, role, account_status FROM users WHERE id = ?",
        (employee_id,),
    )
    capture_api(
        "Users Update", "change a user's department as an administrator",
        "The administrator changes the seeded employee department through the public API. The server persists the profile update and records USER_UPDATED in the audit service.",
        "users", "PUT", f"/users/{employee_id}", 200, token=tokens["admin"],
        body={"department": "Evidence Lab"},
    )
    capture_db(
        "Users Update - After", "verify the updated employee row",
        "This second read uses the same user ID after the API mutation. It demonstrates that the department change was committed to the shared database.",
        "SELECT id, full_name, email, department, role, account_status FROM users WHERE id = ?",
        (employee_id,),
    )
    capture_api(
        "Users Update - Employee another user", "deny an employee updating another account",
        "The employee token does not own the administrator account in the URL. The ownership check denies the request with HTTP 403 before any profile changes occur.",
        "users", "PUT", f"/users/{admin_id}", 403, token=tokens["employee"],
        body={"department": "Not Allowed"},
    )
    capture_api(
        "Users Delete", "delete the newly registered unreferenced user",
        "The administrator deletes the disposable account created earlier in this evidence run. Its ID is retained from the real registration response, and the operation is audited.",
        "users", "DELETE", f"/users/{new_user_id}", 200, token=tokens["admin"],
    )
    capture_api(
        "Users Delete - Analyst", "deny deletion by an analyst",
        "The request is authenticated as an analyst rather than an administrator. Role authorization returns HTTP 403 and the account remains unchanged.",
        "users", "DELETE", f"/users/{employee_id}", 403, token=tokens["analyst"],
    )
    capture_api(
        "Users Get - Existing", "retrieve a password-free user by username",
        "An administrator requests the seeded employee by username. The API returns the public account fields and omits the password hash.",
        "users", "GET", "/users/employee", 200, token=tokens["admin"],
    )
    capture_api(
        "Users Get - Non-existing", "return 404 for an unknown username",
        "The username does not match any persisted account. The lookup returns a structured 404 response instead of an empty or fabricated user object.",
        "users", "GET", "/users/no-such-evidence-user", 404, token=tokens["admin"],
    )
    capture_api(
        "Users Get - Missing token", "reject private user listing without a token",
        "This request omits the Authorization header while targeting a protected collection. The authentication decorator returns HTTP 401 before user records are serialized.",
        "users", "GET", "/users", 401,
    )

    # Authentication and Authorization evidence for report section IV.
    capture_api(
        "Authentication - Insufficient permissions", "show a denied call to the users collection",
        "A regular employee calls the same protected collection endpoint used by an administrator. The role check returns HTTP 403 and emits UNAUTHORIZED_ACCESS to Audit Logs.",
        "users", "GET", "/users", 403, token=tokens["employee"],
    )
    capture_api(
        "Authentication - Correct permissions", "repeat the same API with administrator access",
        "The administrator calls the exact same users collection endpoint and receives HTTP 200. Comparing this response with the preceding denial demonstrates role-based access control.",
        "users", "GET", "/users", 200, token=tokens["admin"],
    )
    capture_db(
        "Authentication - Automatic audit records", "show failed-login and denied-access events",
        "This read-only query selects the LOGIN_FAILED and UNAUTHORIZED_ACCESS rows created by the real requests above. The table shows their actor, severity, related service, and server timestamp.",
        "SELECT id, user_id, action, description, severity, timestamp, related_service FROM logs WHERE action IN (?, ?) ORDER BY id",
        ("LOGIN_FAILED", "UNAUTHORIZED_ACCESS"),
    )

    # Audit Logs: records originate from logins, user activity, denied access, and this manual POST.
    manual_log_body = {
        "user_id": admin_id,
        "action": "DATA_CREATED",
        "description": "Manual evidence audit event",
        "severity": "Information",
        "related_service": "users",
    }
    manual_log = capture_api(
        "Audit Logs POST", "create a manual audit record directly through Logs",
        "An administrator posts a valid manual audit record with a nullable-capable user reference. The Logs service writes it directly to the shared database and supplies the timestamp.",
        "logs", "POST", "/logs", 201, token=tokens["admin"], body=manual_log_body,
    ).json()["data"]
    manual_log_id = manual_log["id"]
    capture_db(
        "Audit Logs Table", "inspect login, user, denied-access, and manual log entries",
        "The query returns real audit records generated by logins, user changes, authorization failures, and the manual POST. The table columns show the actor, action, severity, timestamp, and related service.",
        "SELECT id, user_id, action, description, timestamp, severity, related_service FROM logs ORDER BY id",
    )
    all_logs = capture_api(
        "Audit Logs GET", "retrieve the complete audit collection",
        "An administrator reads the current audit collection after the activity above. The response contains the persisted log summaries in reverse chronological order.",
        "logs", "GET", "/logs", 200, token=tokens["admin"],
    ).json()["data"]["logs"]
    other_log = next((item for item in all_logs if item["id"] != manual_log_id), None)
    if other_log is None:
        raise AssertionError("Expected other activity-generated audit records")
    capture_api(
        "Audit Logs GET - Existing", "retrieve the manually created log by ID",
        "This request looks up the ID returned by the successful manual POST. The response contains the same stored action and description, demonstrating the detail representation.",
        "logs", "GET", f"/logs/{manual_log_id}", 200, token=tokens["admin"],
    )
    capture_api(
        "Audit Logs GET - Invalid ID", "return 404 for a nonexistent log",
        "The selected ID is not present in the logs table. The API reports HTTP 404 with the standard error envelope.",
        "logs", "GET", "/logs/999999", 404, token=tokens["admin"],
    )
    today = datetime.now(timezone.utc).date().isoformat()
    searches = [
        ("by user", {"user_id": str(admin_id)}, "The user_id filter selects records attributed to the administrator. It can be combined with other filters, which are joined with AND."),
        ("by date", {"date": today}, "The date filter matches records whose server timestamp falls on today's UTC date. The request uses the required YYYY-MM-DD format."),
        ("by action", {"action": "LOGIN_SUCCESS"}, "The action filter selects successful authentication events from the standard action list. The returned rows are actual persisted audit records."),
        ("by severity", {"severity": "Warning"}, "The severity filter selects warning-level audit records, including failed authentication and denied access. It accepts only the supported log severity values."),
        ("by service", {"related_service": "users"}, "The service filter selects events associated with the Users service. The value is validated against the configured service names."),
    ]
    for label, params, explanation in searches:
        capture_api(
            f"Audit Logs Search - {label.title()}", f"search audit records {label}",
            explanation,
            "logs", "GET", "/logs/search", 200, token=tokens["auditor"], params=params,
        )
    capture_api(
        "Audit Logs User - With records", "retrieve the administrator's audit history",
        "The administrator has login, user-management, and manual audit activity associated with the account. This endpoint returns those records in a successful user-scoped response.",
        "logs", "GET", f"/logs/user/{admin_id}", 200, token=tokens["auditor"],
    )
    capture_api(
        "Audit Logs User - No records", "show the empty audit history for employee2",
        "The seeded employee2 account has not generated any audit events during this run. The endpoint returns HTTP 200 with an empty logs array and an explicit no-records message.",
        "logs", "GET", f"/logs/user/{employee2_id}", 200, token=tokens["admin"],
    )
    capture_api(
        "Audit Logs Delete - Analyst", "deny an analyst deleting an audit record",
        "The target log exists, but the caller is an analyst rather than an administrator. The authorization check returns HTTP 403 and logs the denied attempt.",
        "logs", "DELETE", f"/logs/{other_log['id']}", 403, token=tokens["analyst"],
    )
    capture_api(
        "Audit Logs PUT - Immutable", "show that audit records cannot be updated",
        "The request attempts to alter the manual record through an unsupported PUT method. Routing returns HTTP 405, leaving the immutable audit row untouched.",
        "logs", "PUT", f"/logs/{manual_log_id}", 405, token=tokens["admin"],
        body={"description": "Attempted tamper"},
    )
    unchanged = capture_api(
        "Audit Logs GET - Unchanged", "verify the immutable log retained its original description",
        "The manual record is fetched again after the rejected PUT attempt. Its original description proves that no update was applied.",
        "logs", "GET", f"/logs/{manual_log_id}", 200, token=tokens["admin"],
    ).json()["data"]
    if unchanged["description"] != manual_log_body["description"]:
        raise AssertionError("A log changed despite the 405 response")
    capture_api(
        "Audit Logs Delete - Admin", "delete the manual log as an administrator",
        "An administrator deletes the manual log created earlier in this run. The endpoint permits deletion but records a separate DATA_DELETED event for the audit trail.",
        "logs", "DELETE", f"/logs/{manual_log_id}", 200, token=tokens["admin"],
    )

    # Notifications: real cross-service recipient checks and data changes.
    notification_specs = [
        ("Admin Threat Alert", admin_id, "Threat Alert", "Critical"),
        ("Analyst Incident Assignment", analyst_id, "Incident Assignment", "Medium"),
        ("Employee Vulnerability Alert", employee_id, "Vulnerability Alert", "High"),
        ("Employee Read State", employee_id, "System Notification", "Low"),
        ("Employee Delete State", employee_id, "Security Alert", "Medium"),
    ]
    notifications = {}
    for title, recipient_id, notification_type, severity in notification_specs:
        body = {
            "user_id": recipient_id,
            "title": title,
            "message": f"Evidence scenario for {title}",
            "notification_type": notification_type,
            "severity": severity,
        }
        created_notification = capture_api(
            f"Notifications POST - {title}", "create an unread notification for a real user",
            "The administrator creates a notification for a seeded recipient. The service verifies that user through the Users API, persists Unread status, and emits a log event.",
            "notifications", "POST", "/notifications", 201,
            token=tokens["admin"], body=body,
        ).json()["data"]
        notifications[title] = created_notification
    capture_db(
        "Notifications Table", "inspect the created notification rows",
        "This read-only query displays the notification rows created by real POST requests. It includes recipient, type, severity, status, and read timestamp so each persisted state is visible.",
        "SELECT id, user_id, title, notification_type, severity, status, created_at, read_at FROM notifications ORDER BY id",
    )
    capture_api(
        "Notifications User - Existing", "list notifications for the administrator",
        "An administrator requests notifications for a valid recipient account. The response contains that user's actual notifications, including the alert created above.",
        "notifications", "GET", f"/notifications/user/{admin_id}", 200, token=tokens["admin"],
    )
    capture_api(
        "Notifications User - Empty", "show an empty result for employee2",
        "Employee2 has no notifications in this seeded evidence run. The API treats this as a valid HTTP 200 response with an empty notifications array.",
        "notifications", "GET", f"/notifications/user/{employee2_id}", 200, token=tokens["admin"],
    )
    admin_notification_id = notifications["Admin Threat Alert"]["id"]
    capture_api(
        "Notifications GET - Existing", "retrieve a specific existing notification",
        "The request retrieves the ID returned by the real notification creation response. The API returns its stored recipient, status, and notification fields.",
        "notifications", "GET", f"/notifications/{admin_notification_id}", 200, token=tokens["admin"],
    )
    capture_api(
        "Notifications GET - Invalid ID", "return 404 for a missing notification",
        "The supplied notification ID does not exist in the database. The service returns its standard structured 404 response.",
        "notifications", "GET", "/notifications/999999", 404, token=tokens["admin"],
    )
    read_id = notifications["Employee Read State"]["id"]
    capture_db(
        "Notifications Read - Before", "inspect the unread notification before mutation",
        "This query captures the selected employee notification before the read action. Its status is Unread and its read_at value is null before the API transition.",
        "SELECT id, user_id, title, status, read_at FROM notifications WHERE id = ?",
        (read_id,),
    )
    capture_api(
        "Notifications Mark Read", "mark the employee's notification as read",
        "The employee updates an owned notification through the read endpoint. The service sets status to Read, records read_at, and creates a STATUS_CHANGED audit event.",
        "notifications", "PUT", f"/notifications/{read_id}/read", 200, token=tokens["employee"],
    )
    capture_db(
        "Notifications Read - After", "verify Read status and timestamp after mutation",
        "The same notification row is selected after the real PUT request. Its status and read_at values demonstrate the persisted transition.",
        "SELECT id, user_id, title, status, read_at FROM notifications WHERE id = ?",
        (read_id,),
    )
    capture_api(
        "Notifications Mark Read - Idempotent", "repeat the read request without changing its timestamp",
        "The notification is already Read, so the second request returns an idempotent message. The existing read_at timestamp is preserved instead of being overwritten.",
        "notifications", "PUT", f"/notifications/{read_id}/read", 200, token=tokens["employee"],
    )
    notification_searches = [
        ("by user", {"user_id": str(employee_id)}, "The user filter selects notifications belonging to the seeded employee. User, type, severity, and status constraints combine with AND."),
        ("by type", {"notification_type": "Threat Alert"}, "The notification type filter returns matching threat alerts. Values are checked against the shared notification-type list."),
        ("by severity", {"severity": "High"}, "The severity filter selects high-severity notifications. The result comes from the shared database and includes only matching rows."),
        ("by status", {"status": "Unread"}, "The status filter selects notifications not yet marked Read. The read-state transition above changes which records can match this query."),
    ]
    for label, params, explanation in notification_searches:
        capture_api(
            f"Notifications Search - {label.title()}", f"search notifications {label}",
            explanation,
            "notifications", "GET", "/notifications/search", 200, token=tokens["analyst"], params=params,
        )
    delete_id = notifications["Employee Delete State"]["id"]
    analyst_delete_id = notifications["Analyst Incident Assignment"]["id"]
    capture_api(
        "Notifications Delete - Analyst", "deny an analyst deleting a notification",
        "The analyst attempts to delete an existing notification but does not have administrator permission. The API returns HTTP 403 and leaves the notification intact.",
        "notifications", "DELETE", f"/notifications/{analyst_delete_id}", 403, token=tokens["analyst"],
    )
    capture_api(
        "Notifications Delete - Admin", "delete an existing notification as an administrator",
        "The administrator deletes the selected employee notification. The successful mutation emits a DATA_DELETED record through the Logs service.",
        "notifications", "DELETE", f"/notifications/{delete_id}", 200, token=tokens["admin"],
    )

    git_log = subprocess.check_output(
        ["git", "log", '--author=Haya Karanouh', "--oneline"],
        cwd=PROJECT_ROOT, text=True,
    )
    RECORDER.text(
        caption("Git History", "show commits authored by Haya Karanouh"),
        git_log,
        explanation="This is the exact output of git log filtered by the requested author. It records the real endpoint-level commit history on the current feature branch.",
    )
    print(f"Evidence captured under {RECORDER.output_dir}")
    return 0


def main():
    raise SystemExit(run_evidence())


if __name__ == "__main__":
    main()
