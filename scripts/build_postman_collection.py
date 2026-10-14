"""Generate the shared Postman collection and its endpoint scenario matrix."""

import json
from pathlib import Path

from common.config import PROJECT_ROOT


ROLE_USERS = {
    "admin": ("admin", "Admin@1234"),
    "analyst": ("analyst", "Analyst@1234"),
    "employee": ("employee", "Employee@1234"),
    "auditor": ("auditor", "Auditor@1234"),
}
SCENARIO_ORDER = ("Success", "Validation error", "Not found", "Wrong role", "Missing token")


def response_test(expected_status, save=None):
    lines = [
        f"pm.test('HTTP {expected_status}', function () {{ pm.response.to.have.status({expected_status}); }});"
    ]
    if save:
        variable, field = save
        lines.extend([
            "if (pm.response.code >= 200 && pm.response.code < 300) {",
            "    const data = pm.response.json().data;",
            f"    pm.collectionVariables.set('{variable}', data.{field});",
            "}",
        ])
    return "\n".join(lines)


def request_item(endpoint, method, path, scenario, base_url):
    expected = scenario["status"]
    description = f"Haya Karanouh – {endpoint} – {scenario['description']}"
    request = {
        "method": method,
        "header": [],
        "url": f"{{{{{base_url}}}}}{scenario.get('path', path)}",
        "description": description,
    }
    token_role = scenario.get("token")
    if token_role:
        request["header"].append({
            "key": "Authorization", "value": f"Bearer {{{{token_{token_role}}}}}", "type": "text"
        })
    body = scenario.get("body")
    if body is not None:
        request["header"].append({"key": "Content-Type", "value": "application/json", "type": "text"})
        request["body"] = {
            "mode": "raw",
            "raw": json.dumps(body, indent=2),
            "options": {"raw": {"language": "json"}},
        }
    if scenario.get("params"):
        query = "&".join(f"{key}={value}" for key, value in scenario["params"].items())
        request["url"] += "?" + query
    item = {
        "name": f"{endpoint} - {scenario['name']}",
        "request": request,
        "event": [{
            "listen": "test",
            "script": {
                "type": "text/javascript",
                "exec": response_test(expected, scenario.get("save")).splitlines(),
            },
        }],
    }
    return item


def endpoint_folder(service, endpoint, method, path, scenarios, base_url):
    categories = {}
    for category in SCENARIO_ORDER:
        key = next((candidate for candidate in scenarios if candidate == category), None)
        if key is None:
            prefix = category.split(" / ", 1)[0]
            key = next((candidate for candidate in scenarios if candidate.startswith(prefix)), None)
        if key is None:
            raise ValueError(f"Missing {category!r} scenario for {endpoint}")
        categories[category] = key
    return {
        "name": f"{service}: {method} {path}",
        "item": [request_item(endpoint, method, path, scenarios[categories[key]], base_url) for key in SCENARIO_ORDER],
    }


def login_item(role, username, password, path="/users/login", dynamic_user=False):
    body = {
        "username": "{{service_username}}" if dynamic_user else username,
        "password": password,
    }
    description = f"Haya Karanouh – Authentication – Log in as {role.title()} and save the JWT collection variable."
    variable = f"token_{role}"
    return {
        "name": f"Login - {role.title()}",
        "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json", "type": "text"}],
            "body": {"mode": "raw", "raw": json.dumps(body, indent=2), "options": {"raw": {"language": "json"}}},
            "url": "{{users_url}}" + path,
            "description": description,
        },
        "event": [{
            "listen": "test",
            "script": {
                "type": "text/javascript",
                "exec": [
                    "pm.test('Login succeeds', function () { pm.response.to.have.status(200); });",
                    f"pm.collectionVariables.set('{variable}', pm.response.json().data.token);",
                ],
            },
        }],
    }


def service_setup_item():
    description = "Haya Karanouh – Authentication – Create a development SERVICE-role account so its login request can save a token."
    body = {
        "full_name": "Postman Service",
        "username": "postman-service-{{$guid}}",
        "email": "postman-service-{{$guid}}@example.com",
        "password": "PostmanService1",
        "department": "Security",
        "role": "Service",
    }
    return {
        "name": "Setup - Create Service role account",
        "request": {
            "method": "POST",
            "header": [
                {"key": "Authorization", "value": "Bearer {{token_admin}}", "type": "text"},
                {"key": "Content-Type", "value": "application/json", "type": "text"},
            ],
            "body": {"mode": "raw", "raw": json.dumps(body, indent=2), "options": {"raw": {"language": "json"}}},
            "url": "{{users_url}}/users/register",
            "description": description,
        },
        "event": [{
            "listen": "test",
            "script": {
                "type": "text/javascript",
                "exec": [
                    "pm.test('Service user created', function () { pm.response.to.have.status(201); });",
                    "pm.collectionVariables.set('service_username', pm.response.json().data.username);",
                ],
            },
        }],
    }


def endpoint_scenarios():
    register = {
        "Success": {"name": "Success", "token": None, "status": 201,
                    "body": {"full_name": "Postman User", "username": "postman-user-{{$guid}}", "email": "postman-{{$guid}}@example.com", "password": "PostmanUser1", "department": "QA", "role": "Security Analyst"},
                    "description": "Create a new account; the response stores its ID for the later delete success case.", "save": ("postman_user_id", "id")},
        "Validation error": {"name": "Validation error", "token": "admin", "status": 422,
                             "body": {"full_name": "Invalid Email", "username": "bad-email-{{$guid}}", "email": "invalid", "password": "StrongPass1", "department": "QA", "role": "Regular Employee"},
                             "description": "Reject a malformed email before insertion."},
        "Not found": {"name": "Not found / new resource", "token": None, "status": 201,
                      "body": {"full_name": "New Resource", "username": "new-resource-{{$guid}}", "email": "new-{{$guid}}@example.com", "password": "StrongPass1", "department": "QA", "role": "Regular Employee"},
                      "description": "Registration has no lookup/not-found state; a previously absent username is accepted as a new resource."},
        "Wrong role": {"name": "Wrong role / public endpoint", "token": "employee", "status": 201,
                       "body": {"full_name": "Forced Employee", "username": "forced-{{$guid}}", "email": "forced-{{$guid}}@example.com", "password": "StrongPass1", "department": "QA", "role": "Security Administrator"},
                       "description": "Registration is public and a non-admin token cannot assign the administrator role; the service forces Regular Employee."},
        "Missing token": {"name": "Missing token / public endpoint", "token": None, "status": 201,
                          "body": {"full_name": "Public Registration", "username": "public-{{$guid}}", "email": "public-{{$guid}}@example.com", "password": "StrongPass1", "department": "QA", "role": "Regular Employee"},
                          "description": "No bearer token is required for public registration."},
    }
    login = {
        "Success": {"name": "Success", "token": None, "status": 200, "body": {"username": "admin", "password": "Admin@1234"}, "description": "Authenticate an active seeded administrator."},
        "Validation error": {"name": "Validation error", "token": None, "status": 422, "body": {"password": "Admin@1234"}, "description": "Reject a login payload with no username or email."},
        "Not found": {"name": "Not found / unknown account", "token": None, "status": 401, "body": {"username": "unknown-{{$guid}}", "password": "StrongPass1"}, "description": "Unknown account names are rejected with the same credential response as a bad password."},
        "Wrong role": {"name": "Wrong role / public endpoint", "token": "employee", "status": 200, "body": {"username": "employee", "password": "Employee@1234"}, "description": "Login is public and authenticates the supplied account, regardless of the caller token's role."},
        "Missing token": {"name": "Missing token / public endpoint", "token": None, "status": 200, "body": {"username": "admin", "password": "Admin@1234"}, "description": "No bearer token is required to obtain a login token."},
    }
    user_update = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "body": {"department": "Engineering"}, "description": "Update a seeded user's profile with administrator permission."},
        "Validation error": {"name": "Validation error", "token": "admin", "status": 422, "body": {"email": "invalid"}, "description": "Reject an invalid email address without changing the user."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/users/999999", "body": {"department": "QA"}, "description": "Return 404 when an administrator updates a nonexistent user ID."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "path": "/users/1", "body": {"department": "QA"}, "description": "A regular employee cannot update another user's account."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "body": {"department": "Engineering"}, "description": "Reject profile updates without a bearer token."},
    }
    user_delete = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/users/{{postman_user_id}}", "description": "Delete the account created by the registration success request."},
        "Validation error": {"name": "Validation error / invalid ID syntax", "token": "admin", "status": 404, "path": "/users/not-an-integer", "description": "This bodyless endpoint validates its integer path converter; malformed IDs do not match the route."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/users/999999", "description": "Return 404 for an absent user ID."},
        "Wrong role": {"name": "Wrong role", "token": "analyst", "status": 403, "path": "/users/3", "description": "Analysts cannot delete user accounts."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/users/3", "description": "Reject deletion without a bearer token."},
    }
    user_list = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "description": "Retrieve password-free user summaries as an administrator."},
        "Validation error": {"name": "Validation error", "token": "admin", "status": 422, "params": {"role": "not-a-role"}, "description": "Reject an unsupported role filter."},
        "Not found": {"name": "Not found / collection response", "token": "auditor", "status": 200, "params": {"role": "Service"}, "description": "A collection has no single-record 404 state; this valid role filter returns the collection for that role."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "description": "Regular employees cannot list all user records."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "description": "Reject user listing without a bearer token."},
    }
    user_detail = {
        "Success": {"name": "Success", "token": "employee", "status": 200, "path": "/users/employee", "description": "Retrieve the current employee's own password-free profile."},
        "Validation error": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/users/", "description": "The username path segment is required; an incomplete path does not match the route."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/users/no-such-user", "description": "Return 404 when the requested username does not exist."},
        "Wrong role": {"name": "Wrong role", "token": "analyst", "status": 403, "path": "/users/employee", "description": "Analysts are not authorized to retrieve user profiles through this endpoint."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/users/employee", "description": "Reject private profile access without a bearer token."},
    }

    log_create = {
        "Success": {"name": "Success", "token": "admin", "status": 201, "body": {"user_id": 1, "action": "DATA_CREATED", "description": "Postman manual log", "severity": "Information", "related_service": "logs"}, "description": "Create a manual audit event and save its ID for detail/delete requests.", "save": ("postman_log_id", "id")},
        "Validation error": {"name": "Validation error", "token": "admin", "status": 422, "body": {"user_id": 1, "description": "Missing action", "severity": "Information", "related_service": "logs"}, "description": "Reject a log record missing its required action."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "body": {"user_id": 999999, "action": "DATA_CREATED", "description": "Unknown actor", "severity": "Information", "related_service": "logs"}, "description": "Reject a provided user ID that does not exist."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "body": {"user_id": 3, "action": "DATA_CREATED", "description": "Denied", "severity": "Information", "related_service": "logs"}, "description": "Regular employees cannot write audit log records."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "body": {"user_id": 1, "action": "DATA_CREATED", "description": "No auth", "severity": "Information", "related_service": "logs"}, "description": "Reject unauthenticated log creation."},
    }
    logs_list = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "description": "Retrieve the audit log collection."},
        "Validation error": {"name": "Validation error / no filter inputs", "token": "admin", "status": 200, "params": {"unsupported": "ignored"}, "description": "This collection endpoint has no filter fields; the response confirms it remains a read-only list."},
        "Not found": {"name": "Not found / collection response", "token": "auditor", "status": 200, "description": "A collection endpoint returns a list rather than a single-record 404."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "description": "Regular employees cannot read the full audit collection."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "description": "Reject audit collection access without a bearer token."},
    }
    log_detail = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/logs/{{postman_log_id}}", "description": "Retrieve the log created by the POST success request."},
        "Validation error / path syntax": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/logs/not-an-integer", "description": "The integer path converter rejects malformed IDs before dispatch."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/logs/999999", "description": "Return 404 for an absent log ID."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "path": "/logs/1", "description": "Regular employees cannot inspect individual audit records."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/logs/1", "description": "Reject log detail access without authentication."},
    }
    log_search = {
        "Success": {"name": "Success", "token": "analyst", "status": 200, "params": {"action": "LOGIN_SUCCESS"}, "description": "Search audit records by a valid standard action."},
        "Validation error": {"name": "Validation error", "token": "admin", "status": 422, "params": {"severity": "Bogus"}, "description": "Reject unsupported severity filter values."},
        "Not found": {"name": "Not found / no matches", "token": "auditor", "status": 200, "params": {"user_id": "999999"}, "description": "Search returns an empty list when a valid filter has no matching records."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "description": "Regular employees cannot search audit records."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "description": "Reject audit search without a bearer token."},
    }
    logs_by_user = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/logs/user/1", "description": "Retrieve a seeded administrator's audit history."},
        "Validation error / path syntax": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/logs/user/not-an-integer", "description": "The path converter requires an integer user ID."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/logs/user/999999", "description": "Return 404 for an unknown user ID."},
        "Wrong role": {"name": "Wrong role", "token": "analyst", "status": 403, "path": "/logs/user/1", "description": "Analysts cannot use the per-user audit endpoint."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/logs/user/1", "description": "Reject per-user log access without a bearer token."},
    }
    log_delete = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/logs/{{postman_log_id}}", "description": "Delete the log created by the POST success request."},
        "Validation error / path syntax": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/logs/not-an-integer", "description": "The bodyless delete route uses an integer ID path converter."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/logs/999999", "description": "Return 404 when the log ID is absent."},
        "Wrong role": {"name": "Wrong role", "token": "analyst", "status": 403, "path": "/logs/1", "description": "Only administrators may delete an audit record."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/logs/1", "description": "Reject deletion without a bearer token."},
    }

    notification_create = {
        "Success": {"name": "Success", "token": "admin", "status": 201, "body": {"user_id": 1, "title": "Postman notification", "message": "Created by the collection", "notification_type": "Security Alert", "severity": "High"}, "description": "Create an unread notification for a real seeded user and save its ID.", "save": ("postman_notification_id", "id")},
        "Validation error": {"name": "Validation error", "token": "admin", "status": 422, "body": {"user_id": 1, "title": "Missing severity", "message": "Invalid request", "notification_type": "Security Alert"}, "description": "Reject notification creation when severity is missing."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "body": {"user_id": 999999, "title": "Unknown user", "message": "Recipient lookup", "notification_type": "Security Alert", "severity": "High"}, "description": "Verify the Users service rejects a nonexistent recipient."},
        "Wrong role": {"name": "Wrong role", "token": "analyst", "status": 403, "body": {"user_id": 2, "title": "Denied", "message": "Role check", "notification_type": "Security Alert", "severity": "High"}, "description": "Analysts cannot create notifications through this endpoint."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "body": {"user_id": 1, "title": "No token", "message": "Auth check", "notification_type": "Security Alert", "severity": "High"}, "description": "Reject notification creation without authentication."},
    }
    notifications_by_user = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/notifications/user/1", "description": "Retrieve notifications for a user as an administrator."},
        "Validation error / path syntax": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/notifications/user/not-an-integer", "description": "The route requires an integer user ID."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/notifications/user/999999", "description": "Return 404 when the recipient account does not exist."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "path": "/notifications/user/1", "description": "An employee cannot inspect another user's notifications."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/notifications/user/1", "description": "Reject per-user notification access without authentication."},
    }
    notification_detail = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/notifications/{{postman_notification_id}}", "description": "Retrieve the notification created by the POST success request."},
        "Validation error / path syntax": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/notifications/not-an-integer", "description": "The route requires an integer notification ID."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/notifications/999999", "description": "Return 404 when a notification ID is absent."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "path": "/notifications/1", "description": "An employee cannot read another user's notification."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/notifications/1", "description": "Reject notification detail access without a bearer token."},
    }
    notification_read = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/notifications/{{postman_notification_id}}/read", "description": "Mark the created notification as read."},
        "Validation error / path syntax": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/notifications/not-an-integer/read", "description": "The route requires an integer notification ID."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/notifications/999999/read", "description": "Return 404 when the notification does not exist."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "path": "/notifications/1/read", "description": "An employee cannot change another user's notification state."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/notifications/1/read", "description": "Reject read-state changes without authentication."},
    }
    notification_search = {
        "Success": {"name": "Success", "token": "analyst", "status": 200, "params": {"notification_type": "Security Alert"}, "description": "Search notifications by a valid notification type."},
        "Validation error": {"name": "Validation error", "token": "admin", "status": 422, "params": {"status": "Unknown"}, "description": "Reject unsupported notification status values."},
        "Not found / no matches": {"name": "Not found / no matches", "token": "auditor", "status": 200, "params": {"user_id": "999999"}, "description": "Return a valid empty result for filters with no matching notifications."},
        "Wrong role": {"name": "Wrong role", "token": "employee", "status": 403, "description": "Regular employees cannot use the search endpoint."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "description": "Reject notification search without authentication."},
    }
    notification_delete = {
        "Success": {"name": "Success", "token": "admin", "status": 200, "path": "/notifications/{{postman_notification_id}}", "description": "Delete the notification created by the POST success request."},
        "Validation error / path syntax": {"name": "Validation error / path syntax", "token": "admin", "status": 404, "path": "/notifications/not-an-integer", "description": "The integer path converter rejects malformed notification IDs."},
        "Not found": {"name": "Not found", "token": "admin", "status": 404, "path": "/notifications/999999", "description": "Return 404 for a missing notification ID."},
        "Wrong role": {"name": "Wrong role", "token": "analyst", "status": 403, "path": "/notifications/1", "description": "Only administrators may delete notifications."},
        "Missing token": {"name": "Missing token", "token": None, "status": 401, "path": "/notifications/1", "description": "Reject notification deletion without a bearer token."},
    }

    return [
        ("Users", "POST", "/users/register", register, "users_url"),
        ("Users", "POST", "/users/login", login, "users_url"),
        ("Users", "PUT", "/users/3", user_update, "users_url"),
        ("Users", "DELETE", "/users/3", user_delete, "users_url"),
        ("Users", "GET", "/users", user_list, "users_url"),
        ("Users", "GET", "/users/employee", user_detail, "users_url"),
        ("Audit Logs", "POST", "/logs", log_create, "logs_url"),
        ("Audit Logs", "GET", "/logs", logs_list, "logs_url"),
        ("Audit Logs", "GET", "/logs/1", log_detail, "logs_url"),
        ("Audit Logs", "GET", "/logs/search", log_search, "logs_url"),
        ("Audit Logs", "GET", "/logs/user/1", logs_by_user, "logs_url"),
        ("Audit Logs", "DELETE", "/logs/1", log_delete, "logs_url"),
        ("Notifications", "POST", "/notifications", notification_create, "notifications_url"),
        ("Notifications", "GET", "/notifications/user/1", notifications_by_user, "notifications_url"),
        ("Notifications", "GET", "/notifications/1", notification_detail, "notifications_url"),
        ("Notifications", "PUT", "/notifications/1/read", notification_read, "notifications_url"),
        ("Notifications", "GET", "/notifications/search", notification_search, "notifications_url"),
        ("Notifications", "DELETE", "/notifications/1", notification_delete, "notifications_url"),
    ]


def build_collection():
    authentication = [
        login_item("admin", *ROLE_USERS["admin"]),
        service_setup_item(),
        login_item("service", "service", "PostmanService1", dynamic_user=True),
        login_item("analyst", *ROLE_USERS["analyst"]),
        login_item("employee", *ROLE_USERS["employee"]),
        login_item("auditor", *ROLE_USERS["auditor"]),
    ]
    folders = [{"name": "Authentication and token setup", "item": authentication}]
    grouped = {}
    for service, method, path, cases, base_url in endpoint_scenarios():
        grouped.setdefault(service, []).append(endpoint_folder(service, f"{method} {path}", method, path, cases, base_url))
    for service in ("Users", "Audit Logs", "Notifications"):
        folders.append({"name": service, "item": grouped[service]})
    return {
        "info": {
            "name": "Haya Karanouh - Security Incident Management APIs",
            "description": "Postman scenario matrix for Users, Audit Logs, and Notifications. Run Authentication and token setup first; it saves role JWTs to collection variables. Development credentials come from database/seed.py.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": folders,
        "variable": [
            {"key": "users_url", "value": "http://127.0.0.1:5001"},
            {"key": "logs_url", "value": "http://127.0.0.1:5005"},
            {"key": "notifications_url", "value": "http://127.0.0.1:5008"},
            *[{"key": f"token_{role}", "value": ""} for role in ("admin", "analyst", "employee", "auditor", "service")],
            {"key": "service_username", "value": ""},
            {"key": "postman_user_id", "value": ""},
            {"key": "postman_log_id", "value": ""},
            {"key": "postman_notification_id", "value": ""},
        ],
    }


def main():
    collection_path = PROJECT_ROOT / "postman" / "HayaKaranouh.postman_collection.json"
    collection_path.write_text(json.dumps(build_collection(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {collection_path}")


if __name__ == "__main__":
    main()
