"""Capture live API and SQL evidence. Author: Tatiana Kaado.

Run with all services started by run_all.py. This resets the development database.
--outage briefly pauses the local assets process, always resuming it in finally.
"""
import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys

import requests
from sqlalchemy.engine import make_url
from common.config import DATABASE_URL, PROJECT_ROOT, SERVICE_URLS
from scripts.evidence.evidence_lib import EvidenceRecorder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outage", action="store_true")
    args = parser.parse_args()
    for service, url in SERVICE_URLS.items():
        try:
            response = requests.get(url + "/health", timeout=3)
            if response.status_code != 200:
                raise RuntimeError(f"HTTP {response.status_code}")
        except (requests.RequestException, RuntimeError) as error:
            raise SystemExit(f"{service} is down: {error}. Start all services with run_all.py before capturing evidence.")
    subprocess.run([sys.executable, "-m", "database.seed", "--reset"], cwd=PROJECT_ROOT, check=True)
    recorder = EvidenceRecorder("Tatiana Kaado")
    tokens = {}
    for role in ["admin", "analyst", "employee", "auditor"]:
        response = requests.post(SERVICE_URLS["users"] + "/users/login", json={"username": role, "password": role.title() + "@1234"}, timeout=10)
        response.raise_for_status()
        tokens[role] = response.json()["data"]["token"]
    for _ in range(2):
        response = requests.post(SERVICE_URLS["users"] + "/users/login", json={"username": "admin", "password": "wrong-password"}, timeout=10)
        assert response.status_code == 401, response.text

    def api(service, method, path, purpose, body=None, expected=200, role="admin", params=None, explanation=None):
        caption = f"Tatiana Kaado – {method} {path} – {purpose}"
        explanation = explanation or f"This request {purpose.lower()}. The live response verifies HTTP {expected} and shows the actual JSON result from the running service."
        response = recorder.api(caption, method, SERVICE_URLS[service] + path, token=tokens.get(role), json=body, params=params, explanation=explanation)
        assert response.status_code == expected, (caption, response.status_code, response.text)
        print(caption, flush=True)
        return response.json().get("data")

    def table(name, explanation):
        columns = {
            "threats": "id, threat_type, threat_value, severity, source",
            "vulnerabilities": "id, title, cve_id, cvss_score, severity, asset_id, status",
            "notifications": "id, user_id, title, notification_type, severity, status",
        }
        return recorder.db(f"Tatiana Kaado – {name} table – Shows persisted records", f"SELECT {columns[name]} FROM {name} ORDER BY id", explanation=explanation)

    created = []
    values = [("IP Address", "198.51.100.42"), ("Domain", "evidence.example"), ("File Hash", "a" * 32), ("Malware Signature", "DEMO_EVIDENCE_SIGNATURE"), ("Other", "demo-custom-indicator")]
    type_explanations = {
        "IP Address": "An IP Address indicator identifies an IPv4 host associated with suspicious activity; the validator rejects malformed octets and IPv6.",
        "Domain": "A Domain indicator identifies a DNS name associated with suspicious activity; labels are validated and stored in lowercase.",
        "File Hash": "A File Hash identifies file contents using a hexadecimal MD5, SHA1 or SHA256 digest of 32, 40 or 64 characters.",
        "Malware Signature": "A Malware Signature stores a non-empty detection signature for matching suspicious content.",
        "Other": "Other stores a non-empty custom indicator that does not fit the predefined network or file categories.",
    }
    for index, (kind, value) in enumerate(values):
        severity = ["Low", "Medium", "High", "Critical", "Low"][index]
        body = dict(threat_type=kind, threat_value=value, description="Synthetic evidence indicator", severity=severity, source="Evidence feed")
        created.append(api("threats", "POST", "/threats", f"Adds {kind}", body, 201, explanation=type_explanations[kind] + f" This example is stored as {severity}; severity expresses priority, with Low limited, Medium moderate, High urgent and Critical immediate response. Critical creation notifies every administrator through the users and notifications APIs."))
    table("threats", "The type column distinguishes IPv4 hosts, domain names, file digests, malware signatures and custom indicators. Severity is stored separately as a constrained Low, Medium, High or Critical value, so each type can appear at every priority.")
    body = dict(threat_type="IP Address", threat_value=values[0][1], description="Duplicate", severity="Low", source="Evidence feed")
    api("threats", "POST", "/threats", "Rejects duplicate type and value", body, 409)
    for kind, value in [("IP Address", "999.1.1.1"), ("Domain", "bad domain"), ("File Hash", "zz-not-hex")]:
        api("threats", "POST", "/threats", f"Rejects invalid {kind}", {**body, "threat_type": kind, "threat_value": value}, 422)
    api("threats", "GET", "/threats", "Lists all threat indicators", explanation="The response uses the shared status, message and data envelope. data.threats is an array of objects containing the ID, type, value, description, severity, source and ISO date_added timestamp.")
    path = f'/threats/{created[0]["id"]}'
    api("threats", "GET", path, "Retrieves a specific threat")
    api("threats", "GET", "/threats/999999", "Rejects a nonexistent ID", expected=404)
    for field, value in [("threat_type", "Domain"), ("threat_value", "evidence"), ("severity", "Critical"), ("source", "Evidence feed")]:
        api("threats", "GET", "/threats/search", f"Searches by {field}", params={field: value}, explanation=f"The {field} filter selects matching threat indicators. Type, severity and source use equality, value uses a literal partial match, and combined filters use AND.")
    combined = api("threats", "GET", "/threats/search", "Combines all filters with AND", params={"threat_type": "Domain", "threat_value": "evidence", "severity": "Medium", "source": "Evidence feed"})
    assert [row["id"] for row in combined["threats"]] == [created[1]["id"]]
    api("threats", "GET", path, "Shows the threat before update")
    api("threats", "PUT", path, "Updates allowed threat fields", {"description": "Confirmed and reviewed", "severity": "High", "source": "Analyst review"}, explanation="Only description, severity and source can change; text must be non-empty and severity must use the shared enum. Type and value remain immutable so the indicator identity and duplicate constraint stay consistent.")
    api("threats", "GET", path, "Shows the threat after update")
    api("threats", "PUT", path, "Rejects changing the indicator type", {"threat_type": "Other"}, 422)
    api("threats", "DELETE", path, "Denies deletion by an analyst", expected=403, role="analyst")
    api("threats", "DELETE", path, "Deletes the threat")
    api("threats", "GET", "/threats", "Denies employee access", expected=403, role="employee")

    assets = requests.get(SERVICE_URLS["assets"] + "/assets", headers={"Authorization": "Bearer " + tokens["admin"]}, timeout=10)
    assets.raise_for_status()
    asset_id = assets.json()["data"]["assets"][0]["id"]
    vulnerabilities = []
    for severity, score in [("Low", 2.5), ("Medium", 5.5), ("High", 8.0), ("Critical", 9.5)]:
        body = dict(title=f"Evidence {severity} vulnerability", description="Synthetic scanner finding", cve_id="CVE-2026-54321", cvss_score=score, severity=severity, asset_id=asset_id, discovery_source="Evidence scanner")
        vulnerabilities.append(api("vulnerabilities", "POST", "/vulnerabilities", f"Creates a {severity} finding", body, 201, explanation=f"CVSS {score} maps to {severity} under the validated score bands. New findings start Open and verify their asset over HTTP; Critical findings send a Vulnerability Alert to every administrator."))
    table("vulnerabilities", "Severity is a constrained string stored independently of the numeric CVSS score, with the API enforcing matching bands: Low below 4, Medium below 7, High below 9 and Critical through 10. The shared enum has no None value, so score zero is represented as Low; status and resolved_at track remediation separately.")
    api("vulnerabilities", "POST", "/vulnerabilities", "Rejects a malformed CVE", {**body, "cve_id": "CVE-bad"}, 422)
    api("vulnerabilities", "POST", "/vulnerabilities", "Rejects CVSS severity mismatch", {**body, "severity": "Low"}, 422)
    api("vulnerabilities", "GET", "/vulnerabilities", "Lists findings with asset name and status")
    path = f'/vulnerabilities/{vulnerabilities[0]["id"]}'
    api("vulnerabilities", "GET", path, "Retrieves a specific finding")
    api("vulnerabilities", "GET", "/vulnerabilities/999999", "Rejects an unknown finding", expected=404)
    api("vulnerabilities", "GET", "/vulnerabilities/not-an-id", "Rejects a malformed ID", expected=404)
    api("vulnerabilities", "GET", path, "Shows the finding before update")
    api("vulnerabilities", "PUT", path, "Updates description and matched severity", {"description": "Investigated exposure", "cvss_score": 7.5, "severity": "High", "status": "Under Investigation"}, role="analyst")
    api("vulnerabilities", "GET", path, "Shows the finding after update")
    api("vulnerabilities", "PUT", path, "Rejects a skipped lifecycle step", {"status": "Closed"}, 422, explanation="The service permits only Open to Under Investigation to In Progress to Resolved to Closed. Skipping directly to Closed fails before persistence and leaves the previous status unchanged.")
    for status in ["In Progress", "Resolved", "Closed"]:
        updated = api("vulnerabilities", "PUT", path, f"Advances to {status}", {"status": status}, role="analyst", explanation="Only the next lifecycle step is allowed for administrators and analysts. Entering Resolved automatically sets resolved_at, which is retained when the finding moves to Closed.")
        if status in ("Resolved", "Closed"):
            assert updated["resolved_at"]
    for field, value in [("cve_id", "CVE-2026-54321"), ("severity", "Critical"), ("asset_id", asset_id), ("status", "Closed")]:
        api("vulnerabilities", "GET", "/vulnerabilities/search", f"Searches by {field}", params={field: value})
    api("vulnerabilities", "DELETE", path, "Denies analyst deletion", expected=403, role="analyst")
    api("vulnerabilities", "DELETE", path, "Deletes a finding")
    table("notifications", "Critical threats and vulnerabilities produce typed notifications addressed to administrators returned by the users API. These rows are actual notifications created by the live requests, not inserted by the evidence script.")

    database_path = make_url(DATABASE_URL).database
    def query(sql, params=()):
        with sqlite3.connect(database_path) as connection:
            return connection.execute(sql, params).fetchall()

    for name in ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"]:
        log_id = query("SELECT COALESCE(MAX(id), 0) FROM logs")[0][0]
        report = api("reports", "GET", "/reports/" + name, f"Generates the {name} report", role="auditor", explanation="The report aggregates real JSON responses obtained through call_service from the owning services. Its numbers are verified in the next database image; the report's own REPORT_GENERATED event is recorded after data collection.")
        params = ()
        if name == "summary":
            sql = """SELECT 'users' AS metric, COUNT(*) AS value FROM users
UNION ALL SELECT 'assets', COUNT(*) FROM assets
UNION ALL SELECT 'open_incidents', COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','Closed')
UNION ALL SELECT 'critical_threats', COUNT(*) FROM threats WHERE severity='Critical'
UNION ALL SELECT 'critical_vulnerabilities', COUNT(*) FROM vulnerabilities WHERE severity='Critical'
UNION ALL SELECT 'recent:' || id, 1 FROM (SELECT id FROM logs WHERE id <= ? ORDER BY timestamp DESC, id DESC LIMIT 10)"""
            params = (log_id,)
            expected = {key: value for key, value in report.items() if key != "recent_activities"}
            expected.update({f'recent:{row["id"]}': 1 for row in report["recent_activities"]})
        elif name == "activity":
            sql = """WITH audit AS (SELECT * FROM logs WHERE id <= ?)
SELECT 'total_activities' AS metric, COUNT(*) AS value FROM audit
UNION ALL SELECT 'login_attempts', COUNT(*) FROM audit WHERE action IN ('LOGIN_SUCCESS','LOGIN_FAILED')
UNION ALL SELECT 'failed_logins', COUNT(*) FROM audit WHERE action='LOGIN_FAILED'
UNION ALL SELECT 'action:' || action, n FROM (SELECT action, COUNT(*) AS n FROM audit GROUP BY action ORDER BY n DESC, action LIMIT 5)"""
            params = (log_id,)
            expected = {key: value for key, value in report.items() if key != "top_actions"}
            expected.update({f'action:{row["action"]}': row["count"] for row in report["top_actions"]})
        else:
            sql = f"SELECT 'total' AS metric, COUNT(*) AS value FROM {name}"
            expected = {"total": report["total"]}
            groups = [("by_type", "asset_type")] if name == "assets" else [("by_severity", "severity"), ("by_type", "threat_type")] if name == "threats" else [("by_severity", "severity"), ("by_status", "status")]
            for key, column in groups:
                sql += f" UNION ALL SELECT '{key}:' || {column}, COUNT(*) FROM {name} GROUP BY {column}"
                expected.update({f"{key}:{value}": count for value, count in report[key].items()})
            if name == "assets":
                sql += " UNION ALL SELECT 'critical_assets', COUNT(*) FROM assets WHERE criticality='Critical'"
                expected["critical_assets"] = report["critical_assets"]
            if name == "threats":
                sql += " UNION ALL SELECT 'recent:' || id, 1 FROM (SELECT id FROM threats ORDER BY date_added DESC, id DESC LIMIT 5)"
                expected.update({f'recent:{row["id"]}': 1 for row in report["recent"]})
            if name == "vulnerabilities":
                sql += " UNION ALL SELECT 'critical:' || id, 1 FROM vulnerabilities WHERE severity='Critical'"
                expected.update({f'critical:{row["id"]}': 1 for row in report["critical"]})
        rows = recorder.db(f"Tatiana Kaado – {name} report verification – Proves API totals using SQL", sql, params=params, explanation="COUNT and GROUP BY independently reproduce the API counts, with selected IDs also checking recent and critical lists. For activity and summary, the captured maximum log ID excludes this report's subsequently written audit event; open incidents means all statuses except Resolved and Closed.")
        actual = {row["metric"]: row["value"] for row in rows}
        assert actual == expected, (name, actual, expected)
        assert query("SELECT COUNT(*) FROM logs WHERE id > ? AND action = 'REPORT_GENERATED'", (log_id,))[0][0] == 1

    api("reports", "GET", "/reports/summary", "Denies an analyst report access", expected=403, role="analyst")
    api("reports", "GET", "/reports/summary", "Denies an employee report access", expected=403, role="employee")
    if args.outage:
        output = subprocess.run(["lsof", "-t", "-iTCP:5002", "-sTCP:LISTEN"], capture_output=True, text=True, check=True).stdout
        pids = set(output.split())
        if len(pids) != 1:
            raise RuntimeError("Cannot safely identify one local assets process")
        pid = int(pids.pop())
        command = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, check=True).stdout
        if "services.assets.app" not in command:
            raise RuntimeError("Refusing to pause an unrelated process on port 5002")
        try:
            os.kill(pid, signal.SIGSTOP)
            api("reports", "GET", "/reports/assets", "Returns 503 while the assets source is paused", expected=503, explanation="The local assets process is temporarily paused, causing the real HTTP call to time out. The report returns 503 naming the unavailable source, and a finally block resumes the process immediately after capture.")
        finally:
            os.kill(pid, signal.SIGCONT)
        requests.get(SERVICE_URLS["assets"] + "/health", timeout=10).raise_for_status()

    api("reports", "GET", "/reports/summary", "Rejects a missing token", expected=401, role=None)
    response = requests.post(SERVICE_URLS["threats"] + "/threats", data='{"broken":', headers={"Authorization": "Bearer " + tokens["admin"], "Content-Type": "application/json"}, timeout=10)
    assert response.status_code == 400, response.text
    recorder.text("Tatiana Kaado – Error handling – Rejects malformed JSON", f'{response.request.method} {response.url}\nContent-Type: application/json\nBody: {response.request.body}\nHTTP {response.status_code}\n{response.text}', explanation="This is an actual HTTP request with incomplete JSON syntax. The local request handler returns the shared JSON error envelope with 400 before business logic executes.")
    api("reports", "GET", "/reports/unknown", "Returns 404 for an unknown route", expected=404)
    injected = api("threats", "GET", "/threats/search", "Treats SQL injection text as a literal value", params={"threat_value": "' OR 1=1 --"}, explanation="SQLAlchemy binds the supplied string as a value and escapes LIKE wildcards. The text does not become SQL syntax, so it returns an empty match instead of exposing all threats.")
    assert injected["threats"] == []
    output = subprocess.run(["git", "log", "--author=Tatiana Kaado", "--oneline"], cwd=PROJECT_ROOT, capture_output=True, text=True, check=True).stdout
    recorder.text("Tatiana Kaado – GitHub history – Shows authored implementation commits", 'git log --author="Tatiana Kaado" --oneline\n' + output, explanation="This is actual Git output filtered by the configured author Tatiana Kaado. The history shows separate endpoint implementation commits along with live validation and supporting artifacts.")
    print(f"Evidence saved to {recorder.output_dir}", flush=True)


if __name__ == "__main__":
    main()
