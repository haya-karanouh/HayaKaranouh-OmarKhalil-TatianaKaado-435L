"""Live endpoint regression checks. Author: Tatiana Kaado."""
import sys
import uuid
import requests


def main():
    tokens = {}
    for role in ["admin", "analyst", "auditor", "employee"]:
        response = requests.post("http://127.0.0.1:5001/users/login", json={"username": role, "password": role.title() + "@1234"}, timeout=10)
        response.raise_for_status()
        tokens[role] = response.json()["data"]["token"]

    def check(method, port, path, status=200, role="admin", **kwargs):
        headers = {"Authorization": "Bearer " + tokens[role]} if role else {}
        response = requests.request(method, f"http://127.0.0.1:{port}{path}", headers=headers, timeout=15, **kwargs)
        assert response.status_code == status, (method, path, response.status_code, response.text)
        print(method, path, status)
        return response.json().get("data")

    if sys.argv[-1] == "threats":
        body = dict(threat_type="Domain", threat_value=uuid.uuid4().hex + ".example", description="Live check", severity="Critical", source="HTTP checks")
        row = check("POST", 5004, "/threats", 201, json=body)
        path = f'/threats/{row["id"]}'
        check("POST", 5004, "/threats", 409, json=body)
        for kind, value in [("IP Address", "999.1.1.1"), ("Domain", "bad domain"), ("File Hash", "xyz")]:
            check("POST", 5004, "/threats", 422, json={**body, "threat_type": kind, "threat_value": value})
        for role in ["admin", "analyst", "auditor"]:
            check("GET", 5004, "/threats", role=role)
            check("GET", 5004, path, role=role)
        found = check("GET", 5004, "/threats/search", params={"threat_type": "Domain", "threat_value": body["threat_value"][:8], "severity": "Critical", "source": "HTTP checks"})
        assert [item["id"] for item in found["threats"]] == [row["id"]]
        check("PUT", 5004, path, json={"description": "Updated", "severity": "High", "source": "check"})
        check("PUT", 5004, path, 422, json={"threat_type": "Other"})
        check("GET", 5004, "/threats/999999", 404)
        check("GET", 5004, "/threats", 403, role="employee")
        check("GET", 5004, "/threats", 401, role=None)
        check("DELETE", 5004, path, 403, role="analyst")
        check("DELETE", 5004, path)
        check("GET", 5004, path, 404)
        notifications = check("GET", 5008, "/notifications/search")
        assert any(item["notification_type"] == "Threat Alert" for item in notifications["notifications"])
    elif sys.argv[-1] == "vulnerabilities":
        asset = check("GET", 5002, "/assets")["assets"][0]
        body = dict(title="Live CVSS check", description="Check", cve_id="CVE-2026-12345", cvss_score=9.5, severity="Critical", asset_id=asset["id"], discovery_source="Scanner")
        row = check("POST", 5007, "/vulnerabilities", 201, json=body)
        assert row["asset_name"] == asset["name"] and row["status"] == "Open"
        path = f'/vulnerabilities/{row["id"]}'
        for field, value in [("cve_id", "bad"), ("severity", "Low"), ("cvss_score", -1), ("cvss_score", True), ("asset_id", "1")]:
            check("POST", 5007, "/vulnerabilities", 422, json={**body, field: value})
        check("POST", 5007, "/vulnerabilities", 404, json={**body, "asset_id": 999999})
        for role in ["admin", "analyst", "auditor"]:
            check("GET", 5007, "/vulnerabilities", role=role)
            check("GET", 5007, path, role=role)
        check("PUT", 5007, path, 422, json={"status": "Closed"})
        check("PUT", 5007, path, 422, json={"cvss_score": 2})
        check("PUT", 5007, path, json={"description": "Updated", "cvss_score": 7.5, "severity": "High"}, role="analyst")
        for status in ["Under Investigation", "In Progress", "Resolved", "Closed"]:
            updated = check("PUT", 5007, path, json={"status": status}, role="analyst")
            assert updated["status"] == status
            if status in ("Resolved", "Closed"):
                assert updated["resolved_at"]
        found = check("GET", 5007, "/vulnerabilities/search", params={"cve_id": body["cve_id"], "severity": "High", "asset_id": asset["id"], "status": "Closed"})
        assert any(item["id"] == row["id"] for item in found["vulnerabilities"])
        check("GET", 5007, "/vulnerabilities/999999", 404)
        check("GET", 5007, "/vulnerabilities", 403, role="employee")
        check("GET", 5007, "/vulnerabilities", 401, role=None)
        check("DELETE", 5007, path, 403, role="analyst")
        check("DELETE", 5007, path)
        check("GET", 5007, path, 404)
        notifications = check("GET", 5008, "/notifications/search")
        assert any(item["notification_type"] == "Vulnerability Alert" for item in notifications["notifications"])
    elif sys.argv[-1] == "reports":
        for name in ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"]:
            path = f"/reports/{name}"
            check("GET", 5006, path)
            check("GET", 5006, path, role="auditor")
            check("GET", 5006, path, 403, role="analyst")
            check("GET", 5006, path, 403, role="employee")
            check("GET", 5006, path, 401, role=None)
            check("GET", 5006, path, 422, params={"unexpected": "1"})
        from common.auth import create_token
        from common.constants import SERVICE
        tokens["service"] = create_token({"id": None, "username": "internal", "role": SERVICE})
        check("GET", 5006, "/reports/summary", 403, role="service")
    else:
        raise SystemExit("Choose threats, vulnerabilities, or reports")
    print("Live checks passed")


if __name__ == "__main__":
    main()
