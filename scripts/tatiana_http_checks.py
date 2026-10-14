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
    print("Live checks passed")


if __name__ == "__main__":
    main()
