"""Build the runnable Tatiana collection. Author: Tatiana Kaado."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "Tatiana Kaado \u2013 "


def request(name, method, port, path, status=200, role="admin", body=None, save=None, raw=None):
    tests = [f"pm.test('HTTP {status}', () => pm.response.to.have.status({status}));"]
    if save:
        tests.append(f"if (pm.response.code === {status}) pm.collectionVariables.set('{save}', pm.response.json().data.id);")
    item = {"name": name, "request": {"method": method, "header": [], "url": "{{base_url}}:" + str(port) + path,
            "description": PREFIX + name + ". Expected HTTP " + str(status) + "."},
            "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": tests}}]}
    item["request"]["auth"] = {"type": "bearer", "bearer": [{"key": "token", "value": "{{" + role + "_token}}", "type": "string"}]} if role else {"type": "noauth"}
    if body is not None or raw is not None:
        item["request"]["header"] = [{"key": "Content-Type", "value": "application/json"}]
        item["request"]["body"] = {"mode": "raw", "raw": raw if raw is not None else json.dumps(body, indent=2), "options": {"raw": {"language": "json"}}}
    return item


def main():
    folders = []
    logins = []
    for role in ["admin", "analyst", "auditor", "employee"]:
        item = request(f"Login {role} and save token", "POST", 5001, "/users/login", role=None,
                       body={"username": role, "password": role.title() + "@1234"})
        item["event"][0]["script"]["exec"].append(f"pm.collectionVariables.set('{role}_token', pm.response.json().data.token);")
        if role == "admin":
            item["event"][0]["script"]["exec"].append("pm.collectionVariables.set('run_id', Date.now().toString());")
        logins.append(item)
    folders.append({"name": "Login per role", "item": logins})
    for name, port, body in [
        ("threats", 5004, dict(threat_type="Domain", threat_value="postman-{{run_id}}.example", description="Postman indicator", severity="Critical", source="Postman")),
        ("vulnerabilities", 5007, dict(title="Postman vulnerability", description="Scanner finding", cve_id="CVE-2026-12345", cvss_score=9.5, severity="Critical", asset_id=1, discovery_source="Postman")),
    ]:
        variable = "threat_id" if name == "threats" else "vulnerability_id"
        base = "/" + name
        detail = base + "/{{" + variable + "}}"
        items = [request("Create " + name, "POST", port, base, 201, body=body, save=variable)]
        if name == "threats":
            items.append(request("Duplicate threat", "POST", port, base, 409, body=body))
            for kind, value in [("IP Address", "999.1.1.1"), ("Domain", "bad domain"), ("File Hash", "not-a-hash")]:
                items.append(request("Reject invalid " + kind, "POST", port, base, 422, body={**body, "threat_type": kind, "threat_value": value}))
            items.append(request("Reject type change", "PUT", port, detail, 422, body={"threat_type": "Other"}))
            filters = [("threat_type", "Domain"), ("threat_value", "postman"), ("severity", "Critical"), ("source", "Postman")]
        else:
            for field, value in [("cve_id", "bad-cve"), ("severity", "Low"), ("cvss_score", 11)]:
                items.append(request("Reject invalid " + field, "POST", port, base, 422, body={**body, field: value}))
            items.append(request("Reject unknown asset", "POST", port, base, 404, body={**body, "asset_id": 999999}))
            items.append(request("Reject invalid status transition", "PUT", port, detail, 422, body={"status": "Closed"}))
            filters = [("cve_id", body["cve_id"]), ("severity", "Critical"), ("asset_id", "1"), ("status", "Open")]
        for field, value in filters:
            items.append(request("Search by " + field, "GET", port, base + "/search?" + field + "=" + value.replace(" ", "%20")))
        for method, path, update in [("POST", base, body), ("GET", base, None), ("GET", detail, None), ("GET", base + "/search", None), ("PUT", detail, {"description": "Updated via Postman"}), ("DELETE", detail, None)]:
            title = method + " " + path
            wrong = "auditor" if method == "PUT" and name == "vulnerabilities" else "analyst" if method in ("POST", "PUT", "DELETE") else "employee"
            items.append(request(title + " missing token", method, port, path, 401, role=None, body=update))
            items.append(request(title + " wrong role", method, port, path, 403, role=wrong, body=update))
            items.append(request(title + " malformed JSON validation", method, port, path, 400, raw='{"broken":'))
            missing = base + "/999999" if path == detail else base + "/missing-route"
            items.append(request(title + " missing resource or route", method if path == detail else "GET", port, missing, 404, body=update if path == detail else None))
            if method != "POST":
                items.append(request(title + " success", method, port, path, body=update))
        folders.append({"name": name.title(), "item": items})
    items = []
    for name in ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"]:
        path = "/reports/" + name
        items.extend([
            request(name + " report success", "GET", 5006, path),
            request(name + " report auditor success", "GET", 5006, path, role="auditor"),
            request(name + " report invalid query", "GET", 5006, path + "?unsupported=1", 422),
            request(name + " report unknown route", "GET", 5006, path + "/missing", 404),
            request(name + " report analyst denied", "GET", 5006, path, 403, role="analyst"),
            request(name + " report employee denied", "GET", 5006, path, 403, role="employee"),
            request(name + " report missing token", "GET", 5006, path, 401, role=None),
        ])
    folders.append({"name": "Reports", "item": items})
    collection = {"info": {"name": "Tatiana Kaado - Threats, Vulnerabilities, Reports", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                  "description": PREFIX + "Run in order after database.seed and run_all.py. Login requests save role tokens; creation requests save IDs. Missing-resource cases use a nonexistent ID where supported, otherwise an unknown child route. CVSS zero maps to Low; resolved_at uses ISO timestamps."},
                  "variable": [{"key": "base_url", "value": "http://127.0.0.1"}, {"key": "run_id", "value": ""}], "item": folders}
    target = ROOT / "postman" / "TatianaKaado.postman_collection.json"
    target.write_text(json.dumps(collection, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {sum(len(folder['item']) for folder in folders)} requests to {target}")


if __name__ == "__main__":
    main()
