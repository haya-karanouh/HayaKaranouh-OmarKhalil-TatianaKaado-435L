"""Execute the collection's requests and status assertions. Author: Tatiana Kaado."""
import json
import re
import time
import requests
from common.config import PROJECT_ROOT


def main():
    collection = json.loads((PROJECT_ROOT / "postman/TatianaKaado.postman_collection.json").read_text())
    variables = {item["key"]: item["value"] for item in collection["variable"]}
    variables["run_id"] = str(time.time_ns())
    count = 0

    def expand(value):
        return re.sub(r"{{([^}]+)}}", lambda match: str(variables[match[1]]), value)

    for folder in collection["item"]:
        for item in folder["item"]:
            request = item["request"]
            assert request["description"].startswith("Tatiana Kaado \u2013 ")
            headers = {entry["key"]: expand(entry["value"]) for entry in request.get("header", [])}
            auth = request["auth"]
            if auth["type"] == "bearer":
                headers["Authorization"] = "Bearer " + expand(auth["bearer"][0]["value"])
            response = requests.request(request["method"], expand(request["url"]), headers=headers,
                                        data=expand(request["body"]["raw"]) if "body" in request else None, timeout=20)
            script = "\n".join(item["event"][0]["script"]["exec"])
            expected = int(re.search(r"to.have.status\((\d+)\)", script)[1])
            assert response.status_code == expected, (item["name"], expected, response.status_code, response.text)
            if folder["name"] == "Login per role":
                role = item["name"].split()[1]
                variables[role + "_token"] = response.json()["data"]["token"]
            match = re.search(r"set\('([^']+)', pm.response.json\(\).data.id\)", script)
            if match:
                variables[match[1]] = response.json()["data"]["id"]
            count += 1
            print(item["name"], response.status_code, flush=True)
    print(f"All {count} collection requests passed.")


if __name__ == "__main__":
    main()
