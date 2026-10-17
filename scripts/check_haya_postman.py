"""Replay Haya's collection against running services. Author: Tatiana Kaado."""
import json
import re
import uuid

import requests
from common.config import PROJECT_ROOT


def main():
    collection = json.loads((PROJECT_ROOT / "postman/HayaKaranouh.postman_collection.json").read_text())
    variables = {item["key"]: item["value"] for item in collection["variable"]}
    count = 0

    def expand(value):
        return re.sub(r"\{\{([^}]+)\}\}", lambda match: str(uuid.uuid4()) if match[1] == "$guid" else str(variables[match[1]]), value)

    def run(items):
        nonlocal count
        for item in items:
            if "item" in item:
                run(item["item"])
                continue
            request = item["request"]
            headers = {header["key"]: expand(header["value"]) for header in request.get("header", [])}
            response = requests.request(request["method"], expand(request["url"]), headers=headers,
                                        data=expand(request["body"]["raw"]) if "body" in request else None, timeout=20)
            script = "\n".join(line for event in item.get("event", []) for line in event["script"]["exec"])
            expected = int(re.search(r"to.have.status\((\d+)\)", script)[1])
            assert response.status_code == expected, (item["name"], expected, response.status_code, response.text)
            if response.ok:
                for key, field in re.findall(r"pm.collectionVariables.set\('([^']+)', (?:pm.response.json\(\).)?data\.(\w+)\)", script):
                    variables[key] = response.json()["data"][field]
            count += 1

    run(collection["item"])
    print(f"Haya collection: all {count} real requests passed.")


if __name__ == "__main__":
    main()
