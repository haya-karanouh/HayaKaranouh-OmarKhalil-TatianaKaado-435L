"""Capture GET /health from all nine running services."""

import argparse
import sys

from common.config import SERVICE_PORTS, SERVICE_URLS
from scripts.evidence import EvidenceRecorder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("student_full_name", nargs="?", default="Haya Karanouh")
    name = parser.parse_args().student_full_name
    recorder = EvidenceRecorder(name)
    failures = []
    for service in SERVICE_PORTS:
        url = f"{SERVICE_URLS[service].rstrip('/')}/health"
        try:
            response = recorder.api(f"{service} health", "GET", url, explanation="Service health check")
            print(f"{service}: HTTP {response.status_code}")
            if not response.ok:
                failures.append(service)
        except Exception as error:
            print(f"{service}: {error}", file=sys.stderr)
            failures.append(service)
    if failures:
        raise SystemExit(f"Health evidence failed for: {', '.join(failures)}")


if __name__ == "__main__":
    main()
