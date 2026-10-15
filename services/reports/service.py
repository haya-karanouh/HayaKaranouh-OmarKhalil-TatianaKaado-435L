"""Reports collected exclusively over HTTP. Author: Tatiana Kaado."""

from collections import Counter
import requests
from werkzeug.exceptions import ServiceUnavailable
from common.constants import ADMIN, AUDITOR, LOGIN_SUCCESS, LOGIN_FAILED, REPORT_GENERATED
from common.errors import PermissionDenied, ValidationError
from common.service_client import call_service, log_event


class ReportsService:
    def health(self):
        return {"service": "reports", "status": "healthy"}

    @staticmethod
    def fetch(source):
        try:
            response = call_service("GET", source, f"/{source}")
            if response.status_code != 200:
                raise ServiceUnavailable(f"{source.title()} source service is unavailable (HTTP {response.status_code})")
            rows = response.json()["data"][source]
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                raise ValueError("Invalid source data")
            return rows
        except (requests.RequestException, ValueError, KeyError, TypeError) as error:
            raise ServiceUnavailable(f"{source.title()} source service is unavailable or returned invalid data") from error

    @staticmethod
    def counts(rows, field):
        return dict(sorted(Counter(row[field] for row in rows).items()))

    @staticmethod
    def recent(rows, field, limit):
        return sorted(rows, key=lambda row: (row[field], row["id"]), reverse=True)[:limit]

    def generate(self, name, actor, filters):
        if actor["role"] not in (ADMIN, AUDITOR):
            raise PermissionDenied("Reports require an administrator or auditor")
        if filters:
            raise ValidationError("Reports do not accept query parameters")
        try:
            data = getattr(self, name)()
        except (KeyError, TypeError, ValueError) as error:
            raise ServiceUnavailable("A source service returned incomplete report data") from error
        log_event(actor["user_id"], REPORT_GENERATED, f"Generated {name} report", "Information", "reports")
        return data

    def summary(self):
        users, assets, incidents, threats, vulnerabilities, logs = [
            self.fetch(source) for source in ("users", "assets", "incidents", "threats", "vulnerabilities", "logs")]
        return {
            "users": len(users), "assets": len(assets),
            "open_incidents": sum(row["status"] not in ("Resolved", "Closed") for row in incidents),
            "critical_threats": sum(row["severity"] == "Critical" for row in threats),
            "critical_vulnerabilities": sum(row["severity"] == "Critical" for row in vulnerabilities),
            "recent_activities": self.recent(logs, "timestamp", 10),
        }

    def incidents(self):
        rows = self.fetch("incidents")
        return {"total": len(rows), "by_severity": self.counts(rows, "severity"), "by_status": self.counts(rows, "status")}

    def assets(self):
        rows = self.fetch("assets")
        return {"total": len(rows), "critical_assets": sum(row["criticality"] == "Critical" for row in rows), "by_type": self.counts(rows, "asset_type")}

    def threats(self):
        rows = self.fetch("threats")
        return {"total": len(rows), "by_severity": self.counts(rows, "severity"), "by_type": self.counts(rows, "threat_type"), "recent": self.recent(rows, "date_added", 5)}

    def vulnerabilities(self):
        rows = self.fetch("vulnerabilities")
        return {"total": len(rows), "by_severity": self.counts(rows, "severity"), "by_status": self.counts(rows, "status"), "critical": [row for row in rows if row["severity"] == "Critical"]}

    def activity(self):
        rows = self.fetch("logs")
        actions = Counter(row["action"] for row in rows)
        return {"total_activities": len(rows), "login_attempts": actions[LOGIN_SUCCESS] + actions[LOGIN_FAILED], "failed_logins": actions[LOGIN_FAILED],
                "top_actions": [{"action": action, "count": count} for action, count in sorted(actions.items(), key=lambda item: (-item[1], item[0]))[:5]]}
