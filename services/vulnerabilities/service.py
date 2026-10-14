"""Vulnerability business logic. Author: Tatiana Kaado."""

from datetime import datetime, timezone
import requests
from werkzeug.exceptions import ServiceUnavailable
from common.constants import ADMIN, DATA_CREATED, INCIDENT_SEVERITIES, VULNERABILITY_STATUSES
from common.db import db
from common.errors import ValidationError, NotFoundError
from common.models import Vulnerability
from common.service_client import call_service, log_event, notify
from common.validators import require_fields, valid_cve, valid_cvss


class VulnerabilitiesService:
    def health(self):
        return {"service": "vulnerabilities", "status": "healthy"}

    @staticmethod
    def assets():
        # The list API avoids the asset detail API's reverse vulnerability lookup.
        try:
            response = call_service("GET", "assets", "/assets")
            if response.status_code != 200:
                raise ServiceUnavailable("Assets service could not retrieve assets")
            return {item["id"]: item for item in response.json()["data"]["assets"]}
        except (requests.RequestException, ValueError, KeyError, TypeError) as error:
            raise ServiceUnavailable("Assets service is unavailable") from error

    @staticmethod
    def admins():
        try:
            response = call_service("GET", "users", "/users", params={"role": ADMIN})
            if response.status_code != 200:
                raise ServiceUnavailable("Users service could not retrieve administrators")
            return response.json()["data"]["users"]
        except (requests.RequestException, ValueError, KeyError, TypeError) as error:
            raise ServiceUnavailable("Users service is unavailable") from error

    @staticmethod
    def serialize(row, assets):
        data = {column.name: (value.isoformat() if hasattr(value, "isoformat") else value)
                for column in Vulnerability.__table__.columns
                for value in [getattr(row, column.name)]}
        asset = assets.get(row.asset_id)
        if asset is None:
            raise ServiceUnavailable(f"Assets service omitted linked asset {row.asset_id}")
        data.update(asset_name=asset["name"], asset_status=asset["status"])
        return data

    @staticmethod
    def validate(data, row=None):
        for field, limit in [("title", 200), ("description", None), ("discovery_source", 160)]:
            if field in data and (not isinstance(data[field], str) or not data[field].strip()
                                  or (limit and len(data[field]) > limit)):
                raise ValidationError(f"{field} must be non-empty text" + (f" of at most {limit} characters" if limit else ""))
        if "cve_id" in data and (not valid_cve(data["cve_id"]) or len(data["cve_id"]) > 32):
            raise ValidationError("cve_id must use CVE-YYYY-NNNN format (maximum 32 characters)")
        if "asset_id" in data and (type(data["asset_id"]) is not int or data["asset_id"] < 1):
            raise ValidationError("asset_id must be a positive integer")
        score = data.get("cvss_score", row.cvss_score if row else None)
        severity = data.get("severity", row.severity if row else None)
        if not valid_cvss(score):
            raise ValidationError("cvss_score must be between 0 and 10")
        score = float(score)
        # The shared enum has no None severity; zero is represented as Low.
        expected = "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"
        if severity not in INCIDENT_SEVERITIES or severity != expected:
            raise ValidationError(f"Severity must be {expected} for CVSS {score}")
        if "status" in data and data["status"] not in VULNERABILITY_STATUSES:
            raise ValidationError("Invalid vulnerability status")

    def create(self, data, actor):
        fields = {"title", "description", "cve_id", "cvss_score", "severity", "asset_id", "discovery_source"}
        require_fields(data, fields, fields)
        self.validate(data)
        assets = self.assets()
        if data["asset_id"] not in assets:
            raise NotFoundError("Asset not found")
        admins = self.admins() if data["severity"] == "Critical" else []
        row = Vulnerability(**{**data, "cvss_score": float(data["cvss_score"])}, status="Open")
        db.session.add(row)
        db.session.commit()
        log_event(actor["user_id"], DATA_CREATED, f"Created vulnerability {row.id}", "Information", "vulnerabilities")
        for admin in admins:
            notify(admin["id"], "Critical vulnerability", f"Vulnerability {row.id}: {row.title}", "Vulnerability Alert", "Critical")
        return self.serialize(row, assets)
