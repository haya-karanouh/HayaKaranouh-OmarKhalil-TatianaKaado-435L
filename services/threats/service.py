"""Threat intelligence business logic. Author: Tatiana Kaado."""

import requests
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import ServiceUnavailable
from common.constants import ADMIN, DATA_CREATED, INCIDENT_SEVERITIES, THREAT_TYPES
from common.db import db
from common.errors import ConflictError, ValidationError
from common.models import Threat
from common.service_client import call_service, log_event, notify
from common.validators import require_fields, valid_domain, valid_hash, valid_ipv4


class ThreatsService:
    def health(self):
        return {"service": "threats", "status": "healthy"}

    @staticmethod
    def serialize(row):
        return {column.name: (value.isoformat() if hasattr(value, "isoformat") else value)
                for column in Threat.__table__.columns
                for value in [getattr(row, column.name)]}

    @staticmethod
    def validate(data):
        for field, limit in [("threat_value", 512), ("description", None), ("source", 160)]:
            if field in data and (not isinstance(data[field], str) or not data[field].strip()
                                  or (limit and len(data[field]) > limit)):
                raise ValidationError(f"{field} must be non-empty text" + (f" of at most {limit} characters" if limit else ""))
        for field, choices in [("threat_type", THREAT_TYPES), ("severity", INCIDENT_SEVERITIES)]:
            if field in data and data[field] not in choices:
                raise ValidationError(f"{field} must be one of: {', '.join(choices)}")
        kind = data.get("threat_type")
        validator = next((check for name, check in [("IP Address", valid_ipv4), ("Domain", valid_domain), ("File Hash", valid_hash)] if name == kind), None)
        if validator and not validator(data.get("threat_value")):
            raise ValidationError("threat_value must match its type: IPv4, domain, or MD5/SHA1/SHA256")

    def create(self, data, actor):
        fields = {"threat_type", "threat_value", "description", "severity", "source"}
        require_fields(data, fields, fields)
        self.validate(data)
        data = dict(data)
        if data["threat_type"] in ("Domain", "File Hash"):
            data["threat_value"] = data["threat_value"].lower().rstrip(".")
        if db.session.query(Threat).filter_by(threat_type=data["threat_type"], threat_value=data["threat_value"]).first():
            raise ConflictError("Threat type and value already exist")
        admins = self.admins() if data["severity"] == "Critical" else []
        row = Threat(**data)
        db.session.add(row)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise ConflictError("Threat type and value already exist") from error
        log_event(actor["user_id"], DATA_CREATED, f"Created threat {row.id}", "Information", "threats")
        for admin in admins:
            notify(admin["id"], "Critical threat", f"Threat {row.id}: {row.threat_value}", "Threat Alert", "Critical")
        return self.serialize(row)

    @staticmethod
    def admins():
        try:
            response = call_service("GET", "users", "/users", params={"role": ADMIN})
            if response.status_code != 200:
                raise ServiceUnavailable("Users service could not retrieve administrators")
            return response.json()["data"]["users"]
        except (requests.RequestException, ValueError, KeyError, TypeError) as error:
            raise ServiceUnavailable("Users service is unavailable") from error

    def list(self, filters=None):
        filters = dict(filters or {})
        require_fields(filters, set(), {"threat_type", "threat_value", "severity", "source"})
        self.validate({key: value for key, value in filters.items() if key != "threat_type"})
        if "threat_type" in filters and filters["threat_type"] not in THREAT_TYPES:
            raise ValidationError("Invalid threat_type")
        query = db.session.query(Threat)
        for field, value in filters.items():
            column = getattr(Threat, field)
            query = query.filter(column.contains(value, autoescape=True) if field == "threat_value" else column == value)
        return [self.serialize(row) for row in query.order_by(Threat.id).all()]

    @staticmethod
    def find(threat_id):
        from common.errors import NotFoundError
        row = db.session.get(Threat, threat_id)
        if row is None:
            raise NotFoundError("Threat not found")
        return row

    def get(self, threat_id):
        return self.serialize(self.find(threat_id))

    def update(self, threat_id, data, actor):
        from common.constants import DATA_UPDATED
        row = self.find(threat_id)
        require_fields(data, set(), {"description", "severity", "source"})
        self.validate(data)
        admins = self.admins() if data.get("severity") == "Critical" and row.severity != "Critical" else []
        for field, value in data.items():
            setattr(row, field, value)
        db.session.commit()
        log_event(actor["user_id"], DATA_UPDATED, f"Updated threat {row.id}: {sorted(data)}", "Information", "threats")
        for admin in admins:
            notify(admin["id"], "Critical threat", f"Threat {row.id}: {row.threat_value}", "Threat Alert", "Critical")
        return self.serialize(row)
