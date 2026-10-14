"""Shared SQLAlchemy models for all nine services."""

from datetime import datetime

from sqlalchemy import UniqueConstraint

from common.constants import (
    ACCOUNT_STATUSES, ASSET_CRITICALITIES, ASSET_STATUSES, INCIDENT_SEVERITIES,
    INCIDENT_STATUSES, LOG_SEVERITIES, NOTIFICATION_STATUSES,
    NOTIFICATION_TYPES, RESPONSE_ACTION_STATUSES, THREAT_TYPES, ROLES,
    VULNERABILITY_STATUSES,
)
from common.db import db


def _enum(values, name):
    return db.Enum(*values, name=name, native_enum=False, create_constraint=True, validate_strings=True)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(160), nullable=False)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(254), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    department = db.Column(db.String(120), nullable=False)
    role = db.Column(_enum(ROLES, "user_role"), nullable=False)
    account_status = db.Column(_enum(ACCOUNT_STATUSES, "account_status"), nullable=False, default="Active")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)


class Asset(db.Model):
    __tablename__ = "assets"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    asset_type = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))
    operating_system = db.Column(db.String(120))
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    department = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(160), nullable=False)
    criticality = db.Column(_enum(ASSET_CRITICALITIES, "asset_criticality"), nullable=False)
    status = db.Column(_enum(ASSET_STATUSES, "asset_status"), nullable=False, default="Active")


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    severity = db.Column(_enum(INCIDENT_SEVERITIES, "incident_severity"), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"))
    assigned_analyst_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    status = db.Column(_enum(INCIDENT_STATUSES, "incident_status"), nullable=False, default="Open")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)


class InvestigationNote(db.Model):
    __tablename__ = "investigation_notes"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False)
    analyst_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Threat(db.Model):
    __tablename__ = "threats"
    __table_args__ = (
        UniqueConstraint("threat_type", "threat_value", name="uq_threat_type_value"),
    )

    id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(_enum(THREAT_TYPES, "threat_type"), nullable=False)
    threat_value = db.Column(db.String(512), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(_enum(INCIDENT_SEVERITIES, "threat_severity"), nullable=False)
    source = db.Column(db.String(160), nullable=False)
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    severity = db.Column(_enum(LOG_SEVERITIES, "log_severity"), nullable=False)
    related_service = db.Column(db.String(80), nullable=False)


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    cve_id = db.Column(db.String(32))
    cvss_score = db.Column(db.Float)
    severity = db.Column(_enum(INCIDENT_SEVERITIES, "vulnerability_severity"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    discovery_source = db.Column(db.String(160), nullable=False)
    status = db.Column(_enum(VULNERABILITY_STATUSES, "vulnerability_status"), nullable=False, default="Open")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)


class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(_enum(NOTIFICATION_TYPES, "notification_type"), nullable=False)
    severity = db.Column(_enum(INCIDENT_SEVERITIES, "notification_severity"), nullable=False)
    status = db.Column(_enum(NOTIFICATION_STATUSES, "notification_status"), nullable=False, default="Unread")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)


class Playbook(db.Model):
    __tablename__ = "playbooks"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False)
    incident_category = db.Column(db.String(100), nullable=False)
    severity = db.Column(_enum(INCIDENT_SEVERITIES, "playbook_severity"), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ResponseAction(db.Model):
    __tablename__ = "response_actions"
    __table_args__ = (
        UniqueConstraint("playbook_id", "step_number", name="uq_response_actions_playbook_step"),
    )

    id = db.Column(db.Integer, primary_key=True)
    playbook_id = db.Column(db.Integer, db.ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    description = db.Column(db.Text, nullable=False)
    step_number = db.Column(db.Integer, nullable=False)
    status = db.Column(_enum(RESPONSE_ACTION_STATUSES, "response_action_status"), nullable=False, default="Pending")
    assigned_user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    completed_at = db.Column(db.DateTime)
