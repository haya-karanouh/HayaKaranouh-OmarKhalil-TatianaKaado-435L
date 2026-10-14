"""Business logic for logs service."""

from common.config import SERVICE_PORTS
from common.constants import LOG_ACTIONS, LOG_SEVERITIES
from common.db import db
from common.errors import NotFoundError, ValidationError
from common.models import Log, User
from common.validators import require_fields, valid_enum


class LogsService:
    def create(self, data):
        allowed = {"user_id", "action", "description", "severity", "related_service"}
        require_fields(data, {"action", "description", "severity", "related_service"}, allowed)
        if not valid_enum(data["action"], LOG_ACTIONS):
            raise ValidationError("action is not supported")
        if not valid_enum(data["severity"], LOG_SEVERITIES):
            raise ValidationError("severity is not supported")
        if data["related_service"] not in SERVICE_PORTS:
            raise ValidationError("related_service is not supported")
        user_id = data.get("user_id")
        if user_id is not None:
            if isinstance(user_id, bool) or not isinstance(user_id, int):
                raise ValidationError("user_id must be an integer or null")
            if db.session.get(User, user_id) is None:
                raise NotFoundError("User not found")
        record = Log(
            user_id=user_id, action=data["action"], description=data["description"],
            severity=data["severity"], related_service=data["related_service"],
        )
        db.session.add(record)
        db.session.commit()
        return self.serialize(record)

    def list_logs(self):
        records = db.session.query(Log).order_by(Log.timestamp.desc(), Log.id.desc()).all()
        return [self.serialize(record) for record in records]

    def get_log(self, log_id):
        record = db.session.get(Log, log_id)
        if record is None:
            raise NotFoundError("Log not found")
        return self.serialize(record)

    @staticmethod
    def serialize(record):
        return {
            "id": record.id,
            "user_id": record.user_id,
            "action": record.action,
            "description": record.description,
            "timestamp": record.timestamp.isoformat() if record.timestamp else None,
            "severity": record.severity,
            "related_service": record.related_service,
        }

    def health(self):
        return {"service": "logs", "status": "healthy"}
