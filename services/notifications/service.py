"""Business logic for notifications service."""

import requests
from werkzeug.exceptions import ServiceUnavailable

from common.config import SERVICE_URLS
from common.constants import DATA_CREATED, INCIDENT_SEVERITIES, NOTIFICATION_TYPES
from common.db import db
from common.errors import NotFoundError, ValidationError
from common.models import Notification
from common.service_client import call_service, log_event
from common.validators import require_fields, valid_enum


class NotificationsService:
    def create(self, data, actor):
        allowed = {"user_id", "title", "message", "notification_type", "severity"}
        require_fields(data, allowed, allowed)
        user_id = data["user_id"]
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            raise ValidationError("user_id must be a positive integer")
        if not valid_enum(data["notification_type"], NOTIFICATION_TYPES):
            raise ValidationError("notification_type is not supported")
        if not valid_enum(data["severity"], INCIDENT_SEVERITIES):
            raise ValidationError("severity is not supported")
        try:
            response = call_service("GET", "users", "/users")
        except requests.RequestException as error:
            raise ServiceUnavailable("Users service is unavailable") from error
        if response.status_code != 200:
            raise ServiceUnavailable("Users service could not verify the notification recipient")
        users = response.json().get("data", {}).get("users", [])
        if not any(user.get("id") == user_id for user in users):
            raise NotFoundError("Notification recipient user not found")

        notification = Notification(
            user_id=user_id, title=data["title"], message=data["message"],
            notification_type=data["notification_type"], severity=data["severity"],
        )
        db.session.add(notification)
        db.session.commit()
        log_event(actor.get("user_id"), DATA_CREATED, f"Created notification {notification.id}", "Information", "notifications")
        return self.serialize(notification)

    @staticmethod
    def serialize(notification):
        return {
            "id": notification.id,
            "user_id": notification.user_id,
            "title": notification.title,
            "message": notification.message,
            "notification_type": notification.notification_type,
            "severity": notification.severity,
            "status": notification.status,
            "created_at": notification.created_at.isoformat() if notification.created_at else None,
            "read_at": notification.read_at.isoformat() if notification.read_at else None,
        }

    def health(self):
        return {"service": "notifications", "status": "healthy"}
