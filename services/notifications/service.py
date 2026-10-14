"""Business logic for notifications service."""

from datetime import datetime
import requests
from werkzeug.exceptions import ServiceUnavailable

from common.config import SERVICE_URLS
from common.constants import (
    ADMIN, ANALYST, AUDITOR, DATA_CREATED, DATA_DELETED, EMPLOYEE, INCIDENT_SEVERITIES,
    NOTIFICATION_STATUSES, NOTIFICATION_TYPES, SERVICE, STATUS_CHANGED,
)
from common.db import db
from common.errors import NotFoundError, PermissionDenied, ValidationError
from common.models import Notification, User
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

    def list_for_user(self, user_id, actor):
        if db.session.get(User, user_id) is None:
            raise NotFoundError("User not found")
        privileged_roles = {ADMIN, AUDITOR, SERVICE}
        if actor["role"] not in privileged_roles and actor["user_id"] != user_id:
            raise PermissionDenied("You may only view your own notifications")
        notifications = db.session.query(Notification).filter_by(user_id=user_id).order_by(
            Notification.created_at.desc(), Notification.id.desc()
        ).all()
        return [self.serialize(notification) for notification in notifications]

    def get_notification(self, notification_id, actor):
        notification = db.session.get(Notification, notification_id)
        if notification is None:
            raise NotFoundError("Notification not found")
        privileged_roles = {ADMIN, AUDITOR, SERVICE}
        if actor["role"] not in privileged_roles and actor["user_id"] != notification.user_id:
            raise PermissionDenied("You may only view your own notifications")
        return self.serialize(notification)

    def mark_read(self, notification_id, actor):
        notification = db.session.get(Notification, notification_id)
        if notification is None:
            raise NotFoundError("Notification not found")
        if actor["role"] not in {ADMIN, SERVICE} and actor["user_id"] != notification.user_id:
            raise PermissionDenied("You may only update your own notifications")
        if notification.status == "Read":
            return {"notification": self.serialize(notification), "already_read": True}
        notification.status = "Read"
        notification.read_at = datetime.utcnow()
        db.session.commit()
        log_event(actor.get("user_id"), STATUS_CHANGED, f"Marked notification {notification.id} as read", "Information", "notifications")
        return {"notification": self.serialize(notification), "already_read": False}

    def search(self, filters):
        allowed = {"user_id", "notification_type", "severity", "status"}
        unexpected = set(filters) - allowed
        if unexpected:
            raise ValidationError(f"Unexpected search filters: {', '.join(sorted(unexpected))}")
        query = db.session.query(Notification)
        if filters.get("user_id"):
            try:
                user_id = int(filters["user_id"])
            except (TypeError, ValueError) as error:
                raise ValidationError("user_id must be a positive integer") from error
            if user_id < 1:
                raise ValidationError("user_id must be a positive integer")
            query = query.filter(Notification.user_id == user_id)
        for field, allowed_values in (
            ("notification_type", NOTIFICATION_TYPES),
            ("severity", INCIDENT_SEVERITIES),
            ("status", NOTIFICATION_STATUSES),
        ):
            value = filters.get(field)
            if value:
                if not valid_enum(value, allowed_values):
                    raise ValidationError(f"{field} is not supported")
                query = query.filter(getattr(Notification, field) == value)
        notifications = query.order_by(Notification.created_at.desc(), Notification.id.desc()).all()
        return [self.serialize(notification) for notification in notifications]

    def delete_notification(self, notification_id, actor):
        notification = db.session.get(Notification, notification_id)
        if notification is None:
            raise NotFoundError("Notification not found")
        db.session.delete(notification)
        db.session.commit()
        log_event(actor.get("user_id"), DATA_DELETED, f"Deleted notification {notification_id}", "Warning", "notifications")
        return {"id": notification_id}

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
