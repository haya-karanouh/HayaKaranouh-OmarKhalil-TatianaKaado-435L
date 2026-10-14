"""HTTP routes for the notifications service."""

from flask import Blueprint, g

from common.auth import require_roles
from common.constants import ADMIN, ANALYST, AUDITOR, EMPLOYEE, SERVICE
from common.errors import success_response
from common.validators import require_fields, require_json_body
from services.notifications.service import NotificationsService

blueprint = Blueprint("notifications", __name__)
service = NotificationsService()


@blueprint.post("/notifications")
@require_roles(ADMIN, SERVICE)
def create_notification():
    """Author: Haya Karanouh. Create a notification for a verified user."""
    allowed = {"user_id", "title", "message", "notification_type", "severity"}
    data = require_json_body(allowed)
    require_fields(data, allowed, allowed)
    return success_response("Notification created", service.create(data, g.user), 201)


@blueprint.get("/notifications/user/<int:user_id>")
@require_roles(ADMIN, AUDITOR, ANALYST, EMPLOYEE, SERVICE)
def notifications_for_user(user_id):
    """Author: Haya Karanouh. List notifications within the caller's ownership scope."""
    notifications = service.list_for_user(user_id, g.user)
    return success_response("Notifications retrieved", {"notifications": notifications})


@blueprint.get("/notifications/<int:notification_id>")
@require_roles(ADMIN, AUDITOR, ANALYST, EMPLOYEE, SERVICE)
def get_notification(notification_id):
    """Author: Haya Karanouh. Retrieve one notification within the caller's scope."""
    return success_response("Notification retrieved", service.get_notification(notification_id, g.user))


@blueprint.put("/notifications/<int:notification_id>/read")
@require_roles(ADMIN, ANALYST, EMPLOYEE, SERVICE)
def mark_notification_read(notification_id):
    """Author: Haya Karanouh. Mark an owned notification as read."""
    result = service.mark_read(notification_id, g.user)
    message = "Notification was already read" if result["already_read"] else "Notification marked as read"
    return success_response(message, result["notification"])


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return notifications service health."""
    return success_response("notifications service is healthy", service.health())
