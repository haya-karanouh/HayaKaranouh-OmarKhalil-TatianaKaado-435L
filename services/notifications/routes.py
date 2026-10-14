"""HTTP routes for the notifications service."""

from flask import Blueprint, g

from common.auth import require_roles
from common.constants import ADMIN, SERVICE
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


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return notifications service health."""
    return success_response("notifications service is healthy", service.health())
