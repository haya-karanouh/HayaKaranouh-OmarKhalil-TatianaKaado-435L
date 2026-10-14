"""HTTP routes for the notifications service."""

from flask import Blueprint

from common.errors import success_response
from services.notifications.service import NotificationsService

blueprint = Blueprint("notifications", __name__)
service = NotificationsService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return notifications service health."""
    return success_response("notifications service is healthy", service.health())
