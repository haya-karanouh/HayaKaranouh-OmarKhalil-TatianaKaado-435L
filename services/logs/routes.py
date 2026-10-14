"""HTTP routes for the logs service."""

from flask import Blueprint

from common.errors import success_response
from services.logs.service import LogsService

blueprint = Blueprint("logs", __name__)
service = LogsService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return logs service health."""
    return success_response("logs service is healthy", service.health())
