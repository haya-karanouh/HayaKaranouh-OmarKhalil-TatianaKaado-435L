"""HTTP routes for the logs service."""

from flask import Blueprint

from common.auth import require_roles
from common.constants import ADMIN, AUDITOR, SERVICE
from common.errors import success_response
from common.validators import require_fields, require_json_body
from services.logs.service import LogsService

blueprint = Blueprint("logs", __name__)
service = LogsService()


@blueprint.post("/logs")
@require_roles(ADMIN, SERVICE)
def create_log():
    """Author: Haya Karanouh. Create an audit record directly in the database."""
    allowed = {"user_id", "action", "description", "severity", "related_service"}
    data = require_json_body(allowed)
    require_fields(data, {"action", "description", "severity", "related_service"}, allowed)
    return success_response("Log created", service.create(data), 201)


@blueprint.get("/logs")
@require_roles(ADMIN, AUDITOR)
def list_logs():
    """Author: Haya Karanouh. List audit records for authorized reviewers."""
    return success_response("Logs retrieved", {"logs": service.list_logs()})


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return logs service health."""
    return success_response("logs service is healthy", service.health())
