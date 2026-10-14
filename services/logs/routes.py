"""HTTP routes for the logs service."""

from flask import Blueprint, request

from common.auth import require_roles
from common.constants import ADMIN, ANALYST, AUDITOR, SERVICE
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


@blueprint.get("/logs/<int:log_id>")
@require_roles(ADMIN, AUDITOR, ANALYST)
def get_log(log_id):
    """Author: Haya Karanouh. Retrieve one audit record by ID."""
    return success_response("Log retrieved", service.get_log(log_id))


@blueprint.get("/logs/search")
@require_roles(ADMIN, AUDITOR, ANALYST)
def search_logs():
    """Author: Haya Karanouh. Search audit records using combined filters."""
    return success_response("Logs retrieved", {"logs": service.search(request.args.to_dict())})


@blueprint.get("/logs/user/<int:user_id>")
@require_roles(ADMIN, AUDITOR)
def logs_for_user(user_id):
    """Author: Haya Karanouh. Retrieve all audit records associated with a user."""
    logs = service.logs_for_user(user_id)
    message = "Logs retrieved" if logs else "No logs found for this user"
    return success_response(message, {"logs": logs})


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return logs service health."""
    return success_response("logs service is healthy", service.health())
