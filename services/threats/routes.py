"""HTTP routes for the threats service."""

from flask import Blueprint, g, request
from werkzeug.exceptions import BadRequest
from common.auth import require_roles
from common.constants import ADMIN, ANALYST, AUDITOR
from common.validators import require_json_body

from common.errors import success_response
from services.threats.service import ThreatsService

blueprint = Blueprint("threats", __name__)
service = ThreatsService()


@blueprint.get("/health")
def health():
    """Author: Tatiana Kaado. Return threats service health."""
    return success_response("threats service is healthy", service.health())


@blueprint.before_request
def check_json():
    if request.is_json:
        try:
            request.get_json()
        except BadRequest:
            raise BadRequest("Malformed JSON body")


@blueprint.post("/threats")
@require_roles(ADMIN)
def create():
    """Author: Tatiana Kaado. Create a validated threat indicator."""
    return success_response("Threat created", service.create(require_json_body(), g.user), 201)

@blueprint.get("/threats")
@require_roles(ADMIN, ANALYST, AUDITOR)
def list_threats():
    """Author: Tatiana Kaado. List threat indicators."""
    return success_response("Threats retrieved", {"threats": service.list()})

@blueprint.get("/threats/<int:threat_id>")
@require_roles(ADMIN, ANALYST, AUDITOR)
def get(threat_id):
    """Author: Tatiana Kaado. Retrieve one threat."""
    return success_response("Threat retrieved", service.get(threat_id))

@blueprint.get("/threats/search")
@require_roles(ADMIN, ANALYST, AUDITOR)
def search():
    """Author: Tatiana Kaado. Search threats with combined filters."""
    return success_response("Threats retrieved", {"threats": service.list(request.args)})
