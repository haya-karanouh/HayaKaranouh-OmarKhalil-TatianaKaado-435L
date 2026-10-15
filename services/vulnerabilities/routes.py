"""HTTP routes for the vulnerabilities service."""

from flask import Blueprint, g, request
from common.auth import require_roles
from common.constants import ADMIN, ANALYST, AUDITOR
from common.validators import require_json_body
from werkzeug.exceptions import BadRequest

from common.errors import success_response
from services.vulnerabilities.service import VulnerabilitiesService

blueprint = Blueprint("vulnerabilities", __name__)
service = VulnerabilitiesService()


@blueprint.get("/health")
def health():
    """Author: Tatiana Kaado. Return vulnerabilities service health."""
    return success_response("vulnerabilities service is healthy", service.health())


@blueprint.before_request
def check_json():
    if request.is_json:
        try:
            request.get_json()
        except BadRequest:
            raise BadRequest("Malformed JSON body")


@blueprint.post("/vulnerabilities")
@require_roles(ADMIN)
def create():
    """Author: Tatiana Kaado. Create a validated vulnerability."""
    return success_response("Vulnerability created", service.create(require_json_body(), g.user), 201)

@blueprint.get("/vulnerabilities")
@require_roles(ADMIN, ANALYST, AUDITOR)
def list_vulnerabilities():
    """Author: Tatiana Kaado. List vulnerabilities with linked asset details."""
    return success_response("Vulnerabilities retrieved", {"vulnerabilities": service.list()})

@blueprint.get("/vulnerabilities/<int:vulnerability_id>")
@require_roles(ADMIN, ANALYST, AUDITOR)
def get(vulnerability_id):
    """Author: Tatiana Kaado. Retrieve a vulnerability and its asset."""
    return success_response("Vulnerability retrieved", service.get(vulnerability_id))

@blueprint.put("/vulnerabilities/<int:vulnerability_id>")
@require_roles(ADMIN, ANALYST)
def update(vulnerability_id):
    """Author: Tatiana Kaado. Update permitted fields and advance status."""
    return success_response("Vulnerability updated", service.update(vulnerability_id, require_json_body(), g.user))

@blueprint.get("/vulnerabilities/search")
@require_roles(ADMIN, ANALYST, AUDITOR)
def search():
    """Author: Tatiana Kaado. Search CVE, severity, asset and status."""
    return success_response("Vulnerabilities retrieved", {"vulnerabilities": service.list(request.args)})

@blueprint.delete("/vulnerabilities/<int:vulnerability_id>")
@require_roles(ADMIN)
def delete(vulnerability_id):
    """Author: Tatiana Kaado. Delete a vulnerability as administrator."""
    return success_response("Vulnerability deleted", service.delete(vulnerability_id, g.user))
