"""HTTP routes for the incidents service."""

from flask import Blueprint, g, request
from common.auth import require_roles
from common.constants import ADMIN, ANALYST, AUDITOR, EMPLOYEE
from common.validators import require_json_body

from common.errors import success_response
from services.incidents.service import IncidentsService

blueprint = Blueprint("incidents", __name__)
service = IncidentsService()


@blueprint.get("/health")
def health():
    """Author: Omar Khalil. Return incidents service health."""
    return success_response("incidents service is healthy", service.health())


@blueprint.post('/incidents')
@require_roles(ADMIN, EMPLOYEE)
def create():
    """Author: Omar Khalil. Incident created."""
    return success_response('Incident created', service.create(require_json_body(), g.user), 201)


@blueprint.get('/incidents')
@require_roles(ADMIN, AUDITOR)
def list_incidents():
    """Author: Omar Khalil. Incidents retrieved."""
    return success_response('Incidents retrieved', {'incidents': service.list(request.args)})


@blueprint.get('/incidents/<int:incident_id>')
@require_roles(ADMIN, ANALYST, AUDITOR, EMPLOYEE)
def get(incident_id):
    """Author: Omar Khalil. Incident retrieved."""
    return success_response('Incident retrieved', service.get(incident_id, g.user))


@blueprint.put('/incidents/<int:incident_id>/assign')
@require_roles(ADMIN)
def assign(incident_id):
    """Author: Omar Khalil. Incident assigned."""
    return success_response('Incident assigned', service.assign(incident_id, require_json_body(), g.user))
