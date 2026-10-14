"""HTTP routes for the playbooks service."""

from flask import Blueprint, g
from common.auth import require_roles
from common.constants import ADMIN, ANALYST, AUDITOR
from common.validators import require_json_body

from common.errors import success_response
from services.playbooks.service import PlaybooksService

blueprint = Blueprint("playbooks", __name__)
service = PlaybooksService()


@blueprint.get("/health")
def health():
    """Author: Omar Khalil. Return playbooks service health."""
    return success_response("playbooks service is healthy", service.health())


@blueprint.post('/playbooks')
@require_roles(ADMIN)
def create():
    """Author: Omar Khalil. Playbook created."""
    return success_response('Playbook created', service.create(require_json_body(), g.user), 201)
