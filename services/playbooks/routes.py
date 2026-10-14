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


@blueprint.get('/playbooks')
@require_roles(ADMIN, ANALYST, AUDITOR)
def list_playbooks():
    """Author: Omar Khalil. Playbooks retrieved."""
    return success_response('Playbooks retrieved', {'playbooks': service.list()})


@blueprint.get('/playbooks/<int:playbook_id>')
@require_roles(ADMIN, ANALYST, AUDITOR)
def get(playbook_id):
    """Author: Omar Khalil. Playbook retrieved."""
    return success_response('Playbook retrieved', service.get(playbook_id))


@blueprint.post('/playbooks/<int:playbook_id>/actions')
@require_roles(ADMIN, ANALYST)
def add_action(playbook_id):
    """Author: Omar Khalil. Response action created."""
    return success_response('Response action created', service.add_action(playbook_id, require_json_body(), g.user), 201)
