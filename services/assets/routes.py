"""HTTP routes for the assets service."""

from flask import Blueprint, g, request
from common.auth import require_roles
from common.constants import ADMIN, ANALYST, AUDITOR
from common.validators import require_json_body

from common.errors import success_response
from services.assets.service import AssetsService

blueprint = Blueprint("assets", __name__)
service = AssetsService()


@blueprint.get("/health")
def health():
    """Author: Omar Khalil. Return assets service health."""
    return success_response("assets service is healthy", service.health())


@blueprint.post('/assets')
@require_roles(ADMIN)
def create():
    """Author: Omar Khalil. Asset created."""
    return success_response('Asset created', service.create(require_json_body(), g.user), 201)


@blueprint.put('/assets/<int:asset_id>')
@require_roles(ADMIN)
def update(asset_id):
    """Author: Omar Khalil. Asset updated."""
    return success_response('Asset updated', service.update(asset_id, require_json_body(), g.user))
