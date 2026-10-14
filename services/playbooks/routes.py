"""HTTP routes for the playbooks service."""

from flask import Blueprint

from common.errors import success_response
from services.playbooks.service import PlaybooksService

blueprint = Blueprint("playbooks", __name__)
service = PlaybooksService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return playbooks service health."""
    return success_response("playbooks service is healthy", service.health())
