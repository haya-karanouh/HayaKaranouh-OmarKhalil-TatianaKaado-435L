"""HTTP routes for the incidents service."""

from flask import Blueprint

from common.errors import success_response
from services.incidents.service import IncidentsService

blueprint = Blueprint("incidents", __name__)
service = IncidentsService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return incidents service health."""
    return success_response("incidents service is healthy", service.health())
