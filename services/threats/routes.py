"""HTTP routes for the threats service."""

from flask import Blueprint

from common.errors import success_response
from services.threats.service import ThreatsService

blueprint = Blueprint("threats", __name__)
service = ThreatsService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return threats service health."""
    return success_response("threats service is healthy", service.health())
