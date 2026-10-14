"""HTTP routes for the assets service."""

from flask import Blueprint

from common.errors import success_response
from services.assets.service import AssetsService

blueprint = Blueprint("assets", __name__)
service = AssetsService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return assets service health."""
    return success_response("assets service is healthy", service.health())
