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
