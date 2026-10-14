"""HTTP routes for the users service."""

from flask import Blueprint

from common.errors import success_response
from services.users.service import UsersService

blueprint = Blueprint("users", __name__)
service = UsersService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return users service health."""
    return success_response("users service is healthy", service.health())
