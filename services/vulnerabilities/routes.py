"""HTTP routes for the vulnerabilities service."""

from flask import Blueprint

from common.errors import success_response
from services.vulnerabilities.service import VulnerabilitiesService

blueprint = Blueprint("vulnerabilities", __name__)
service = VulnerabilitiesService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return vulnerabilities service health."""
    return success_response("vulnerabilities service is healthy", service.health())
