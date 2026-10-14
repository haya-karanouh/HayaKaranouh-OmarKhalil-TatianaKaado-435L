"""HTTP routes for the reports service."""

from flask import Blueprint

from common.errors import success_response
from services.reports.service import ReportsService

blueprint = Blueprint("reports", __name__)
service = ReportsService()


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return reports service health."""
    return success_response("reports service is healthy", service.health())
