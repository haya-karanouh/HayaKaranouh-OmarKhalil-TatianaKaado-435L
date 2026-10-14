"""HTTP routes for the reports service."""

from flask import Blueprint, g, request
from common.auth import require_roles
from common.constants import ADMIN, AUDITOR

from common.errors import success_response
from services.reports.service import ReportsService

blueprint = Blueprint("reports", __name__)
service = ReportsService()


@blueprint.get("/health")
def health():
    """Author: Tatiana Kaado. Return reports service health."""
    return success_response("reports service is healthy", service.health())


@blueprint.get("/reports/summary")
@require_roles(ADMIN, AUDITOR)
def summary():
    """Author: Tatiana Kaado. Summarize security data from source APIs."""
    return success_response("Summary report generated", service.generate("summary", g.user, request.args))


@blueprint.get("/reports/incidents")
@require_roles(ADMIN, AUDITOR)
def incidents():
    """Author: Tatiana Kaado. Generate the incidents report from HTTP sources."""
    return success_response("incidents report generated", service.generate("incidents", g.user, request.args))
