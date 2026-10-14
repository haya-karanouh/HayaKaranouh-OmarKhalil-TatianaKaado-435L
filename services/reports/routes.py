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


@blueprint.get("/reports/assets")
@require_roles(ADMIN, AUDITOR)
def assets():
    """Author: Tatiana Kaado. Generate the assets report from HTTP sources."""
    return success_response("assets report generated", service.generate("assets", g.user, request.args))


@blueprint.get("/reports/threats")
@require_roles(ADMIN, AUDITOR)
def threats():
    """Author: Tatiana Kaado. Generate the threats report from HTTP sources."""
    return success_response("threats report generated", service.generate("threats", g.user, request.args))


@blueprint.get("/reports/vulnerabilities")
@require_roles(ADMIN, AUDITOR)
def vulnerabilities():
    """Author: Tatiana Kaado. Generate the vulnerabilities report from HTTP sources."""
    return success_response("vulnerabilities report generated", service.generate("vulnerabilities", g.user, request.args))


@blueprint.get("/reports/activity")
@require_roles(ADMIN, AUDITOR)
def activity():
    """Author: Tatiana Kaado. Generate the activity report from HTTP sources."""
    return success_response("activity report generated", service.generate("activity", g.user, request.args))
