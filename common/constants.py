"""Canonical role, status, and audit-action names."""

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"
SERVICE = "Service"

ROLES = [ADMIN, ANALYST, EMPLOYEE, AUDITOR, SERVICE]
ACCOUNT_STATUSES = ["Active", "Inactive", "Suspended"]
ASSET_CRITICALITIES = ["Low", "Medium", "High", "Critical"]
ASSET_STATUSES = ["Active", "Inactive", "Under Maintenance"]
INCIDENT_SEVERITIES = ["Low", "Medium", "High", "Critical"]
INCIDENT_STATUSES = ["Open", "Under Investigation", "Mitigated", "Resolved", "Closed"]
THREAT_TYPES = ["IP Address", "Domain", "File Hash", "Malware Signature", "Other"]
LOG_SEVERITIES = ["Information", "Warning", "Error", "Critical"]
VULNERABILITY_STATUSES = ["Open", "Under Investigation", "In Progress", "Resolved", "Closed"]
NOTIFICATION_TYPES = ["Incident Assignment", "Security Alert", "System Notification", "Threat Alert", "Vulnerability Alert"]
NOTIFICATION_STATUSES = ["Unread", "Read"]
RESPONSE_ACTION_STATUSES = ["Pending", "In Progress", "Completed"]

LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILED = "LOGIN_FAILED"
USER_CREATED = "USER_CREATED"
USER_UPDATED = "USER_UPDATED"
USER_DELETED = "USER_DELETED"
ROLE_CHANGED = "ROLE_CHANGED"
UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
DATA_CREATED = "DATA_CREATED"
DATA_UPDATED = "DATA_UPDATED"
DATA_DELETED = "DATA_DELETED"
INCIDENT_ASSIGNED = "INCIDENT_ASSIGNED"
STATUS_CHANGED = "STATUS_CHANGED"
REPORT_GENERATED = "REPORT_GENERATED"
LOG_ACTIONS = [
    LOGIN_SUCCESS, LOGIN_FAILED, USER_CREATED, USER_UPDATED, USER_DELETED,
    ROLE_CHANGED, UNAUTHORIZED_ACCESS, DATA_CREATED, DATA_UPDATED,
    DATA_DELETED, INCIDENT_ASSIGNED, STATUS_CHANGED, REPORT_GENERATED,
]
