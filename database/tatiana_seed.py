"""Idempotent threat and vulnerability samples. Author: Tatiana Kaado."""
from datetime import datetime
from common.constants import THREAT_TYPES, INCIDENT_SEVERITIES, VULNERABILITY_STATUSES
from common.db import db
from common.models import Asset, Threat, Vulnerability


def seed_tatiana_data():
    """Cover every shared threat type, severity and vulnerability status."""
    for index, kind in enumerate(THREAT_TYPES):
        for level, severity in enumerate(INCIDENT_SEVERITIES):
            value = [f"192.0.2.{level + 1}", f"indicator-{level}.example", f"{level + 1:064x}",
                     f"DEMO_SIGNATURE_{level}", f"demo-indicator-{level}"][index]
            if not db.session.query(Threat).filter_by(threat_type=kind, threat_value=value).first():
                db.session.add(Threat(threat_type=kind, threat_value=value, description=f"Synthetic {severity} {kind} indicator", severity=severity, source="Development seed"))
    assets = db.session.query(Asset).order_by(Asset.id).all()
    if not assets:
        raise RuntimeError("Seed assets before Tatiana's vulnerabilities")
    for index, status in enumerate(VULNERABILITY_STATUSES):
        for level, (severity, score) in enumerate(zip(INCIDENT_SEVERITIES, [2.5, 5.5, 8.0, 9.5])):
            title = f"Seed {severity} vulnerability - {status}"
            if not db.session.query(Vulnerability).filter_by(title=title).first():
                now = datetime.utcnow()
                db.session.add(Vulnerability(title=title, description="Synthetic scanner finding for report demonstrations", cve_id=f"CVE-2026-{1000 + index * 4 + level}", cvss_score=score, severity=severity, asset_id=assets[level % len(assets)].id, discovery_source="Development scanner", status=status, created_at=now, resolved_at=now if status in ("Resolved", "Closed") else None))
    db.session.commit()
