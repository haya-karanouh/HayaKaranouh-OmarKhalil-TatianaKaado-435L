"""Idempotent sample domain data. Author: Omar Khalil."""
from common.db import db
from common.models import User, Asset, Incident, Playbook, ResponseAction


def seed_omar_data():
    """Insert several assets, four incident severities and two ordered playbooks."""
    users = {user.username: user.id for user in db.session.query(User).all()}
    assets = []
    for index, (name, kind, criticality) in enumerate([
        ('Development Workstation', 'Workstation', 'Low'),
        ('Mail Application', 'Application', 'Medium'),
        ('Production Server', 'Server', 'High'),
        ('Customer Database', 'Database', 'Critical'),
    ], 1):
        asset = db.session.query(Asset).filter_by(name=name, ip_address=f'10.0.0.{index}').first()
        if asset is None:
            asset = Asset(name=name, asset_type=kind, ip_address=f'10.0.0.{index}', owner_id=users['employee'], department='Engineering', location='Beirut', criticality=criticality, status='Active')
            db.session.add(asset)
            db.session.flush()
        assets.append(asset)
    for asset, severity, description in zip(assets, ['Low', 'Medium', 'High', 'Critical'], [
        'Blocked suspicious attachment on an isolated development workstation; no execution.',
        'Phishing message delivered to a mailbox; exposure requires investigation.',
        'Malware execution on a production server threatens service availability.',
        'Confirmed leakage of customer data threatens confidentiality across the organization.',
    ]):
        title = f'Seed {severity} security incident'
        if db.session.query(Incident).filter_by(title=title).first() is None:
            db.session.add(Incident(title=title, description=description, category='Data Leakage' if severity == 'Critical' else 'Malware' if severity == 'High' else 'Phishing', severity=severity, reporter_id=users['employee'], asset_id=asset.id, status='Open'))
    for name, category in [('Phishing Response', 'Phishing'), ('Malware Containment', 'Malware')]:
        playbook = db.session.query(Playbook).filter_by(name=name).first()
        if playbook is None:
            playbook = Playbook(name=name, description=f'Ordered procedure for {category.lower()} incidents', incident_category=category, severity='High', created_by=users['admin'])
            db.session.add(playbook)
            db.session.flush()
            for step, description in enumerate(['Contain the affected resource', 'Investigate and collect evidence', 'Restore service and document findings'], 1):
                db.session.add(ResponseAction(playbook_id=playbook.id, description=description, step_number=step, status='Pending', assigned_user_id=users['analyst']))
    db.session.commit()
