"""Capture every requested scenario from live services. Author: Omar Khalil.

Start python run_all.py first, then run this module. This resets the development DB.
"""
import json
import sqlite3
import subprocess
import sys
import requests
from sqlalchemy.engine import make_url
from common.config import DATABASE_URL, PROJECT_ROOT, SERVICE_PORTS
from scripts.evidence.evidence_lib import EvidenceRecorder


def main():
    for service, port in SERVICE_PORTS.items():
        try:
            response = requests.get(f'http://127.0.0.1:{port}/health', timeout=3)
            if response.status_code != 200:
                raise RuntimeError(f'HTTP {response.status_code}')
        except (requests.RequestException, RuntimeError) as error:
            raise SystemExit(f'{service} is down on port {port}: {error}. Start all services with run_all.py before capturing evidence.')
    subprocess.run([sys.executable, '-m', 'database.seed', '--reset'], cwd=PROJECT_ROOT, check=True)
    recorder = EvidenceRecorder('Omar Khalil')
    tokens = {}
    users = {}
    for role, password in [('admin', 'Admin@1234'), ('analyst', 'Analyst@1234'), ('employee', 'Employee@1234'), ('auditor', 'Auditor@1234'), ('employee2', 'Employee@1234')]:
        response = requests.post('http://127.0.0.1:5001/users/login', json={'username': role, 'password': password}, timeout=10)
        response.raise_for_status()
        tokens[role] = response.json()['data']['token']
        users[role] = response.json()['data']['user']['id']

    def api(title, purpose, method, port, path, body=None, expected=200, role='admin', params=None, explanation=None):
        explanation = explanation or f'This request {purpose.lower()}. The live response demonstrates HTTP {expected} and the shared status/message/data or error envelope.'
        response = recorder.api(f'Omar Khalil – {title} – {purpose}', method, f'http://127.0.0.1:{port}{path}', token=tokens.get(role), json=body, params=params, explanation=explanation)
        if response.status_code != expected:
            raise AssertionError(f'{title}: expected {expected}, got {response.status_code}: {response.text}')
        return response.json().get('data')

    def table(name, purpose, explanation, sql=None, params=()):
        return recorder.db(f'Omar Khalil – {name} table – {purpose}', sql or f'SELECT * FROM {name}', params=params, explanation=explanation)

    assets = []
    for index, (kind, severity) in enumerate(zip(['Workstation', 'Application', 'Server', 'Database'], ['Low', 'Medium', 'High', 'Critical']), 20):
        body = dict(name=f'Evidence {kind}', asset_type=kind, ip_address=f'10.20.0.{index}', department='Engineering', owner_id=users['employee'], criticality=severity)
        assets.append(api('POST /assets', f'Creates a {severity} criticality {kind}', 'POST', 5002, '/assets', body, 201))
    table('assets', 'Shows stored criticality values', 'Criticality is stored as one of Low, Medium, High or Critical in the shared SQLAlchemy enum column. SQLite enforces the enum using a CHECK constraint, while the API validates the value before insertion.')
    body = dict(name='Evidence disposable', asset_type='Server', ip_address='10.20.1.1', department='Engineering', owner_id=users['employee'], criticality='High')
    for field, value, purpose in [('ip_address', '999.1.1.1', 'Rejects an invalid IPv4 address'), ('criticality', 'Extreme', 'Rejects invalid criticality')]:
        api('POST /assets', purpose, 'POST', 5002, '/assets', {**body, field: value}, 422)
    api('POST /assets', 'Rejects a missing name', 'POST', 5002, '/assets', {k: v for k, v in body.items() if k != 'name'}, 422)
    path = f'/assets/{assets[0]["id"]}'
    api('GET /assets/{id}', 'Shows the asset before update', 'GET', 5002, path)
    api('PUT /assets/{id}', 'Updates name and criticality', 'PUT', 5002, path, {'name': 'Evidence Updated Workstation', 'criticality': 'High'})
    table('assets', 'Shows the committed update', 'The update changes only permitted fields and commits before returning success. This parameterized query confirms the new name and criticality persisted in SQLite.', 'SELECT * FROM assets WHERE id = ?', (assets[0]['id'],))
    disposable = api('POST /assets', 'Creates a deletable asset', 'POST', 5002, '/assets', body, 201)
    api('DELETE /assets/{id}', 'Denies analyst deletion', 'DELETE', 5002, f'/assets/{disposable["id"]}', expected=403, role='analyst', explanation='The shared require_roles decorator verifies the JWT and checks the Security Administrator role before calling business logic. An analyst receives 403, so the deletion never executes; unauthorized access is submitted to the audit service.')
    api('DELETE /assets/{id}', 'Deletes an unreferenced asset', 'DELETE', 5002, f'/assets/{disposable["id"]}')
    api('GET /assets', 'Lists assets in the shared JSON envelope', 'GET', 5002, '/assets', explanation='The response is a JSON object containing status, message and data. The data.assets array contains serialized asset objects with identifiers, owner IDs, criticality and status, rather than bare database rows.')
    api('GET /assets/{id}', 'Includes HTTP-linked incident and vulnerability records', 'GET', 5002, path, explanation='Asset details include related_incident_ids and related_vulnerabilities obtained through HTTP calls to their owning services. A missing or unavailable vulnerabilities endpoint produces an empty related list while asset retrieval still succeeds.')
    api('GET /assets/{id}', 'Rejects an unknown asset ID', 'GET', 5002, '/assets/999999', expected=404)
    for field, value in [('name', 'Evidence'), ('asset_type', 'Server'), ('ip_address', assets[2]['ip_address']), ('department', 'Engineering'), ('criticality', 'Critical')]:
        api('GET /assets/search', f'Filters by {field}', 'GET', 5002, '/assets/search', params={field: value}, role='analyst', explanation=f'The {field} filter is applied to the asset query; name uses a literal partial match and other filters use equality. When multiple filters are supplied they combine with AND, and results remain in the data.assets array.')
    api('GET /assets', 'Denies employee asset access', 'GET', 5002, '/assets', expected=403, role='employee')

    reasons = {
        'Low': 'A suspicious message was blocked on an isolated workstation without execution or data exposure.',
        'Medium': 'A delivered phishing message exposes one mailbox and needs investigation, with no confirmed compromise.',
        'High': 'Malware execution on a production server threatens service availability and requires urgent containment.',
        'Critical': 'Confirmed customer data leakage threatens organization-wide confidentiality and requires immediate response.',
    }
    incidents = []
    for asset, severity in zip(assets, reasons):
        body = dict(title=f'Evidence {severity} incident', description=reasons[severity], category='Data Leakage' if severity == 'Critical' else 'Malware' if severity == 'High' else 'Phishing', severity=severity, asset_id=asset['id'])
        incidents.append(api('POST /incidents', f'Creates a {severity} severity incident', 'POST', 5003, '/incidents', body, 201, role='employee', explanation=f'{reasons[severity]} This impact and scope justify the {severity} severity; the reporter ID is taken from the authenticated employee token and status starts Open.'))
    table('incidents', 'Shows incidents across four severities', 'Severity records impact and urgency separately from lifecycle status. Low and Medium examples have limited or unconfirmed impact, while High threatens production availability and Critical represents confirmed customer data exposure.')
    api('POST /incidents', 'Rejects invalid severity', 'POST', 5003, '/incidents', {**body, 'severity': 'Extreme'}, 422)
    api('POST /incidents', 'Rejects missing required fields', 'POST', 5003, '/incidents', {'title': 'Missing fields'}, 422)
    api('GET /incidents', 'Lists status and assigned analyst IDs', 'GET', 5003, '/incidents')
    ipath = f'/incidents/{incidents[2]["id"]}'
    api('GET /incidents/{id}', 'Retrieves incident details and notes', 'GET', 5003, ipath)
    api('GET /incidents/{id}', 'Rejects an unknown incident ID', 'GET', 5003, '/incidents/999999', expected=404)
    api('PUT /incidents/{id}/assign', 'Denies assignment by an analyst', 'PUT', 5003, ipath + '/assign', {'analyst_id': users['analyst']}, 403, role='analyst')
    api('PUT /incidents/{id}/assign', 'Rejects assignment to a non-analyst', 'PUT', 5003, ipath + '/assign', {'analyst_id': users['employee']}, 422)
    api('PUT /incidents/{id}/assign', 'Assigns a verified Security Analyst', 'PUT', 5003, ipath + '/assign', {'analyst_id': users['analyst']}, explanation='The users service confirms that the target has the Security Analyst role before assignment is committed. The operation logs INCIDENT_ASSIGNED and sends an Incident Assignment notification to that analyst.')
    table('incidents', 'Shows the assigned analyst', 'The assigned_analyst_id foreign key now references the verified analyst. This assignment also controls which analyst can retrieve the incident, add notes and advance its status.', 'SELECT * FROM incidents WHERE id = ?', (incidents[2]['id'],))
    api('PUT /incidents/{id}/status', 'Rejects Open to Closed', 'PUT', 5003, ipath + '/status', {'status': 'Closed'}, 422, explanation='The lifecycle permits only the next status, so an Open incident cannot skip directly to Closed. The error names Under Investigation as the allowed next status and leaves the record Open.')
    for status in ['Under Investigation', 'Mitigated', 'Resolved', 'Closed']:
        api('PUT /incidents/{id}/status', f'Advances to {status}', 'PUT', 5003, ipath + '/status', {'status': status}, role='analyst', explanation=f'The assigned analyst advances the incident to {status} through the next permitted lifecycle step. Each transition is logged and notifies the reporter; resolved_at is set on Resolved and preserved on Closed.')
    api('POST /incidents/{id}/notes', 'Adds an authenticated investigation note', 'POST', 5003, ipath + '/notes', {'content': 'Isolated server, collected malware sample, restored from verified backup.'}, 201, role='analyst')
    api('GET /incidents/{id}', 'Includes the stored investigation note', 'GET', 5003, ipath)
    table('investigation_notes', 'Shows note author and incident link', 'Investigation notes reference both their incident and authenticated analyst. The content and creation timestamp form the investigation record returned with incident details.')
    api('GET /incidents/{id}', 'Denies another employee access', 'GET', 5003, ipath, expected=403, role='employee2', explanation='Regular employees can retrieve only incidents whose reporter_id matches the user ID in their token. The second employee did not report this incident, so the object-level permission check returns 403.')

    playbooks = []
    for name, category in [('Evidence Phishing Response', 'Phishing'), ('Evidence Malware Response', 'Malware')]:
        playbooks.append(api('POST /playbooks', f'Creates {name}', 'POST', 5009, '/playbooks', dict(name=name, description='Contain, investigate and recover', incident_category=category, severity='High'), 201))
    table('playbooks', 'Shows category, severity and creator', 'Each playbook records an incident category, severity and authenticated creator. Its actions are stored separately and reference the playbook through a foreign key.')
    api('GET /playbooks', 'Lists response playbooks', 'GET', 5009, '/playbooks', role='auditor')
    ppath = f'/playbooks/{playbooks[0]["id"]}'
    api('GET /playbooks/{id}', 'Retrieves playbook details', 'GET', 5009, ppath)
    api('GET /playbooks/{id}', 'Rejects an unknown playbook ID', 'GET', 5009, '/playbooks/999999', expected=404)
    actions = {}
    for step in [2, 1, 3]:
        actions[step] = api('POST /playbooks/{id}/actions', f'Adds step {step}', 'POST', 5009, ppath + '/actions', dict(description={1: 'Contain affected mailbox', 2: 'Investigate message headers', 3: 'Restore and document findings'}[step], step_number=step, assigned_user_id=users['analyst']), 201, role='analyst')
    table('response_actions', 'Shows numeric execution order', 'step_number determines execution order independently of insertion order or action ID. A unique constraint prevents duplicate step numbers within one playbook, and an action can start only after all lower-numbered steps are Completed.', 'SELECT * FROM response_actions WHERE playbook_id = ? ORDER BY step_number', (playbooks[0]['id'],))
    api('GET /playbooks/{id}', 'Returns actions ordered by step number', 'GET', 5009, ppath)
    api('POST /playbooks/{id}/actions', 'Rejects a duplicate step number', 'POST', 5009, ppath + '/actions', dict(description='Duplicate step', step_number=1), 409)
    api('PUT /actions/{id}/status', 'Rejects starting step two before step one', 'PUT', 5009, f'/actions/{actions[2]["id"]}/status', {'status': 'In Progress'}, 422)
    for step in [1, 2, 3]:
        for status in ['In Progress', 'Completed']:
            api('PUT /actions/{id}/status', f'Advances step {step} to {status}', 'PUT', 5009, f'/actions/{actions[step]["id"]}/status', {'status': status}, role='analyst', explanation=f'Step {step} progresses from Pending through In Progress to Completed, with all lower steps completed before it starts. Every transition is submitted to audit logs, and Completed automatically records completed_at.')
    api('DELETE /playbooks/{id}', 'Denies deletion by an analyst', 'DELETE', 5009, ppath, expected=403, role='analyst')
    api('GET /playbooks', 'Denies employee playbook access', 'GET', 5009, '/playbooks', expected=403, role='employee')
    api('DELETE /playbooks/{id}', 'Deletes playbook and cascades its actions', 'DELETE', 5009, ppath, explanation='Deleting a playbook invokes the response_actions foreign key ON DELETE CASCADE. The service logs the deleted playbook and each removed action, preserving execution history in the audit service.')
    table('response_actions', 'Confirms deleted playbook actions are absent', 'The query returns no actions for the deleted playbook. This confirms the foreign key cascade removed the dependent actions rather than leaving orphan records.', 'SELECT * FROM response_actions WHERE playbook_id = ?', (playbooks[0]['id'],))

    table('logs', 'Shows real mutation and lifecycle audit events', 'All three services submit create, update, delete and status changes to the logs API. These immutable entries retain action execution history even after a playbook and its actions are deleted.', "SELECT id, user_id, action, description, related_service FROM logs WHERE related_service IN ('assets','incidents','playbooks') ORDER BY id")
    table('notifications', 'Shows assignment and reporter notifications', 'Incident assignment creates an Incident Assignment notification for the selected analyst. Every status transition creates a System Notification for the original reporter through the notifications service.')
    database_path = make_url(DATABASE_URL).database
    with sqlite3.connect(database_path) as connection:
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for name in tables:
            for kind, pragma in [('Structure', 'table_info'), ('Foreign keys', 'foreign_key_list')]:
                cursor = connection.execute(f'PRAGMA {pragma}("{name}")')
                rows = [dict(zip([item[0] for item in cursor.description], row)) for row in cursor.fetchall()]
                recorder.text(f'Omar Khalil – {name} {kind} – Shows database design', f'PRAGMA {pragma}("{name}")\n' + json.dumps(rows, indent=2), explanation=f'This is the actual SQLite {kind.lower()} metadata for the {name} table. Column types, nullability and primary keys describe its structure; foreign keys describe dependencies and deletion behavior, with an empty list indicating no outgoing foreign keys.')
    output = subprocess.run(['git', 'log', '--author=Omar Khalil', '--oneline'], cwd=PROJECT_ROOT, capture_output=True, text=True, check=True).stdout
    recorder.text('Omar Khalil – GitHub history – Shows authored implementation commits', 'git log --author="Omar Khalil" --oneline\n' + output, explanation='This output comes directly from the local Git history filtered by author Omar Khalil. It shows separate endpoint commits and validation work; publishing those commits to GitHub depends on repository write access.')
    print(f'Evidence saved to {recorder.output_dir}')


if __name__ == '__main__':
    main()
