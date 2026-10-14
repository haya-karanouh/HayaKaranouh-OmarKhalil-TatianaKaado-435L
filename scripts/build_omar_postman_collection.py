"""Build Omar's repeatable Postman scenarios. Author: Omar Khalil."""
import json
from pathlib import Path

PREFIX = 'Omar Khalil – '


def request(name, method, port, path, body=None, role='admin', expected=200, description='', save=None):
    headers = [{'key': 'Content-Type', 'value': 'application/json'}]
    if role:
        headers.append({'key': 'Authorization', 'value': 'Bearer {{' + role + '_token}}'})
    item = {'name': name, 'request': {'method': method, 'header': headers, 'url': f'http://{{{{host}}}}:{port}{path}', 'description': PREFIX + description}}
    if body is not None:
        item['request']['body'] = {'mode': 'raw', 'raw': json.dumps(body, indent=2), 'options': {'raw': {'language': 'json'}}}
    script = [f'pm.test("Expected HTTP {expected}", () => pm.response.to.have.status({expected}));', 'pm.test("JSON envelope", () => pm.expect(pm.response.json()).to.have.property("status"));']
    if save:
        script.append(f'if (pm.response.code === {expected}) pm.collectionVariables.set("{save}", pm.response.json().data.id);')
    item['event'] = [{'listen': 'test', 'script': {'type': 'text/javascript', 'exec': script}}]
    return item


def main():
    asset = dict(name='Postman Production Server', asset_type='Server', ip_address='10.50.0.1', department='Engineering', owner_id=3, criticality='High')
    incident = dict(title='Postman phishing report', description='Suspicious attachment delivered to a mailbox', category='Phishing', severity='Medium', asset_id='{{asset_id}}')
    playbook = dict(name='Postman Phishing Response', description='Contain, investigate and recover', incident_category='Phishing', severity='High')
    action = dict(description='Contain affected mailbox', step_number=1, assigned_user_id=2)
    folders = []
    login_items = []
    for role, password in [('admin', 'Admin@1234'), ('analyst', 'Analyst@1234'), ('employee', 'Employee@1234'), ('auditor', 'Auditor@1234'), ('employee2', 'Employee@1234')]:
        item = request(f'Login {role}', 'POST', 5001, '/users/login', {'username': role, 'password': password}, role=None, description=f'Logs in the seeded {role} through the real API and saves its JWT.')
        item['event'][0]['script']['exec'].append(f'pm.collectionVariables.set("{role}_token", pm.response.json().data.token);')
        login_items.append(item)
    login_items.append(request('Create disposable asset', 'POST', 5002, '/assets', {**asset, 'name': 'Postman Disposable Asset', 'ip_address': '10.50.0.2'}, expected=201, save='disposable_asset_id', description='Creates a separate unreferenced asset for deletion without disrupting incident tests.'))
    folders.append({'name': 'Authentication and setup', 'item': login_items})

    def endpoint(title, method, port, path, body, success, bad, missing_path, save=None, role='admin', wrong='employee', bad_expected=422, explanation=''):
        invalid_method, invalid_path, invalid_body = bad
        items = [
            request('Success', method, port, path, body, role, success, f'{title}: succeeds with the permitted role. {explanation}', save),
            request('Validation error', invalid_method, port, invalid_path, invalid_body, role, bad_expected, f'{title}: checks invalid input. {explanation}'),
            request('Not found', method, port, missing_path, body, role, 404, f'{title}: checks an unknown resource or unmatched route. Collection and creation endpoints have no missing-record case, so their unmatched-route example demonstrates the JSON 404 envelope.'),
            request('Wrong role', method, port, path, body, wrong, 403, f'{title}: rejects a role without permission before executing business logic.'),
            request('Missing token', method, port, path, body, None, 401, f'{title}: rejects a request without the bearer token.'),
        ]
        folders.append({'name': title, 'item': items})

    endpoint('POST /assets', 'POST', 5002, '/assets', asset, 201, ('POST', '/assets', {**asset, 'ip_address': '999.1.1.1'}), '/assets/not-a-route', save='asset_id')
    endpoint('PUT /assets/{id}', 'PUT', 5002, '/assets/{{asset_id}}', {'criticality': 'Critical'}, 200, ('PUT', '/assets/{{asset_id}}', {'criticality': 'Extreme'}), '/assets/999999')
    endpoint('DELETE /assets/{id}', 'DELETE', 5002, '/assets/{{disposable_asset_id}}', None, 200, ('DELETE', '/assets/not-an-integer', None), '/assets/999999', wrong='analyst', bad_expected=404, explanation='This bodyless endpoint has no input-validation body; a malformed path ID returns 404.')
    endpoint('GET /assets', 'GET', 5002, '/assets', None, 200, ('PATCH', '/assets', None), '/assets/not-a-route', role='auditor', bad_expected=405, explanation='This collection has no request-body validation or missing entity; unsupported PATCH returns 405.')
    endpoint('GET /assets/{id}', 'GET', 5002, '/assets/{{asset_id}}', None, 200, ('GET', '/assets/not-an-integer', None), '/assets/999999', role='analyst', bad_expected=404, explanation='A malformed path identifier cannot match the integer route and returns 404.')
    endpoint('GET /assets/search', 'GET', 5002, '/assets/search?name=Postman&department=Engineering', None, 200, ('GET', '/assets/search?criticality=Extreme', None), '/assets/search/not-a-route', role='analyst')
    folders.append({'name': 'Asset search filters', 'item': [request(f'Search by {field}', 'GET', 5002, f'/assets/search?{field}={value}', role='analyst', description=f'Filters assets by {field}; name is partial and combined filters use AND.') for field, value in [('name', 'Postman'), ('asset_type', 'Server'), ('ip_address', '10.50.0.1'), ('department', 'Engineering'), ('criticality', 'Critical')]]})
    endpoint('POST /incidents', 'POST', 5003, '/incidents', incident, 201, ('POST', '/incidents', {**incident, 'severity': 'Extreme'}), '/incidents/not-a-route', save='incident_id', role='employee', wrong='analyst')
    endpoint('GET /incidents', 'GET', 5003, '/incidents?asset_id={{asset_id}}', None, 200, ('GET', '/incidents?asset_id=invalid', None), '/incidents/not-a-route', role='auditor')
    endpoint('GET /incidents/{id}', 'GET', 5003, '/incidents/{{incident_id}}', None, 200, ('GET', '/incidents/not-an-integer', None), '/incidents/999999', role='employee', wrong='employee2', bad_expected=404, explanation='Employees can view their own reports; another employee is rejected. Malformed path IDs return 404.')
    endpoint('PUT /incidents/{id}/assign', 'PUT', 5003, '/incidents/{{incident_id}}/assign', {'analyst_id': 2}, 200, ('PUT', '/incidents/{{incident_id}}/assign', {'analyst_id': 3}), '/incidents/999999/assign', wrong='analyst')
    endpoint('PUT /incidents/{id}/status', 'PUT', 5003, '/incidents/{{incident_id}}/status', {'status': 'Under Investigation'}, 200, ('PUT', '/incidents/{{incident_id}}/status', {'status': 'Closed'}), '/incidents/999999/status', role='analyst')
    endpoint('POST /incidents/{id}/notes', 'POST', 5003, '/incidents/{{incident_id}}/notes', {'content': 'Inspected message headers and quarantined attachment.'}, 201, ('POST', '/incidents/{{incident_id}}/notes', {'content': ''}), '/incidents/999999/notes', role='analyst')
    lifecycle = [request('Create lifecycle incident', 'POST', 5003, '/incidents', {**incident, 'title': 'Full incident lifecycle'}, role='employee', expected=201, save='lifecycle_incident_id', description='Creates a fresh Open incident for a complete independent lifecycle.'), request('Assign lifecycle analyst', 'PUT', 5003, '/incidents/{{lifecycle_incident_id}}/assign', {'analyst_id': 2}, description='Assigns the analyst before analyst-only lifecycle execution.'), request('Reject Open to Closed', 'PUT', 5003, '/incidents/{{lifecycle_incident_id}}/status', {'status': 'Closed'}, role='analyst', expected=422, description='Rejects a skipped transition and names Under Investigation as the allowed next status.')]
    lifecycle += [request(f'Advance to {status}', 'PUT', 5003, '/incidents/{{lifecycle_incident_id}}/status', {'status': status}, role='analyst', description=f'Advances to the next permitted status {status}; Resolved sets resolved_at and each step notifies the reporter.') for status in ['Under Investigation', 'Mitigated', 'Resolved', 'Closed']]
    lifecycle += [request('Add lifecycle note', 'POST', 5003, '/incidents/{{lifecycle_incident_id}}/notes', {'content': 'Containment and recovery verified.'}, role='analyst', expected=201, description='Records a note with the analyst identity from the token.'), request('Inspect lifecycle and notes', 'GET', 5003, '/incidents/{{lifecycle_incident_id}}', description='Shows Closed status, resolution timestamp and investigation notes.')]
    folders.append({'name': 'Full incident lifecycle', 'item': lifecycle})
    endpoint('POST /playbooks', 'POST', 5009, '/playbooks', playbook, 201, ('POST', '/playbooks', {**playbook, 'severity': 'Extreme'}), '/playbooks/not-a-route', save='playbook_id')
    endpoint('GET /playbooks', 'GET', 5009, '/playbooks', None, 200, ('PATCH', '/playbooks', None), '/playbooks/not-a-route', role='auditor', bad_expected=405, explanation='This bodyless collection has no validation or missing-record case; unsupported PATCH returns 405.')
    endpoint('GET /playbooks/{id}', 'GET', 5009, '/playbooks/{{playbook_id}}', None, 200, ('GET', '/playbooks/not-an-integer', None), '/playbooks/999999', role='analyst', bad_expected=404, explanation='Actions are ordered by step_number; malformed path identifiers return 404.')
    endpoint('POST /playbooks/{id}/actions', 'POST', 5009, '/playbooks/{{playbook_id}}/actions', action, 201, ('POST', '/playbooks/{{playbook_id}}/actions', {**action, 'step_number': 0}), '/playbooks/999999/actions', save='action_id', role='analyst')
    folders.append({'name': 'Duplicate action step', 'item': [request('Reject duplicate step one', 'POST', 5009, '/playbooks/{{playbook_id}}/actions', action, role='analyst', expected=409, description='The unique playbook_id/step_number constraint rejects a duplicate action with 409.')]})
    endpoint('PUT /actions/{id}/status', 'PUT', 5009, '/actions/{{action_id}}/status', {'status': 'In Progress'}, 200, ('PUT', '/actions/{{action_id}}/status', {'status': 'Pending'}), '/actions/999999/status', role='analyst')
    workflow = [request('Create workflow playbook', 'POST', 5009, '/playbooks', {**playbook, 'name': 'Full workflow'}, expected=201, save='workflow_playbook_id', description='Creates a separate playbook for the complete action workflow.')]
    for step in [2, 1]:
        workflow.append(request(f'Add step {step}', 'POST', 5009, '/playbooks/{{workflow_playbook_id}}/actions', {**action, 'step_number': step, 'description': f'Workflow step {step}'}, role='analyst', expected=201, save=f'workflow_action_{step}_id', description='Inserts steps out of order to demonstrate numeric ordering.'))
    workflow.append(request('Reject out of order start', 'PUT', 5009, '/actions/{{workflow_action_2_id}}/status', {'status': 'In Progress'}, role='analyst', expected=422, description='Step two cannot start until step one is Completed.'))
    for step in [1, 2]:
        for status in ['In Progress', 'Completed']:
            workflow.append(request(f'Step {step}: {status}', 'PUT', 5009, f'/actions/{{{{workflow_action_{step}_id}}}}/status', {'status': status}, role='analyst', description='Executes Pending → In Progress → Completed in step order; completion records completed_at.'))
    workflow += [request('Inspect ordered actions', 'GET', 5009, '/playbooks/{{workflow_playbook_id}}', role='analyst', description='Shows actions in step_number order with completed timestamps.'), request('Delete workflow playbook', 'DELETE', 5009, '/playbooks/{{workflow_playbook_id}}', description='Deletes the playbook and cascades its dependent response actions.')]
    folders.append({'name': 'Full playbook workflow', 'item': workflow})
    endpoint('DELETE /playbooks/{id}', 'DELETE', 5009, '/playbooks/{{playbook_id}}', None, 200, ('DELETE', '/playbooks/not-an-integer', None), '/playbooks/999999', wrong='analyst', bad_expected=404, explanation='This bodyless endpoint has no validation body; malformed integer IDs return 404.')
    collection = {'info': {'name': 'Omar Khalil – Assets, Incidents and Playbooks', 'description': PREFIX + 'Run folders in order against a seeded development database. Authentication uses the real login API. Each endpoint includes success, invalid-input (or explicitly inapplicable bodyless variant), unknown-resource/route, wrong-role and missing-token cases. Repeat runs create fresh records and IDs are saved automatically.', 'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'}, 'variable': [{'key': 'host', 'value': '127.0.0.1'}], 'item': folders}
    # IDs in request JSON must be numbers after variable replacement, not quoted strings.
    def numeric_ids(items):
        for item in items:
            if 'item' in item:
                numeric_ids(item['item'])
            elif 'body' in item['request']:
                raw = item['request']['body']['raw']
                for variable in ['asset_id']:
                    raw = raw.replace('"{{' + variable + '}}"', '{{' + variable + '}}')
                item['request']['body']['raw'] = raw
    numeric_ids(folders)
    output = Path('postman/OmarKhalil.postman_collection.json')
    output.write_text(json.dumps(collection, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'Wrote {output}')


if __name__ == '__main__':
    main()
