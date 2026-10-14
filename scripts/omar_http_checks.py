"""Real HTTP regression checks. Author: Omar Khalil.

Run with --service assets, incidents, or playbooks after run_all.py.
"""
import argparse
import requests


class Checks:
    def __init__(self):
        self.tokens = {}
        self.count = 0
        for role, password in [('admin', 'Admin@1234'), ('analyst', 'Analyst@1234'), ('employee', 'Employee@1234'), ('auditor', 'Auditor@1234'), ('employee2', 'Employee@1234')]:
            response = requests.post('http://127.0.0.1:5001/users/login', json={'username': role, 'password': password}, timeout=10)
            response.raise_for_status()
            self.tokens[role] = response.json()['data']['token']

    def request(self, method, port, path, expected=200, role='admin', body=None, params=None):
        headers = {'Authorization': 'Bearer ' + self.tokens[role]} if role else {}
        response = requests.request(method, f'http://127.0.0.1:{port}{path}', headers=headers, json=body, params=params, timeout=20)
        assert response.status_code == expected, (method, path, expected, response.status_code, response.text)
        self.count += 1
        return response.json().get('data')

    def incidents(self):
        asset = self.request('POST', 5002, '/assets', 201, body=dict(name='Incident test asset', asset_type='Server', ip_address='10.4.5.6', owner_id=3, department='Engineering', criticality='High'))
        body = dict(title='HTTP phishing report', description='Suspicious attachment', category='Phishing', severity='High', asset_id=asset['id'])
        incident = self.request('POST', 5003, '/incidents', 201, role='employee', body=body)
        path = f'/incidents/{incident["id"]}'
        assert incident['reporter_id'] == 3 and incident['status'] == 'Open'
        for data in [{**body, 'severity': 'Extreme'}, {**body, 'category': 'Unknown'}, {**body, 'asset_id': True}, {'title': 'Missing'}]:
            self.request('POST', 5003, '/incidents', 422, body=data)
        self.request('POST', 5003, '/incidents', 404, body={**body, 'asset_id': 999999})
        self.request('POST', 5003, '/incidents', 403, role='analyst', body=body)
        self.request('GET', 5003, '/incidents', role='auditor')
        rows = self.request('GET', 5003, '/incidents', params={'asset_id': asset['id']})['incidents']
        assert [row['id'] for row in rows] == [incident['id']]
        self.request('GET', 5003, '/incidents', 422, params={'asset_id': 'bad'})
        self.request('GET', 5003, path, role='employee')
        self.request('GET', 5003, path, 403, role='employee2')
        self.request('GET', 5003, path, 403, role='analyst')
        self.request('PUT', 5003, path + '/assign', 403, role='analyst', body={'analyst_id': 2})
        self.request('PUT', 5003, path + '/assign', 422, body={'analyst_id': 3})
        self.request('PUT', 5003, path + '/assign', 404, body={'analyst_id': 999999})
        assigned = self.request('PUT', 5003, path + '/assign', body={'analyst_id': 2})
        assert assigned['assigned_analyst_id'] == 2
        self.request('GET', 5003, path, role='analyst')
        self.request('PUT', 5003, path + '/status', 422, body={'status': 'Closed'})
        for status in ['Under Investigation', 'Mitigated', 'Resolved', 'Closed']:
            row = self.request('PUT', 5003, path + '/status', role='analyst', body={'status': status})
            assert row['status'] == status
            if status in ['Resolved', 'Closed']:
                assert row['resolved_at']
        self.request('PUT', 5003, path + '/status', 422, body={'status': 'Resolved'})
        note = self.request('POST', 5003, path + '/notes', 201, role='analyst', body={'content': 'Quarantined attachment and reviewed headers.'})
        assert note['analyst_id'] == 2
        assert self.request('GET', 5003, path)['investigation_notes'][0]['id'] == note['id']
        for method, suffix, data in [('GET', '', None), ('PUT', '/assign', {'analyst_id': 2}), ('PUT', '/status', {'status': 'Closed'}), ('POST', '/notes', {'content': 'Note'})]:
            self.request(method, 5003, '/incidents/999999' + suffix, 404, body=data)
            self.request(method, 5003, path + suffix, 401, role=None, body=data)
        notifications = self.request('GET', 5008, '/notifications/user/2')['notifications']
        assert any(row['notification_type'] == 'Incident Assignment' for row in notifications)
        self.request('DELETE', 5002, f'/assets/{asset["id"]}', 409)
        linked = self.request('GET', 5002, f'/assets/{asset["id"]}')
        assert incident['id'] in linked['related_incident_ids']

    def assets(self):
        body = dict(name='HTTP test server', asset_type='Server', ip_address='10.1.2.3', owner_id=3, department='Engineering', criticality='High')
        asset = self.request('POST', 5002, '/assets', 201, body=body)
        asset_id = asset['id']
        assert asset['status'] == 'Active' and asset['location'] == 'Unspecified'
        for field, value in [('ip_address', '999.1.2.3'), ('criticality', 'Extreme'), ('asset_type', 'Unknown'), ('owner_id', True), ('name', 123)]:
            self.request('POST', 5002, '/assets', 422, body={**body, field: value})
        self.request('POST', 5002, '/assets', 422, body={k: v for k, v in body.items() if k != 'name'})
        self.request('POST', 5002, '/assets', 404, body={**body, 'owner_id': 999999})
        for method, path, data in [('POST', '/assets', body), ('PUT', f'/assets/{asset_id}', {'name': 'Forbidden'}), ('DELETE', f'/assets/{asset_id}', None), ('GET', '/assets', None), ('GET', f'/assets/{asset_id}', None), ('GET', '/assets/search', None)]:
            self.request(method, 5002, path, 401, role=None, body=data)
            self.request(method, 5002, path, 403, role='employee', body=data)
        self.request('DELETE', 5002, f'/assets/{asset_id}', 403, role='analyst')
        self.request('GET', 5002, '/assets', role='auditor')
        specific = self.request('GET', 5002, f'/assets/{asset_id}', role='analyst')
        assert 'related_vulnerabilities' in specific and 'related_incident_ids' in specific
        for field in ['name', 'asset_type', 'ip_address', 'department', 'criticality']:
            value = 'test server' if field == 'name' else body[field]
            rows = self.request('GET', 5002, '/assets/search', role='analyst', params={field: value})['assets']
            assert asset_id in [row['id'] for row in rows]
        assert self.request('GET', 5002, '/assets/search', params={'name': 'HTTP', 'department': 'No Match'})['assets'] == []
        updated = self.request('PUT', 5002, f'/assets/{asset_id}', body={'name': 'Updated server', 'status': 'Under Maintenance', 'criticality': 'Critical'})
        assert updated['name'] == 'Updated server' and updated['criticality'] == 'Critical'
        self.request('GET', 5002, '/assets/999999', 404)
        self.request('PUT', 5002, '/assets/999999', 404, body={'name': 'Missing'})
        self.request('DELETE', 5002, '/assets/999999', 404)
        self.request('DELETE', 5002, f'/assets/{asset_id}')
        self.request('GET', 5002, f'/assets/{asset_id}', 404)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--service', choices=['assets', 'incidents', 'playbooks'], required=True)
    args = parser.parse_args()
    checks = Checks()
    getattr(checks, args.service)()
    print(f'{args.service}: {checks.count} real HTTP checks passed')


if __name__ == '__main__':
    main()
