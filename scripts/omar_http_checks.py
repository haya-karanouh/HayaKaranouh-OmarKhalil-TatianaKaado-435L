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
