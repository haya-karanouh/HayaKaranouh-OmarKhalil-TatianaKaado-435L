"""Replay the generated collection through real HTTP. Author: Omar Khalil."""
import json
import re
from pathlib import Path
import requests


def main():
    collection = json.loads(Path('postman/OmarKhalil.postman_collection.json').read_text(encoding='utf-8'))
    variables = {'host': '127.0.0.1'}
    count = 0

    def replace(value):
        return re.sub(r'\{\{([^}]+)\}\}', lambda match: str(variables[match[1]]), value)

    def run(items):
        nonlocal count
        for item in items:
            if 'item' in item:
                run(item['item'])
                continue
            request = item['request']
            assert request['description'].startswith('Omar Khalil – ')
            body = json.loads(replace(request['body']['raw'])) if 'body' in request else None
            headers = {header['key']: replace(header['value']) for header in request['header']}
            response = requests.request(request['method'], replace(request['url']), headers=headers, json=body, timeout=20)
            script = '\n'.join(item['event'][0]['script']['exec'])
            expected = int(re.search(r'Expected HTTP (\d+)', script)[1])
            assert response.status_code == expected, (item['name'], request['url'], expected, response.status_code, response.text)
            assert response.json()['status'] == ('success' if expected < 400 else 'error')
            for variable in re.findall(r'pm.collectionVariables.set\("([^"]+)"', script):
                variables[variable] = response.json()['data']['token' if variable.endswith('_token') else 'id']
            count += 1
    run(collection['item'])
    print(f'Postman collection: {count} real requests passed; every description has the required author prefix')


if __name__ == '__main__':
    main()
