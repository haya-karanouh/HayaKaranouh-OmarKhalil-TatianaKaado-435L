"""Asset business logic. Author: Omar Khalil."""
import requests
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import ServiceUnavailable
from common.constants import ASSET_CRITICALITIES, ASSET_STATUSES, DATA_CREATED, DATA_UPDATED, DATA_DELETED, STATUS_CHANGED
from common.db import db
from common.errors import ValidationError, NotFoundError, ConflictError
from common.models import Asset
from common.service_client import call_service, log_event
from common.validators import require_fields, valid_ipv4

ASSET_TYPES = ['Server', 'Workstation', 'Database', 'Application', 'Network Device', 'Cloud Resource']


class AssetsService:
    @staticmethod
    def verify_owner(value):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValidationError('owner_id must be a positive integer')
        try:
            response = call_service('GET', 'users', '/users')
            if response.status_code != 200:
                raise ServiceUnavailable('Users service could not verify owner')
            users = response.json()['data']['users']
        except (requests.RequestException, ValueError, KeyError) as error:
            raise ServiceUnavailable('Users service is unavailable') from error
        if not any(user['id'] == value for user in users):
            raise NotFoundError('Owner user not found')

    def validate(self, data):
        for field, choices in [('asset_type', ASSET_TYPES), ('criticality', ASSET_CRITICALITIES), ('status', ASSET_STATUSES)]:
            if field in data and data[field] not in choices:
                raise ValidationError(f'{field} must be one of: {", ".join(choices)}')
        if 'ip_address' in data and not valid_ipv4(data['ip_address']):
            raise ValidationError('ip_address must be a valid IPv4 address')
        for field, limit in [('name', 160), ('department', 120), ('operating_system', 120), ('location', 160)]:
            if field in data and (not isinstance(data[field], str) or not data[field].strip() or len(data[field]) > limit):
                raise ValidationError(f'{field} must be a non-empty string of at most {limit} characters')
        if 'owner_id' in data:
            self.verify_owner(data['owner_id'])

    @staticmethod
    def serialize(asset):
        return {column.name: getattr(asset, column.name) for column in Asset.__table__.columns}

    @staticmethod
    def find(asset_id):
        asset = db.session.get(Asset, asset_id)
        if asset is None:
            raise NotFoundError('Asset not found')
        return asset

    def create(self, data, actor):
        required = {'name', 'asset_type', 'ip_address', 'department', 'owner_id', 'criticality'}
        require_fields(data, required, required | {'operating_system', 'location', 'status'})
        self.validate(data)
        asset = Asset(**{'location': 'Unspecified', 'status': 'Active', **data})
        db.session.add(asset)
        db.session.commit()
        log_event(actor['user_id'], DATA_CREATED, f'Created asset {asset.id}', 'Information', 'assets')
        return self.serialize(asset)

    def update(self, asset_id, data, actor):
        asset = self.find(asset_id)
        require_fields(data, set(), {'name', 'owner_id', 'department', 'criticality', 'status'})
        self.validate(data)
        old_status = asset.status
        for field, value in data.items():
            setattr(asset, field, value)
        db.session.commit()
        log_event(actor['user_id'], DATA_UPDATED, f'Updated asset {asset.id}: {sorted(data)}', 'Information', 'assets')
        if old_status != asset.status:
            log_event(actor['user_id'], STATUS_CHANGED, f'Asset {asset.id}: {old_status} -> {asset.status}', 'Information', 'assets')
        return self.serialize(asset)

    def delete(self, asset_id, actor):
        db.session.delete(self.find(asset_id))
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise ConflictError('Asset is referenced by other records') from error
        log_event(actor['user_id'], DATA_DELETED, f'Deleted asset {asset_id}', 'Warning', 'assets')
        return {'id': asset_id}

    def list(self, filters=None):
        filters = dict(filters or {})
        if set(filters) - {'name', 'asset_type', 'ip_address', 'department', 'criticality'}:
            raise ValidationError('Unsupported asset search filter')
        self.validate(filters)
        query = db.session.query(Asset)
        for field, value in filters.items():
            column = getattr(Asset, field)
            query = query.filter(column.contains(value, autoescape=True) if field == 'name' else column == value)
        return [self.serialize(asset) for asset in query.order_by(Asset.id).all()]

    def get(self, asset_id):
        data = self.serialize(self.find(asset_id))
        data.update(related_incident_ids=[], related_vulnerabilities=[])
        for service, path, key in [('incidents', '/incidents', 'incidents'), ('vulnerabilities', '/vulnerabilities/search', 'vulnerabilities')]:
            try:
                response = call_service('GET', service, path, params={'asset_id': asset_id})
                if response.status_code == 200:
                    rows = response.json().get('data', {}).get(key, [])
                    data['related_incident_ids' if service == 'incidents' else 'related_vulnerabilities'] = [row['id'] for row in rows] if service == 'incidents' else rows
            except (requests.RequestException, ValueError, KeyError, TypeError):
                pass
        return data

    def health(self):
        return {'service': 'assets', 'status': 'healthy'}
