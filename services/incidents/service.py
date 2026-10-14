"""Incident business rules. Author: Omar Khalil."""
from datetime import datetime
import requests
from werkzeug.exceptions import ServiceUnavailable
from common.constants import ADMIN, ANALYST, EMPLOYEE, SERVICE, INCIDENT_SEVERITIES, INCIDENT_STATUSES, DATA_CREATED, STATUS_CHANGED, INCIDENT_ASSIGNED
from common.db import db
from common.errors import ValidationError, NotFoundError, PermissionDenied
from common.models import Incident, InvestigationNote
from common.service_client import call_service, log_event, notify
from common.validators import require_fields

INCIDENT_CATEGORIES = ['Malware', 'Unauthorized Access', 'Phishing', 'Data Leakage', 'Account Compromise', 'Denial of Service', 'Other']


class IncidentsService:
    @staticmethod
    def positive_id(value, field):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValidationError(f'{field} must be a positive integer')
        return value

    @staticmethod
    def find(incident_id):
        incident = db.session.get(Incident, incident_id)
        if incident is None:
            raise NotFoundError('Incident not found')
        return incident

    @staticmethod
    def remote(method, service, path, **kwargs):
        try:
            response = call_service(method, service, path, **kwargs)
        except requests.RequestException as error:
            raise ServiceUnavailable(f'{service.title()} service is unavailable') from error
        if response.status_code == 404:
            raise NotFoundError(f'{service.title()} record not found')
        if response.status_code != 200:
            raise ServiceUnavailable(f'{service.title()} service could not verify record')
        try:
            return response.json()['data']
        except (ValueError, KeyError) as error:
            raise ServiceUnavailable(f'{service.title()} service returned an invalid response') from error

    @staticmethod
    def serialize(row):
        return {column.name: (value.isoformat() if isinstance(value, datetime) else value)
                for column in row.__table__.columns if (value := getattr(row, column.name)) is not None} | {
                    column.name: None for column in row.__table__.columns if getattr(row, column.name) is None}

    def create(self, data, actor):
        required = {'title', 'description', 'category', 'severity', 'asset_id'}
        require_fields(data, required, required)
        for field in ['title', 'description']:
            if not isinstance(data[field], str) or not data[field].strip():
                raise ValidationError(f'{field} must be a non-empty string')
        if len(data['title']) > 200:
            raise ValidationError('title must be at most 200 characters')
        for field, values in [('category', INCIDENT_CATEGORIES), ('severity', INCIDENT_SEVERITIES)]:
            if data[field] not in values:
                raise ValidationError(f'{field} must be one of: {", ".join(values)}')
        self.positive_id(data['asset_id'], 'asset_id')
        self.remote('GET', 'assets', f'/assets/{data["asset_id"]}')
        incident = Incident(**data, reporter_id=actor['user_id'], status='Open')
        db.session.add(incident)
        db.session.commit()
        log_event(actor['user_id'], DATA_CREATED, f'Created incident {incident.id}', 'Information', 'incidents')
        return self.serialize(incident)

    def list(self, filters):
        if set(filters) - {'asset_id'}:
            raise ValidationError('Unsupported incident filter')
        query = db.session.query(Incident)
        if 'asset_id' in filters:
            try:
                asset_id = int(filters['asset_id'])
            except (TypeError, ValueError) as error:
                raise ValidationError('asset_id must be a positive integer') from error
            self.positive_id(asset_id, 'asset_id')
            query = query.filter_by(asset_id=asset_id)
        return [self.serialize(row) for row in query.order_by(Incident.id).all()]

    def get(self, incident_id, actor):
        incident = self.find(incident_id)
        if actor['role'] == ANALYST and incident.assigned_analyst_id != actor['user_id']:
            raise PermissionDenied('Only the assigned analyst may view this incident')
        if actor['role'] == EMPLOYEE and incident.reporter_id != actor['user_id']:
            raise PermissionDenied('Employees may only view incidents they reported')
        data = self.serialize(incident)
        data['investigation_notes'] = [self.serialize(note) for note in db.session.query(InvestigationNote).filter_by(incident_id=incident_id).order_by(InvestigationNote.created_at, InvestigationNote.id).all()]
        return data

    def assign(self, incident_id, data, actor):
        incident = self.find(incident_id)
        require_fields(data, {'analyst_id'}, {'analyst_id'})
        analyst_id = self.positive_id(data['analyst_id'], 'analyst_id')
        users = self.remote('GET', 'users', '/users')['users']
        analyst = next((user for user in users if user['id'] == analyst_id), None)
        if analyst is None:
            raise NotFoundError('Analyst user not found')
        if analyst['role'] != ANALYST:
            raise ValidationError('Assigned user must have the Security Analyst role')
        incident.assigned_analyst_id = analyst_id
        db.session.commit()
        log_event(actor['user_id'], INCIDENT_ASSIGNED, f'Assigned incident {incident_id} to analyst {analyst_id}', 'Information', 'incidents')
        notify(analyst_id, f'Incident {incident_id} assigned', incident.title, 'Incident Assignment', incident.severity)
        return self.serialize(incident)

    @staticmethod
    def authorize_change(incident, actor):
        if actor['role'] not in {ADMIN, SERVICE} and not (actor['role'] == ANALYST and actor['user_id'] == incident.assigned_analyst_id):
            raise PermissionDenied('Only an administrator or the assigned analyst may change this incident')

    def status(self, incident_id, data, actor):
        incident = self.find(incident_id)
        self.authorize_change(incident, actor)
        require_fields(data, {'status'}, {'status'})
        index = INCIDENT_STATUSES.index(incident.status)
        allowed = INCIDENT_STATUSES[index + 1] if index + 1 < len(INCIDENT_STATUSES) else None
        if data['status'] != allowed or allowed is None:
            raise ValidationError(f'Allowed next status: {allowed or "none (Closed is terminal)"}')
        old_status = incident.status
        incident.status = allowed
        if allowed == 'Resolved':
            incident.resolved_at = datetime.utcnow()
        db.session.commit()
        log_event(actor['user_id'], STATUS_CHANGED, f'Incident {incident_id}: {old_status} -> {allowed}', 'Information', 'incidents')
        notify(incident.reporter_id, f'Incident {incident_id} status changed', f'{incident.title}: {allowed}', 'System Notification', incident.severity)
        return self.serialize(incident)

    def add_note(self, incident_id, data, actor):
        incident = self.find(incident_id)
        self.authorize_change(incident, actor)
        require_fields(data, {'content'}, {'content'})
        if not isinstance(data['content'], str) or not data['content'].strip():
            raise ValidationError('content must be a non-empty string')
        note = InvestigationNote(incident_id=incident_id, analyst_id=actor['user_id'], content=data['content'])
        db.session.add(note)
        db.session.commit()
        log_event(actor['user_id'], DATA_CREATED, f'Created investigation note {note.id} for incident {incident_id}', 'Information', 'incidents')
        return self.serialize(note)

    def health(self):
        return {'service': 'incidents', 'status': 'healthy'}
