"""Playbook business rules. Author: Omar Khalil."""
from datetime import datetime
import requests
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import ServiceUnavailable
from common.constants import INCIDENT_SEVERITIES, RESPONSE_ACTION_STATUSES, DATA_CREATED, DATA_DELETED, DATA_UPDATED, STATUS_CHANGED
from common.db import db
from common.errors import ValidationError, NotFoundError, ConflictError
from common.models import Playbook, ResponseAction
from common.service_client import call_service, log_event
from common.validators import require_fields
from services.incidents.service import INCIDENT_CATEGORIES


class PlaybooksService:
    @staticmethod
    def serialize(row):
        result = {}
        for column in row.__table__.columns:
            value = getattr(row, column.name)
            result[column.name] = value.isoformat() if isinstance(value, datetime) else value
        return result

    @staticmethod
    def find(playbook_id):
        playbook = db.session.get(Playbook, playbook_id)
        if playbook is None:
            raise NotFoundError('Playbook not found')
        return playbook

    @staticmethod
    def verify_user(user_id):
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            raise ValidationError('assigned_user_id must be a positive integer')
        try:
            response = call_service('GET', 'users', '/users')
            if response.status_code != 200:
                raise ServiceUnavailable('Users service could not verify assignee')
            users = response.json()['data']['users']
        except (requests.RequestException, ValueError, KeyError) as error:
            raise ServiceUnavailable('Users service is unavailable') from error
        if not any(user['id'] == user_id for user in users):
            raise NotFoundError('Assigned user not found')

    def create(self, data, actor):
        required = {'name', 'description', 'incident_category', 'severity'}
        require_fields(data, required, required)
        for field in ['name', 'description']:
            if not isinstance(data[field], str) or not data[field].strip():
                raise ValidationError(f'{field} must be a non-empty string')
        if len(data['name']) > 160:
            raise ValidationError('name must be at most 160 characters')
        for field, choices in [('incident_category', INCIDENT_CATEGORIES), ('severity', INCIDENT_SEVERITIES)]:
            if data[field] not in choices:
                raise ValidationError(f'{field} must be one of: {", ".join(choices)}')
        playbook = Playbook(**data, created_by=actor['user_id'])
        db.session.add(playbook)
        db.session.commit()
        log_event(actor['user_id'], DATA_CREATED, f'Created playbook {playbook.id}', 'Information', 'playbooks')
        return self.serialize(playbook)

    def list(self):
        return [self.serialize(row) for row in db.session.query(Playbook).order_by(Playbook.id).all()]

    def get(self, playbook_id):
        result = self.serialize(self.find(playbook_id))
        result['actions'] = [self.serialize(row) for row in db.session.query(ResponseAction).filter_by(playbook_id=playbook_id).order_by(ResponseAction.step_number).all()]
        return result

    def add_action(self, playbook_id, data, actor):
        self.find(playbook_id)
        require_fields(data, {'description', 'step_number'}, {'description', 'step_number', 'assigned_user_id'})
        if not isinstance(data['description'], str) or not data['description'].strip():
            raise ValidationError('description must be a non-empty string')
        step = data['step_number']
        if isinstance(step, bool) or not isinstance(step, int) or step < 1:
            raise ValidationError('step_number must be a positive integer')
        if 'assigned_user_id' in data:
            self.verify_user(data['assigned_user_id'])
        action = ResponseAction(**data, playbook_id=playbook_id, status='Pending')
        db.session.add(action)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise ConflictError('step_number must be unique within the playbook') from error
        log_event(actor['user_id'], DATA_CREATED, f'Added action {action.id}, step {step}, to playbook {playbook_id}', 'Information', 'playbooks')
        return self.serialize(action)

    def status(self, action_id, data, actor):
        action = db.session.get(ResponseAction, action_id)
        if action is None:
            raise NotFoundError('Response action not found')
        require_fields(data, {'status'}, {'status', 'assigned_user_id'})
        index = RESPONSE_ACTION_STATUSES.index(action.status)
        allowed = RESPONSE_ACTION_STATUSES[index + 1] if index + 1 < len(RESPONSE_ACTION_STATUSES) else None
        if allowed is None or data['status'] != allowed:
            raise ValidationError(f'Allowed next status: {allowed or "none (Completed is terminal)"}')
        if allowed == 'In Progress' and db.session.query(ResponseAction.id).filter(ResponseAction.playbook_id == action.playbook_id, ResponseAction.step_number < action.step_number, ResponseAction.status != 'Completed').first():
            raise ValidationError('All lower steps must be Completed before this step starts')
        if 'assigned_user_id' in data:
            self.verify_user(data['assigned_user_id'])
        old_status, old_assignee = action.status, action.assigned_user_id
        action.status = allowed
        if 'assigned_user_id' in data:
            action.assigned_user_id = data['assigned_user_id']
        if allowed == 'Completed':
            action.completed_at = datetime.utcnow()
        db.session.commit()
        log_event(actor['user_id'], STATUS_CHANGED, f'Action {action_id} in playbook {action.playbook_id}: {old_status} -> {allowed}', 'Information', 'playbooks')
        if old_assignee != action.assigned_user_id:
            log_event(actor['user_id'], DATA_UPDATED, f'Action {action_id} assignee: {old_assignee} -> {action.assigned_user_id}', 'Information', 'playbooks')
        return self.serialize(action)

    def delete(self, playbook_id, actor):
        playbook = self.find(playbook_id)
        action_ids = [row.id for row in db.session.query(ResponseAction).filter_by(playbook_id=playbook_id).all()]
        db.session.delete(playbook)
        db.session.commit()
        for action_id in action_ids:
            log_event(actor['user_id'], DATA_DELETED, f'Cascade deleted action {action_id} from playbook {playbook_id}', 'Information', 'playbooks')
        log_event(actor['user_id'], DATA_DELETED, f'Deleted playbook {playbook_id}', 'Warning', 'playbooks')
        return {'id': playbook_id, 'deleted_action_ids': action_ids}

    def health(self):
        return {'service': 'playbooks', 'status': 'healthy'}
