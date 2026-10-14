"""Business logic for users service."""

import bcrypt
from datetime import datetime
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Unauthorized

from common.auth import create_token
from common.constants import (
    ACCOUNT_STATUSES, EMPLOYEE, LOGIN_FAILED, LOGIN_SUCCESS, ROLE_CHANGED,
    ROLES, USER_CREATED, USER_DELETED, USER_UPDATED,
)
from common.db import db
from common.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from common.models import User
from common.service_client import log_event
from common.validators import require_fields, strong_password, valid_email


class UsersService:
    def register(self, data, actor=None):
        allowed = {"full_name", "username", "email", "password", "department", "role"}
        required = allowed
        require_fields(data, required, allowed)
        if not valid_email(data["email"]):
            raise ValidationError("email must be a valid email address")
        if not strong_password(data["password"]):
            raise ValidationError("password must have 8+ characters, uppercase, lowercase, and a digit")

        role = data["role"] if actor and actor.get("role") == "Security Administrator" else EMPLOYEE
        if actor and actor.get("role") == "Security Administrator" and role not in {
            "Security Administrator", "Security Analyst", EMPLOYEE, "Auditor", "Service",
        }:
            raise ValidationError("role is not supported")
        duplicate = db.session.query(User.id).filter(
            or_(User.username == data["username"], User.email == data["email"])
        ).first()
        if duplicate:
            raise ConflictError("username or email is already registered")

        user = User(
            full_name=data["full_name"], username=data["username"], email=data["email"],
            password_hash=bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
            department=data["department"], role=role,
        )
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise ConflictError("username or email is already registered") from error
        log_event(
            actor.get("user_id") if actor else None, USER_CREATED,
            f"Created user {user.username}", "Information", "users",
        )
        return self.serialize(user)

    def login(self, data):
        require_fields(data, {"password"}, {"username", "email", "password"})
        identifier = data.get("username") or data.get("email")
        if not identifier:
            raise ValidationError("username or email is required")
        user = db.session.query(User).filter(
            or_(User.username == identifier, User.email == identifier)
        ).first()
        password_matches = user is not None and bcrypt.checkpw(
            data["password"].encode("utf-8"), user.password_hash.encode("utf-8")
        )
        if not password_matches:
            log_event(user.id if user else None, LOGIN_FAILED, "Failed login attempt", "Warning", "users")
            raise Unauthorized("Invalid username/email or password")
        if user.account_status != "Active":
            log_event(user.id, LOGIN_FAILED, f"Login denied for {user.account_status.lower()} account", "Warning", "users")
            raise PermissionDenied("This account is inactive or suspended")

        user.last_login = datetime.utcnow()
        db.session.commit()
        log_event(user.id, LOGIN_SUCCESS, f"User {user.username} logged in", "Information", "users")
        return {"token": create_token(user), "user": self.serialize(user)}

    def update(self, user_id, data, actor):
        is_admin = actor["role"] == "Security Administrator"
        user = db.session.get(User, user_id)
        if user is None:
            raise NotFoundError("User not found")
        if not is_admin and actor["user_id"] != user.id:
            raise PermissionDenied("Regular employees may only update their own account")
        editable_fields = {"full_name", "email", "department"}
        if is_admin:
            editable_fields |= {"username", "role", "account_status"}
        unexpected = set(data) - editable_fields
        if unexpected:
            raise PermissionDenied(f"You cannot update these fields: {', '.join(sorted(unexpected))}")
        if not data:
            raise ValidationError("At least one field is required")
        if "email" in data and not valid_email(data["email"]):
            raise ValidationError("email must be a valid email address")
        if "role" in data and data["role"] not in ROLES:
            raise ValidationError("role is not supported")
        if "account_status" in data and data["account_status"] not in ACCOUNT_STATUSES:
            raise ValidationError("account_status is not supported")
        for field in ("username", "email"):
            if field in data:
                duplicate = db.session.query(User.id).filter(
                    getattr(User, field) == data[field], User.id != user.id
                ).first()
                if duplicate:
                    raise ConflictError(f"{field} is already in use")

        old_role = user.role
        old_status = user.account_status
        for field, value in data.items():
            setattr(user, field, value)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise ConflictError("username or email is already in use") from error
        log_event(user.id, USER_UPDATED, f"Updated user {user.username}", "Information", "users")
        if user.role != old_role or user.account_status != old_status:
            log_event(user.id, ROLE_CHANGED, f"Changed role/status for user {user.username}", "Warning", "users")
        return self.serialize(user)

    def delete(self, user_id, actor):
        user = db.session.get(User, user_id)
        if user is None:
            raise NotFoundError("User not found")
        username = user.username
        db.session.delete(user)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise ConflictError("User cannot be deleted because other records reference this account") from error
        log_event(actor["user_id"], USER_DELETED, f"Deleted user {username}", "Warning", "users")
        return {"id": user_id, "username": username}

    def list_users(self, role=None):
        query = db.session.query(User)
        if role:
            if role not in ROLES:
                raise ValidationError("role is not supported")
            query = query.filter(User.role == role)
        return [self.serialize(user) for user in query.order_by(User.id).all()]

    def get_by_username(self, username, actor):
        user = db.session.query(User).filter_by(username=username).first()
        if user is None:
            raise NotFoundError("User not found")
        if actor["role"] == EMPLOYEE and actor["username"] != user.username:
            raise PermissionDenied("Regular employees may only view their own account")
        return self.serialize(user)

    @staticmethod
    def serialize(user):
        return {
            "id": user.id,
            "full_name": user.full_name,
            "username": user.username,
            "email": user.email,
            "department": user.department,
            "role": user.role,
            "account_status": user.account_status,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }

    def health(self):
        return {"service": "users", "status": "healthy"}
