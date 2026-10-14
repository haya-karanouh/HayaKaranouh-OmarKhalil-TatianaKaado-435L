"""Business logic for users service."""

import bcrypt
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from common.constants import EMPLOYEE, USER_CREATED
from common.db import db
from common.errors import ConflictError, ValidationError
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
        log_event(user.id, USER_CREATED, f"Created user {user.username}", "Information", "users")
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
