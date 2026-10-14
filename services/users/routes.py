"""HTTP routes for the users service."""

import jwt
from flask import Blueprint, g, request

from common.config import JWT_ALGORITHM, JWT_SECRET
from common.constants import ADMIN, AUDITOR, EMPLOYEE
from common.auth import require_roles
from common.errors import error_response, success_response
from common.validators import require_fields, require_json_body
from services.users.service import UsersService

blueprint = Blueprint("users", __name__)
service = UsersService()


@blueprint.post("/users/register")
def register():
    """Author: Haya Karanouh. Register a user with a role based on the caller."""
    data = require_json_body({"full_name", "username", "email", "password", "department", "role"})
    require_fields(data, {"full_name", "username", "email", "password", "department", "role"})
    actor = None
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return error_response("Missing or invalid bearer token", 401)
        try:
            actor = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.PyJWTError:
            return error_response("Invalid or expired token", 401)
        if "role" not in actor:
            return error_response("Invalid token claims", 401)
    return success_response("User registered", service.register(data, actor), 201)


@blueprint.post("/users/login")
def login():
    """Author: Haya Karanouh. Authenticate a user and return a JWT."""
    data = require_json_body({"username", "email", "password"})
    return success_response("Login successful", service.login(data))


@blueprint.put("/users/<int:user_id>")
@require_roles(ADMIN, EMPLOYEE)
def update_user(user_id):
    """Author: Haya Karanouh. Update an account according to the caller's role."""
    allowed = {"full_name", "username", "email", "department", "role", "account_status"}
    data = require_json_body(allowed)
    return success_response("User updated", service.update(user_id, data, g.user))


@blueprint.delete("/users/<int:user_id>")
@require_roles(ADMIN)
def delete_user(user_id):
    """Author: Haya Karanouh. Delete an unreferenced user as an administrator."""
    return success_response("User deleted", service.delete(user_id, g.user))


@blueprint.get("/users")
@require_roles(ADMIN, AUDITOR)
def list_users():
    """Author: Haya Karanouh. List user summaries with an optional role filter."""
    return success_response("Users retrieved", {"users": service.list_users(request.args.get("role"))})


@blueprint.get("/users/<string:username>")
@require_roles(ADMIN, AUDITOR, EMPLOYEE)
def get_user(username):
    """Author: Haya Karanouh. Retrieve a user within the caller's access scope."""
    return success_response("User retrieved", service.get_by_username(username, g.user))


@blueprint.get("/health")
def health():
    """Author: Haya Karanouh. Return users service health."""
    return success_response("users service is healthy", service.health())
