"""Consistent API error and success response helpers."""

from flask import jsonify
from werkzeug.exceptions import HTTPException


class ApiError(Exception):
    status_code = 500

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class ValidationError(ApiError):
    status_code = 422


class NotFoundError(ApiError):
    status_code = 404


class ConflictError(ApiError):
    status_code = 409


class PermissionDenied(ApiError):
    status_code = 403


def error_response(message, status_code):
    return jsonify({"status": "error", "message": message}), status_code


def success_response(message, data=None, status_code=200):
    return jsonify({"status": "success", "message": message, "data": data}), status_code


def register_error_handlers(app):
    """Register JSON handlers for expected API and HTTP errors."""
    @app.errorhandler(ApiError)
    def handle_api_error(error):
        return error_response(error.message, error.status_code)

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return error_response(error.description, error.code or 500)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        app.logger.exception("Unhandled request error")
        return error_response("Internal server error", 500)
