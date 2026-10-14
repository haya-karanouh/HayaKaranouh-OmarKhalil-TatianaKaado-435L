"""Flask application for the playbooks service."""

from flask import Flask

from common.db import init_db
from common.errors import register_error_handlers
from services.playbooks.routes import blueprint


def create_app():
    app = Flask(__name__)
    import common.models  # noqa: F401
    init_db(app)
    register_error_handlers(app)
    app.register_blueprint(blueprint)
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5009)
