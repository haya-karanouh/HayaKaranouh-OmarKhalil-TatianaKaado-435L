"""Mint a development JWT for a seeded, active user."""

import argparse

from flask import Flask

from common.auth import create_token
from common.db import db, init_db
from common.models import User


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="username of a seeded active user")
    args = parser.parse_args()

    app = Flask(__name__)
    init_db(app)
    with app.app_context():
        user = db.session.query(User).filter_by(username=args.username).first()
        if user is None:
            parser.error(f"No seeded user named {args.username!r}")
        if user.account_status != "Active":
            parser.error(f"User {args.username!r} is not active")
        print(create_token(user))


if __name__ == "__main__":
    main()
