"""Create the shared schema and a predictable set of development accounts."""

import argparse

import bcrypt
from flask import Flask
from sqlalchemy import text

from common.db import db, init_db
from common.models import User

USERS = [
    ("Admin User", "admin", "admin@aub.edu", "Admin@1234", "Security", "Security Administrator", "Active"),
    ("Analyst User", "analyst", "analyst@aub.edu", "Analyst@1234", "Security", "Security Analyst", "Active"),
    ("Employee User", "employee", "employee@aub.edu", "Employee@1234", "Engineering", "Regular Employee", "Active"),
    ("Auditor User", "auditor", "auditor@aub.edu", "Auditor@1234", "Audit", "Auditor", "Active"),
    ("Analyst Two", "analyst2", "analyst2@aub.edu", "Analyst@1234", "Security", "Security Analyst", "Active"),
    ("Employee Two", "employee2", "employee2@aub.edu", "Employee@1234", "Engineering", "Regular Employee", "Active"),
    ("Suspended User", "suspended", "suspended@aub.edu", "Suspended@1234", "Engineering", "Regular Employee", "Suspended"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="drop and recreate all tables before seeding")
    args = parser.parse_args()

    app = Flask(__name__)
    init_db(app)
    with app.app_context():
        if args.reset:
            db.drop_all()
        db.create_all()
        db.session.execute(text(
            "CREATE TRIGGER IF NOT EXISTS logs_immutable_update "
            "BEFORE UPDATE ON logs BEGIN SELECT RAISE(ABORT, 'logs are immutable'); END"
        ))
        for full_name, username, email, password, department, role, account_status in USERS:
            if db.session.query(User).filter_by(username=username).first():
                continue
            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            db.session.add(User(
                full_name=full_name, username=username, email=email,
                password_hash=password_hash, department=department, role=role,
                account_status=account_status,
            ))
        db.session.commit()
        print(f"Database ready. {len(USERS)} development users are available.")


if __name__ == "__main__":
    main()
