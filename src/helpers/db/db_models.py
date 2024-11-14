from helpers.db.db_init import db
from sqlalchemy import func

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    social_signup = db.Column(db.Boolean, default=False)
    max_api_key = db.Column(db.Integer, default=3)
    created_at = db.Column(
        db.TIMESTAMP, server_default=func.now(), nullable=False
    )  # (This time relies on server time zone e.g., UTC+2:00)
    confirmation_token = db.Column(db.String(100), nullable=True)
    confirmation_token_expiration = db.Column(db.DateTime, nullable=True)
    confirmed = db.Column(db.Boolean, default=False)
    ip_signup = db.Column(db.String(45), nullable=True)
    ip_last = db.Column(db.String(45), nullable=True)
    first_name = db.Column(db.Boolean, default=False)
    name_changed_at = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    first_request_timestamp = db.Column(db.DateTime, nullable=True)
    request_count = db.Column(db.Integer, default=0)
    request_limit = db.Column(db.Integer, default=1000)


class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    api_key = db.Column(db.String(150), unique=True, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=func.now(), nullable=False)
    user = db.relationship("User", backref=db.backref("api_keys", lazy=True))


class ApiKeyAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action_type = db.Column(db.String(20), nullable=False)
    action_date = db.Column(db.Date, nullable=False)
    action_count = db.Column(db.Integer, default=0)
    user = db.relationship("User", backref=db.backref("api_key_actions", lazy=True))