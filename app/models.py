from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.associationproxy import association_proxy
import re
from datetime import datetime, timezone

db = SQLAlchemy()

# User Model
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    # columns
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(), nullable=False)
    last_name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)

    # relationships
    journals = relationship('Jounal', back_populates='user' ,cascade='all, delete-orphan')

    # validations
    @validates('email')
    def validate_email(self, key, email):
        assert '@' in email, 'Invalid email format'
        assert re.match(r"[^@]+@[^@]+\.[^@]+", email), 'Invalid email format'
        return email
    
    @validates('password')
    def validate_password(self, key, password):
        assert len(password) > 6, "Password should be at least 6 characters long"
        assert re.search(r"[A-Z]", password), "Password should contain at least one uppercase letter"
        assert re.search(r"[a-z]", password), "Password should contain at least one lowercase letter"
        assert re.search(r"[0-9]", password), "Password should contain at least one digit"
        assert re.search(r"[!@#$%^&*(),.?\":{}|<>]", password), "Password should contain at least one special character"
        return password

# Journal Model
class Jounal(db.Model, SerializerMixin):
    __tablename__ = 'journals'

    # columns
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    body = db.Column(db.Text(), nullable=False)
    category = db.Column(db.String(), nullable=False, default='General')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

    # foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # relationships
    user = relationship('User', back_populates='journals')

    # validations
    @validates('title')
    def validate_title(self, key, title):
        assert len(title) > 0, "Title should not be empty"
        return title

    @validates('body')
    def validate_body(self, key, body):
        assert len(body) > 0, "Body should not be empty"
        return body
