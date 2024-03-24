'''User model for application users. '''
from api.utils.db import db
from api.models.roles import Role
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'
    '''
        Represents a user of the application.
    '''
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(45), index=True, nullable=False)
    last_name = db.Column(db.String(45), index=True, nullable=False)
    username = db.Column(db.String(45), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    company = db.Column(db.String(120), index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    jobposts = db.relationship('JobPost', backref='author', lazy=True)
    roles = db.relationship('Role', secondary='user_roles',
                            back_populates='users', lazy=True)
    
    def __repr__(self):
        ''' Return a string representation of a user.'''
        return '<User {}>'.format(self.username)
    
    def has_role(self, role):
        ''' Check if a user has a role.'''
        return bool(
            Role.query
            .join(Role.users)
            .filter(User.id == self.id)
            .filter(Role.id == role)
            .count() == 1
        )

    def save(self):
        ''' Save a user to the database.'''
        db.session.add(self)
        db.session.commit()

    def delete(self):
        ''' Delete a user from the database.'''
        db.session.delete(self)
        db.session.commit()
