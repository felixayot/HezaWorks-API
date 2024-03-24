'''User roles class definition.'''
from api.utils.db import db


class UserRole(db.Model):
    __tablename__ = 'user_roles'
    ''' Represents a user role. '''
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)

    def __repr__(self):
        ''' Return a string representation of the user role.'''
        return '<UserRole: {} -> {}>'.format(
            self.user_id,
            self.role_id
            )

    def save(self):
        ''' Save a user role to the database.'''
        db.session.add(self)
        db.session.commit()

    def delete(self):
        ''' Delete a user role from the database.'''
        db.session.delete(self)
        db.session.commit()
    
    """
    @classmethod
    def get_user_role_by_user_id(cls, user_id):
        ''' Get a user role by user ID.'''
        return cls.query.filter_by(user_id=user_id).first()
    
    @classmethod
    def get_user_role_by_role_id(cls, role_id):
        ''' Get a user role by role ID.'''
        return cls.query.filter_by(role_id=role_id).first()
    
    @classmethod
    def get_all_user_roles(cls):
        ''' Get all user roles.'''
        return cls.query.all()

    @classmethod
    def get_user_roles_by_user_id(cls, user_id):
        ''' Get all user roles by user ID.'''
        return cls.query.filter_by(user_id=user_id).all()
"""
