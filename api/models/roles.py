'''Roles class definition.'''
from api.utils.db import db
from api.models.user_roles import UserRole


class Role(db.Model):
    __tablename__ = 'roles'
    ''' Represents a user role. '''
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(45), index=True, nullable=False)
    slug = db.Column(db.String(45), index=True, nullable=False, unique=True)
    users = db.relationship('User', secondary='user_roles',
                            back_populates='roles', lazy=True)

    def __repr__(self):
        ''' Return a string representation of the role.'''
        return '<Role: {}>'.format(self.slug)
    
    def save(self):
        ''' Save a role to the database.'''
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        ''' Delete a role from the database.'''
        db.session.delete(self)
        db.session.commit()
    
    """
    @classmethod
    def get_role_by_id(cls, id):
        ''' Get a role by its ID.'''
        return cls.query.get_or_404(id)
    
    @classmethod
    def get_role_by_name(cls, name):
        ''' Get a role by its name.'''
        return cls.query.filter_by(name=name).first()
    
    @classmethod
    def get_all_roles(cls):
        ''' Get all roles.'''
        return cls.query.all()
    
    @classmethod
    def get_role_by_name_or_404(cls, name):
        ''' Get a role by its name or return 404.'''
        return cls.query.filter_by(name=name).first_or_404()
    
    @classmethod
    def get_role_by_id_or_404(cls, id):
        ''' Get a role by its ID or return 404.'''
        return cls.query.get_or_404(id)
    
    @classmethod
    def delete_role(cls, id):
        ''' Delete a role.'''
        role = cls.query.get_or_404(id)
        db.session.delete(role)
        db.session.commit()
        return role
    """
