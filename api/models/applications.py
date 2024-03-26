'''Model for job applications.'''
from api.utils.db import db
from datetime import datetime
from enum import Enum


class Status(Enum):
    ''' Represents the status of a job application.'''
    SUBMITTED = 'Submitted'
    IN_PROGRESS = 'In Progress'
    ACCEPTED = 'Accepted'
    REJECTED = 'Rejected'


class Application(db.Model):
    __tablename__ = 'applications'
    '''
        Represents a job application.
    '''
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('job_posts.id'), nullable=False)
    status = db.Column(db.Enum(Status), default=Status.SUBMITTED)
    applied_at = db.Column(db.DateTime(timezone=True), default=datetime.now)

    def __repr__(self):
        ''' Return a string representation of the application.'''
        return '<Application {}>'.format(self.id)

    def save(self):
        ''' Save an application to the database.'''
        db.session.add(self)
        db.session.commit()

    def delete(self):
        ''' Delete an application from the database.'''
        db.session.delete(self)
        db.session.commit()
