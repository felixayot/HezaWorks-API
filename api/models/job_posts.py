'''Module for JobPost model.'''
from api.utils.db import db
from datetime import datetime


class JobPost(db.Model):
    __tablename__ = 'job_posts'
    '''
        Represents a job post.
    '''
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(45), index=True, nullable=False)
    organization = db.Column(db.Text, index=True)
    description = db.Column(db.Text, index=True, nullable=False)
    requirements = db.Column(db.Text, index=True, nullable=False)
    posted_at = db.Column(db.DateTime(timezone=True),
                           default=datetime.now)
    expires_on = db.Column(db.DateTime(timezone=True), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    applicants = db.relationship('Application', backref='job_post', lazy=True)

    def __repr__(self):
        ''' Return a string representation of the job post.'''
        return '<JobPost {}>'.format(self.id)
    
    def save(self):
        ''' Save a job post to the database.'''
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        ''' Delete a job post from the database.'''
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def get_job_by_id(cls, id):
        return cls.query.get_or_404(id)
