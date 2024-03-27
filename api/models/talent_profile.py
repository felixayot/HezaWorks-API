'''Talent user professional profile class definition'''
from api.utils.db import db
from datetime import datetime


class TalentProfile(db.Model):
    __tablename__ = 'talent_profiles'
    '''
        Represents a talent user professional
        profile
    '''
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    resume = db.Column(db.String(45), index=True, nullable=False)
    phone_number = db.Column(db.Unicode(255), index=True, unique=True, nullable=False)
    address = db.Column(db.String(255), index=True, nullable=False)
    city = db.Column(db.String(255), index=True, nullable=False)
    education_level = db.Column(db.Text, index=True, nullable=False)
    institution = db.Column(db.Text, index=True, nullable=False)
    field = db.Column(db.Text, index=True, nullable=False)
    employer = db.Column(db.Text, index=True, nullable=False)
    title = db.Column(db.Text, index=True, nullable=False)
    responsibilities = db.Column(db.Text, index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    #bio = db.Column(db.Text)
    #website = db.Column(db.String(255))
    #linkedin = db.Column(db.String(255))
    #github = db.Column(db.String(255))
    #twitter = db.Column(db.String(255))
    #skills = db.Column(db.Text)
    #experience = db.Column(db.Text)
    #certifications = db.Column(db.Text)
    #interests = db.Column(db.Text)

    def __repr__(self):
        '''String representation of talent profile.'''
        return f'<TalentProfile {self.user_id}>'
    
    def save(self):
        '''Save new profile to db.'''
        db.session.add(self)
        db.session.commit()
