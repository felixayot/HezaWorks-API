'''Class definition for rekoved tokens.'''
from api.utils.db import db
from datetime import datetime


class RevokedToken(db.Model):
    '''Class definition for revoked tokens.'''
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.now)

    def save(self):
        '''Method to add a token to the revoked tokens table.'''
        db.session.add(self)
        db.session.commit()

    @classmethod
    def jti_in_blocklist(cls, jti):
        '''Method to check if a token is in blocklist.'''
        query = cls.query.filter_by(jti=jti).one_or_none()
        return query is not None

    def __repr__(self):
        return f'<RevokedToken: {self.jti}>'
