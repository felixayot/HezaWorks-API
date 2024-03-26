'''Decorators for authenticating roles.'''
from functools import wraps
from flask import make_response, jsonify
from flask_jwt_extended import current_user
from api.utils.jwt import jwt
from api.models.users import User

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']
    return User.query.filter_by(username=identity).one_or_none()

def auth_role_required(role_id):
    ''' Decorator to require a role for a route.'''
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            roles = role_id if isinstance(role_id, list) else [role_id]
            if all(not current_user.has_role(r) for r in roles):
                msg = {
                     'message': 'You do not have sufficient roles to access this page.'
                     }
                return make_response(msg, 403)
            return fn(*args, **kwargs)
        return decorator
    return wrapper
