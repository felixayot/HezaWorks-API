'''Module for user authentication views.'''
from flask_restx import Namespace, Resource, fields
from api.models.users import User
from api.models.roles import Role
from api.utils.jwt import jwt
from api.models.user_roles import UserRole
from api.auth.decorators import auth_role_required
from flask import request, jsonify
from api.models.revoked_tokens import RevokedToken
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import Conflict, BadRequest, Unauthorized
from http import HTTPStatus
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    get_jwt,
    current_user
    )

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']
    return User.query.filter_by(username=identity).one_or_none()

@jwt.token_in_blocklist_loader
def token_in_blocklist_callback(jwt_header, jwt_data):
    jti = jwt_data['jti']
    return RevokedToken.jti_in_blocklist(jti)

auth_namespace=Namespace('auth',
                         description="a namespace for authentication")

signup_model=auth_namespace.model('Signup', {
    'first_name': fields.String(required=True, description='User first name'),
    'last_name': fields.String(required=True, description='User last name'),
    'username': fields.String(required=True, description='User username'),
    'email': fields.String(required=True, description='User email'),
    'company': fields.String(description='User company'),
    'password': fields.String(required=True, description='User password'),
    'confirm_password': fields.String(required=True,
                                      description='User password confirmation')
})

login_model=auth_namespace.model('Login', {
    'username': fields.String(required=True, description='User username'),
    'password': fields.String(required=True, description='User password')
})

user_model=auth_namespace.model('User', {
    'id': fields.Integer(description='User ID'),
    'first_name': fields.String(description='User first name'),
    'last_name': fields.String(description='User last name'),
    'username': fields.String(description='User username'),
    'email': fields.String(description='User email'),
    'password_hash': fields.String(description='User password hash'),
    'company': fields.String(description='User company'),
    'is_active': fields.Boolean(description='User is active'),
    'roles': fields.ClassName(UserRole, description='User assigned roles')
})

@auth_namespace.route('/signup')
class SignUp(Resource):
    ''' Resource for user signup. '''
    @auth_namespace.expect(signup_model)
    @auth_namespace.marshal_with(user_model)
    def post(self):
        '''
            Create a new user
        '''
        data = request.get_json()
        try:
            new_user = User(
                first_name=data.get('first_name'),
                last_name=data.get('last_name'),
                username=data.get('username'),
                email=data.get('email'),
                company=data.get('company'),
                password_hash=generate_password_hash(data.get('password'))
            )
            new_user.save()
            role = Role.query.filter_by(slug='user').first()
            user_role = UserRole(user_id=new_user.id, role_id=role.id)
            user_role.save()
            return new_user, HTTPStatus.CREATED
        except Exception as e:
            if e.args[0] == '(sqlite3.IntegrityError) UNIQUE constraint failed: users.username':
                raise Conflict(f'User with username: {data.get("username")} already exists.')
            elif e.args[0] == '(sqlite3.IntegrityError) UNIQUE constraint failed: users.email':
                raise Conflict(f'User with email: {data.get("email")} already exists.')
            elif e.args[0] == 'sqlalchemy.exc.InvalidRequestError: One or more':
                print('Database Error:' + e)
            else:
                raise Unauthorized('Invalid username or password.')


@auth_namespace.route('/login')
class Login(Resource):
    ''' Resource for user login. '''
    @auth_namespace.expect(login_model)
    def post(self):
        '''
            Log in a user
        '''
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            raise BadRequest('Missing username or password.')
        user = User.query.filter_by(username=username).first()
        if not user:
            raise Unauthorized('User does not exist.')
        user_roles = UserRole.query.filter_by(user_id=user.id).all()
        user_roles=[role.role_id for role in user_roles]
        if user and check_password_hash(user.password_hash, password):
            access_token = create_access_token(identity=username)
            refresh_token = create_refresh_token(identity=username)
            return {
                'message': 'User login successful',
                'roles': user_roles,
                'access_token': access_token,
                'refresh_token': refresh_token
            }, HTTPStatus.OK
        if not check_password_hash(user.password_hash, password):
            raise Unauthorized('Invalid username or password.')
        if not user.is_active:
            raise Unauthorized('User is not active.')


@auth_namespace.route('/refresh')
class Refresh(Resource):

    @jwt_required(refresh=True)
    def post(self):
        '''
            Refresh a user token
        '''
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user)
        return {
            'access_token': new_token
        }, HTTPStatus.OK


@auth_namespace.route('/logout')
class Logout(Resource):

    @jwt_required()
    def post(self):
        '''
            Log out a user
        '''
        jti = get_jwt()['jti']
        revoked_token = RevokedToken(jti=jti)
        revoked_token.save()
        return {
            'message': f'{current_user.username} logged out successfully'
        }, HTTPStatus.OK
    

@auth_namespace.route('/whois')
class WhoIs(Resource):
    method_decorators = [auth_role_required(1), jwt_required()]
    def get(self):
        '''
            Get user details
        '''
        user_roles=UserRole.query.filter_by(user_id=current_user.id).all()
        user_roles=[role.role_id for role in user_roles]
        return {
            'message': 'User details retrieved successfully',
            'current user details': {
                'username': current_user.username,
                'email': current_user.email,
                'roles': user_roles
                }
            }, HTTPStatus.OK


@auth_namespace.route('/users/recruiters')
class GetAllUsers(Resource):
    method_decorators = [auth_role_required(['super-admin', 'admin']), jwt_required()]

    @auth_namespace.marshal_with(user_model)
    def get(self):
        '''Get all users'''
        users = User.query.filter_by(roles=['recruiter']).all()
        return users, HTTPStatus.OK


@auth_namespace.route('/users')
class GetAllUsers(Resource):
    method_decorators = [auth_role_required('super-admin'), jwt_required()]

    def get(self):
        '''Get all users'''
        users = User.query.all()
        return users, HTTPStatus.OK
