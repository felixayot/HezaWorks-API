'''Module for user authentication views.'''
from flask_restx import Namespace, Resource, fields
from api.models.users import User
from api.models.roles import Role
from api.utils.jwt import jwt
from api.models.user_roles import UserRole
from api.models.talent_profile import TalentProfile
from api.auth.decorators import auth_role_required
from flask import request, jsonify
from api.models.revoked_tokens import RevokedToken
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import (
    Conflict, BadRequest, Unauthorized,
    NotFound)
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

talentprofile_model=auth_namespace.model('TalentProfile', {
    'user_id': fields.Integer(description='User ID'),
    'resume': fields.String(required=True, description='User Resume'),
    'phone_number': fields.String(required=True, description='User mobile phone number'),
    'address': fields.String(required=True, description='User physical home address'),
    'city': fields.String(required=True, description='User current city of residence'),
    'education_level': fields.String(required=True, description='User highest level of education'),
    'institution': fields.String(required=True, description='User institution where certification was obtained'),
    'field': fields.String(required=True, description='User field of study'),
    'employer': fields.String(required=True, description='User former or current employer'),
    'title': fields.String(required=True, description='User title for former job'),
    'responsibilities': fields.String(required=True, description='User responsibilities in former work place')
})


@auth_namespace.route('/signup')
class SignUp(Resource):
    ''' Resource for user signup. '''
    @auth_namespace.expect(signup_model)
    @auth_namespace.marshal_with(user_model)
    @auth_namespace.doc(description='Create a new user')
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
            if data.get('company'):
                new_user.is_active = False
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
    @auth_namespace.doc(description='Log in a user')
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
                'user_id': user.id,
                'roles': user_roles,
                'access_token': access_token,
                'refresh_token': refresh_token
            }, HTTPStatus.OK
        if not check_password_hash(user.password_hash, password):
            raise Unauthorized('Invalid username or password.')
        '''
        if not user.is_active:
            raise Unauthorized('User is not active.')
        '''


@auth_namespace.route('/refresh')
class Refresh(Resource):

    @jwt_required(refresh=True)
    @auth_namespace.doc(description='Refresh a user token')
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
    @auth_namespace.doc(description='Log out a user')
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
    

@auth_namespace.route('/whois/<int:id>')
class WhoIs(Resource):
    method_decorators = [auth_role_required(1), jwt_required()]

    @auth_namespace.doc(description='Get user details', params={'id': 'User ID'})
    def get(self, id):
        '''
            Get user details
        '''
        user = User.query.filter_by(id=id).first()
        #user_roles=UserRole.query.filter_by(user_id=id).all()
        user_roles=[role.id for role in user.roles]
        return {
            'message': 'User details retrieved successfully',
            'current user details': {
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'roles': user_roles
                }
            }, HTTPStatus.OK


@auth_namespace.route('/users/recruiters')
class GetAllRecruiters(Resource):
    method_decorators = [auth_role_required([1, 2]), jwt_required()]

    @auth_namespace.marshal_with(user_model)
    @auth_namespace.doc(description='Get all recruiters')
    def get(self):
        '''Get all users'''
        users = User.query.filter_by(roles=['recruiter']).all()
        return users, HTTPStatus.OK


@auth_namespace.route('/users')
class GetAllUsers(Resource):
    method_decorators = [auth_role_required('super-admin'), jwt_required()]

    @auth_namespace.doc(description='Get all users')
    def get(self):
        '''Get all users'''
        users = User.query.all()
        return users, HTTPStatus.OK


@auth_namespace.route('/users/me')
class UserAccount(Resource):
    @jwt_required()
    @auth_namespace.doc(description='Get user account')
    def get(self):
        '''Get user account'''
        user = User.query.filter_by(username=current_user.username).first()
        user_roles=UserRole.query.filter_by(user_id=user.id).all()
        user_roles=[role.role_id for role in user_roles]
        full_name = user.first_name + ' ' + user.last_name
        #return user, HTTPStatus.OK
        return {
            'message': 'User Account Details',
            'userID': user.id,
            'name': full_name,
            'username': current_user.username,
            'email': current_user.email,
            'company': user.company,
            'roles': user_roles,
            'is_active': user.is_active,
            'created_at': str(user.created_at),
            'updated_at': str(user.updated_at)
                }, HTTPStatus.OK


@auth_namespace.route('/user/talentprofile')
class CreateTalentProfile(Resource):
    @auth_namespace.expect(talentprofile_model)
    @auth_namespace.marshal_with(talentprofile_model)
    @auth_namespace.doc(description='Create a talent profile')
    @jwt_required()
    def post(self):
        if current_user.is_active == False:
            raise Unauthorized('User is not active.')

        data = auth_namespace.payload
        if not data:
            raise BadRequest('No data provided.')
        if not data['resume'] or not data['phone_number'] \
            or not data['address'] or not data['city'] \
                or not data['education_level'] \
                    or not data['institution'] or not data['field'] \
                        or not data['employer'] or not data['title'] \
                            or not data['responsibilities']:
            raise BadRequest('Missing data.')
        try:
            talentprofile = TalentProfile(
                resume=data['resume'],
                phone_number=data['phone_number'],
                address=data['address'],
                city=data['city'],
                education_level=data['education_level'],
                institution=data['institution'],
                field=data['field'],
                employer=data['employer'],
                title=data['title'],
                responsibilities=data['responsibilities'],
                owner=current_user
                )
            talentprofile.save()
            return talentprofile, HTTPStatus.CREATED
        except Exception as e:
            raise BadRequest('Failed to create profile.') from e

    @auth_namespace.marshal_with(talentprofile_model)
    @auth_namespace.doc(description='Get a talent profile')
    @jwt_required()
    def get(self):
        '''Get user talent profile'''

        talentprofile = TalentProfile.query.filter_by(user_id=current_user.id).one_or_none()
        return talentprofile, HTTPStatus.OK

    @auth_namespace.expect(talentprofile_model)
    @auth_namespace.marshal_with(talentprofile_model)
    @auth_namespace.doc(description='Create a talent profile')
    @jwt_required()
    def put(self):
        '''Update a talent profile'''

        if current_user.is_active == False:
            raise Unauthorized('User is not active.')

        profile_to_update = TalentProfile.query.filter_by(user_id=current_user.id).one_or_none()
        data = auth_namespace.payload
        try:
            if data['resume']:
                profile_to_update.resume = data['resume']
            profile_to_update.resume = profile_to_update.resume
            if data['phone_number']:
                profile_to_update.phone_number = data['phone_number']
            profile_to_update.phone_number = profile_to_update.phone_number
            if data['address']:
                profile_to_update.address = data['address']
            profile_to_update.address = profile_to_update.address
            if data['city']:
                profile_to_update.city = data['city']
            profile_to_update.city = profile_to_update.city
            if data['education_level']:
                profile_to_update.education_level = data['education_level']
            profile_to_update.education_level = profile_to_update.education_level
            if data['institution']:
                profile_to_update.institution = data['institution']
            profile_to_update.institution = profile_to_update.institution
            if data['field']:
                profile_to_update.field = data['field']
            profile_to_update.field = profile_to_update.field
            if data['employer']:
                profile_to_update.employer = data['employer']
            profile_to_update.employer = profile_to_update.employer
            if data['title']:
                profile_to_update.title = data['title']
            profile_to_update.title = profile_to_update.title
            if data['responsibilities']:
                profile_to_update.responsibilities = data['responsibilities']
            profile_to_update.responsibilities = profile_to_update.responsibilities
            profile_to_update.save()
            return profile_to_update, HTTPStatus.OK
        except Exception as e:
            raise BadRequest('Failed to update profile.') from e


@auth_namespace.route('/users/talentlist')
class GetAllTalentUsers(Resource):
    method_decorators = [auth_role_required([1, 2, 3]), jwt_required()]

    @auth_namespace.doc(description='Get all talent users')
    def get(self):
        '''Get all talent users'''
        if current_user.is_active == False:
            raise Unauthorized('User is not active.')
        talents = []
        page = request.args.get('page', 1, type=int)
        try:
            profiles = TalentProfile.query.paginate(page=page, per_page=6)
            for p in profiles:
                talents.append({
                    'id': p.user_id,
                    'name': p.owner.first_name + ' ' + p.owner.last_name,
                    'email': p.owner.email,
                    'resume': p.resume,
                    'phone:': p.phone_number,
                    'city': p.city,
                    'education_level': p.education_level,
                    'institution': p.institution,
                    'field': p.field,
                    'employer': p.employer,
                    'title': p.title,
                    'responsibilities': p.responsibilities
                })
            return talents, HTTPStatus.OK
        except Exception as e:
            raise NotFound('No talent profiles found') from e


@auth_namespace.route('/users/newrecruiter/<int:id>')
class ManageUser(Resource):
    method_decorators = [auth_role_required([1, 2]), jwt_required()]
    @auth_namespace.marshal_with(user_model)
    @auth_namespace.doc(description='Make a user a recruiter by id', params={'id': 'User ID'})
    def put(self, id):
        '''Make a user a recruiter by id'''
        user = User.query.filter_by(id=id).first()
        user.is_active = True
        make_recruiter = UserRole(user_id=user.id, role_id=3)
        make_recruiter.save()
        user.save()
        return user, HTTPStatus.OK


@auth_namespace.route('/users/newadmin/<int:id>')
class MakeAdmin(Resource):
    method_decorators = [auth_role_required(1), jwt_required()]
    @auth_namespace.marshal_with(user_model)
    @auth_namespace.doc(description='Make a user an admin by id', params={'id': 'A user ID'})
    def put(self, id):
        '''Make a user an admin by id'''
        user = User.query.filter_by(id=id).first()
        make_recruiter = UserRole(user_id=user.id, role_id=2)
        make_recruiter.save()
        user.save()
        return user, HTTPStatus.OK


@auth_namespace.route('/users/deactivate/<int:id>')
class DeactivateUser(Resource):
    method_decorators = [auth_role_required([1, 2]), jwt_required()]
    @auth_namespace.marshal_with(user_model)
    @auth_namespace.doc(description='Deactivate a user by id', params={'id': 'A user ID'})
    def put(self, id):
        '''Deactivate a user by id'''
        user = User.query.filter_by(id=id).first()
        user.deactivate()
        return user, HTTPStatus.OK


@auth_namespace.route('/users/activate/<int:id>')
class ActivateUser(Resource):
    method_decorators = [auth_role_required([1, 2]), jwt_required()]
    @auth_namespace.marshal_with(user_model)
    @auth_namespace.doc(description='Activate a user by id', params={'id': 'A user ID'})
    def put(self, id):
        '''Activate a user by id'''
        user = User.query.filter_by(id=id).first()
        user.activate()
        return user, HTTPStatus.OK
    

@auth_namespace.route('/users/delete/<int:id>')
class DeleteUser(Resource):
    method_decorators = [auth_role_required(1), jwt_required()]
    @auth_namespace.marshal_with(user_model)
    @auth_namespace.doc(description='Delete a user by id', params={'id': 'A user ID'})
    def delete(self, id):
        '''Delete a user by id'''
        user = User.query.filter_by(id=id).first()
        user.delete()
        return user, HTTPStatus.OK
