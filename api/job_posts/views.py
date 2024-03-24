from flask_restx import Namespace, Resource, fields
from api.utils.db import db
from api.utils.jwt import jwt
from api.models.job_posts import JobPost
from api.models.users import User
from api.auth.decorators import auth_role_required
from werkzeug.exceptions import Unauthorized, BadRequest, Forbidden
from flask_jwt_extended import jwt_required, get_jwt_identity
from http import HTTPStatus
from datetime import datetime


jobs_namespace=Namespace('jobs', description="a namespace for job posts")

jobposts_model=jobs_namespace.model('JobPost', {
    'id': fields.Integer(description='Job post ID'),
    'title': fields.String(required=True, description='Job title'),
    'organization': fields.String(description='Company name'),
    'description': fields.String(required=True, description='Job description'),
    'requirements': fields.String(required=True, description='Job requirements'),
    'posted_at': fields.DateTime(description='Date and time the job was posted'),
    'expires_on': fields.DateTime(required=True, description='Date and time the job post expires'),
})


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']
    return User.query.filter_by(username=identity).one_or_none()



@jobs_namespace.route('/posts')
class GetJobposts(Resource):
    '''Class for Jobposts endpoint.'''
    @jobs_namespace.marshal_with(jobposts_model)
    def get(self):
        '''
            Get all job posts
        '''
        jobs = JobPost.query.all()
        return jobs, HTTPStatus.OK


@jobs_namespace.route('/posts/job/<int:id>')
class JobRUDbyId(Resource):
    '''Represents endpoint to view a job by id.'''
    @jobs_namespace.marshal_with(jobposts_model)
    def get(self, id):
        '''
            Get a single job post
        '''   
        return JobPost.get_job_by_id(id), HTTPStatus.OK


@jobs_namespace.route('/posts')
class ProtectedJobpostRoutes(Resource):
    '''Represents Endpoint for jobpost creation.'''
    method_decorators = [auth_role_required([1, 2, 3]), jwt_required()]
    @jobs_namespace.expect(jobposts_model)
    @jobs_namespace.marshal_with(jobposts_model)
    def post(self):
        '''
            Create a new job post
        '''
        data = jobs_namespace.payload
        username = get_jwt_identity()
        current_user = User.query.filter_by(username=username).first()
        '''
        if not data['title'] or data['description'] \
            or data['requirements'] or data['expires_on']:
            raise BadRequest('Please provide all required fields')
        '''
        expiredate = data['expires_on']
        expiredate = datetime.strptime(expiredate, '%Y-%m-%d')
        if expiredate < datetime.now():
            raise BadRequest('The expiry date cannot be now or in the past')
        try:
            new_job = JobPost(
                title=data['title'],
                organization=current_user.company,
                description=data['description'],
                requirements=data['requirements'],
                expires_on=expiredate,
                author=current_user)
            new_job.save()
            return new_job, HTTPStatus.CREATED
        except Exception as e:
            raise Unauthorized('Failed. Action unauthorized.') from e


@jobs_namespace.route('/posts/job/<int:id>')
class ProtectedJobRUD(Resource):
    method_decorators = [auth_role_required([1, 2, 3]), jwt_required()]
    @jobs_namespace.expect(jobposts_model)
    @jobs_namespace.marshal_with(jobposts_model)
    def put(self, id):
        '''
            Update a single job post
        '''
        post_to_update = JobPost.get_job_by_id(id)
        data = jobs_namespace.payload
        try:
            if data['title']:
                post_to_update.title = data['title']
            post_to_update.title = post_to_update.title

            if data['description']:
                post_to_update.description = data['description']
            post_to_update.description = post_to_update.description
            
            if data['requirements']:
                post_to_update.requirements = data['requirements']
            post_to_update.requirements = post_to_update.requirements

            db.session.commit()

            return post_to_update, HTTPStatus.OK
        except Exception as e:
            raise Forbidden('You do not have sufficient roles to update this job post.')

    def delete(self, id):
        '''
            Delete a single job post
        '''
        post_to_delete = JobPost.get_job_by_id(id)
        try:
            post_to_delete.delete()
            return {
                'message': 'Job post deleted successfully'
            }, HTTPStatus.OK
        except Exception as e:
            raise Forbidden('You do not have sufficient roles to delete this job post.')
