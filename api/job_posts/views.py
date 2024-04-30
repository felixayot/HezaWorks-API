from flask_restx import Namespace, Resource, fields
from flask import request
from api.utils.db import db
from api.utils.jwt import jwt
from api.models.job_posts import JobPost
from api.models.users import User
from api.models.applications import Application, Status
from api.auth.decorators import auth_role_required
from werkzeug.exceptions import (
    Unauthorized, BadRequest, Forbidden, NotFound
    )
from flask_jwt_extended import jwt_required, current_user
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
    'applicants': fields.List(fields.String, description='Applicants for the job post'),
})

applications_model=jobs_namespace.model('JobApplications', {
    'id': fields.Integer(description='Application ID'),
    'job_id': fields.Integer(description='Job post title'),
    'user_id': fields.Integer(description='Applicant username'),
    'status': fields.String(description='Application status')
})

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']
    return User.query.filter_by(username=identity).one_or_none()


@jobs_namespace.route('/posts')
class GetJobposts(Resource):
    '''Class for Jobposts endpoint.'''
    def get(self):
        '''
            Get all job posts
        '''
        posts = []
        page = request.args.get('page', 1, type=int)
        try:
            jobs = JobPost.query.order_by(JobPost.posted_at.desc()).paginate(page=page, per_page=4)
            for j in jobs:
                posts.append({
                    'id': j.id,
                    'title': j.title,
                    'organization': j.organization,
                    'description': j.description,
                    'requirements': j.requirements,
                    'posted_at': j.posted_at.strftime('%m-%d-%Y'),
                    'expires_on': j.expires_on.strftime('%m-%d-%Y')
                })
            return posts, HTTPStatus.OK
        except Exception as e:
            raise NotFound('No job posts found') from e


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
        if current_user.is_active == False:
            raise Unauthorized('Your account is deactivated. Please contact the administrator.')
        #username = get_jwt_identity()
        #current_user = User.query.filter_by(username=username).first()
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


@jobs_namespace.route('/posts/job/<int:id>/apply')
class ApplyForJob(Resource):
    @jwt_required()
    def post(self, id):
        '''
            Apply for a job post
        '''
        job_to_apply = JobPost.get_job_by_id(id)
        if job_to_apply.author == current_user:
            raise BadRequest('You cannot apply for your own job post')
        elif current_user.is_active == False:
            raise Unauthorized('Your account is deactivated. Please contact the administrator.')
        elif Application.query.filter_by(job_id=id, user_id=current_user.id).one_or_none():
            raise BadRequest('You have already applied for this job post')
            #if job_to_apply.expires_on < datetime.now():
            # raise BadRequest('This job post has expired')
        else:
            applctn = Application(
                job_post=job_to_apply,
                applicant=current_user,
            )
            applctn.save()
            return {
                'message': 'Application successful',
                'application_id': applctn.id,
                'job_id': job_to_apply.id,
                'job_title': job_to_apply.title,
                'applicant': current_user.username,
                'status': applctn.status.value
            }, HTTPStatus.CREATED


@jobs_namespace.route('/posts/job/<int:id>/applicants')
class GetApplicants(Resource):
    method_decorators = [auth_role_required([1, 2, 3]), jwt_required()]
    def get(self, id):
        '''
            Get all applicants for a job post
        '''
        apps = []
        job = JobPost.get_job_by_id(id)
        applctns = Application.query.filter_by(job_post=job).all()
        for a in applctns:
            apps.append({
                'application_id': a.id,
                'job_id': a.job_id,
                'job_title': a.job_post.title,
                'applicant': a.applicant.email,
                'status': a.status.value,
                'applied_at': a.applied_at.strftime('%m-%d-%Y')
            })
        return apps, HTTPStatus.OK
    

@jobs_namespace.route('/user/myposts')
class GetJobpostsByUser(Resource):
    method_decorators = [auth_role_required([1, 2, 3]), jwt_required()]
    def get(self):
        '''
            Get all job posts by a user
        '''
        if not current_user:
            return {
                'message': 'You are not perform this action. Please login.'
            }#, HTTPStatus.UNAUTHORIZED
        page = request.args.get('page', 1, type=int)
        posts = []
        try:
            jobs = JobPost.query.filter_by(author=current_user).\
                order_by(JobPost.posted_at.desc()).\
                    paginate(page=page, per_page=4)
            for j in jobs:
                posts.append({
                    'id': j.id,
                    'title': j.title,
                    'description': j.description,
                    'requirements': j.requirements,
                    'posted_at': j.posted_at.strftime('%m-%d-%Y'),
                    'expires_on': j.expires_on.strftime('%m-%d-%Y')
                    })
            return posts, HTTPStatus.OK
        except Exception as e:
            raise NotFound('No job posts found') from e


@jobs_namespace.route('/user/allapplicants')
class GetAllApplicants(Resource):
    method_decorators = [auth_role_required([1, 2, 3]), jwt_required()]
    def get(self):
        '''
            Get all job applications to all jobs for a single user.
        '''
        jobs = current_user.jobposts
        applications = []
        job_applicants = []
        for j in jobs:
            applications.append(j.applicants)
        for applicants in applications:
            for a in applicants:
                job_applicants.append({
                    'application_id': a.id,
                    'job_id': a.job_id,
                    'title': a.job_post.title,
                    'applicant': a.applicant.email,
                    'status': a.status.value,
                    'applied_at': a.applied_at.strftime('%m-%d-%Y')
                })
        return job_applicants, HTTPStatus.OK


@jobs_namespace.route('/user/myapplications')
class GetApplicationsByUser(Resource):
    @jwt_required()
    def get(self):
        '''
            Get all job applications for a user
        '''
        myapps = []
        applctns = current_user.applications
        for a in applctns:
            myapps.append({
                'application_id': a.id,
                'job_id': a.job_post.id,
                'job_title': a.job_post.title,
                'status': a.status.value,
                'applied_at': a.applied_at.strftime('%m-%d-%Y')
            })
        return myapps, HTTPStatus.OK


@jobs_namespace.route('/user/applications/<int:id>')
class GetApplicationById(Resource):
    @jwt_required()
    def get(self, id):
        '''
            Get an application by id
        '''
        if not current_user:
            return {
                'message': 'You are not perform this action. Please login.'
            }, HTTPStatus.UNAUTHORIZED
        application = Application.query.filter_by(id=id).first()
        if not application:
            raise NotFound('Application not found')
        return {
            'application_id': application.id,
            'job_id': application.job_id,
            'job_title': application.job_post.title,
            'applicant': application.applicant.email,
            'status': application.status.value,
            'applied_at': application.applied_at.strftime('%m-%d-%Y')
        }, HTTPStatus.OK


@jobs_namespace.route('/user/applicants/<int:id>')
class ManageApplications(Resource):
    method_decorators = [auth_role_required([1, 2, 3]), jwt_required()]

    def get(self, id):
        '''
            Get an application by id
        '''
        if not current_user:
            raise Unauthorized('You are not perform this action. Please login.')
        application = Application.query.filter_by(id=id).first()
        if not application:
            raise NotFound('Application not found')
        return {
            'application_id': application.id,
            'job_id': application.job_id,
            'job_title': application.job_post.title,
            'applicant': application.applicant.email,
            'status': application.status.value,
            'applied_at': application.applied_at.strftime('%m-%d-%Y')
        }, HTTPStatus.OK

    @jobs_namespace.expect(applications_model)
    def put(self, id):
        '''
            Update an application status
        '''
        application = Application.query.filter_by(id=id).first()
        data = jobs_namespace.payload
        try:
            if data['status'] == 'In Progress' or 'in progress':
                in_progress_str = data['status']
                in_progress = in_progress_str.replace(' ', '_')
                ip_status = Status[in_progress.upper()]
                application.status = ip_status
            else:
                status_str = data['status']
                upp_status = Status[status_str.upper()]
                application.status = upp_status
            application.status = application.status
            db.session.commit()

            return {
                'message': 'Application status updated successfully'
            }, HTTPStatus.OK
        except Exception as e:
            print(e)

    def delete(self, id):
        '''
            Delete an application
        '''
        application = Application.query.filter_by(id=id).first()
        try:
            application.delete()
            return {
                'message': 'Application deleted successfully'
            }, HTTPStatus.OK
        except Exception as e:
            raise Forbidden('You do not have sufficient roles to delete this application.') from e
