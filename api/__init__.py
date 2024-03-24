''' This module creates an instance of the Flask app
    and initializes the database. 
'''
from flask import Flask
from flask_cors import CORS
from config import Config
from flask_restx import Api
from api.job_posts.views import jobs_namespace
from api.auth.views import auth_namespace
from api.utils.db import db
from api.utils.jwt import jwt
from werkzeug.exceptions import (
    NotFound, BadRequest,
    MethodNotAllowed, Unauthorized,
    Forbidden, InternalServerError
)


def create_app(config_class=Config):
    ''' Create an instance of the Flask app. '''
    app = Flask(__name__)
    app.config.from_object(config_class)
    api = Api(app, version='1.0', title='HezaWorks API', description='A REST API for employers and job seekers.')
    api.add_namespace(jobs_namespace)
    api.add_namespace(auth_namespace, path='/auth')
    CORS(app)
    
    db.init_app(app)
    jwt.init_app(app)

    @api.errorhandler(NotFound)
    def handle_not_found_error(error):
        ''' Handle 404 errors. '''
        return {'error': 'Not found'}, 404
    
    @api.errorhandler(BadRequest)
    def handle_bad_request_error(error):
        ''' Handle 400 errors. '''
        return {'error': 'Bad request'}, 400
    
    @api.errorhandler(MethodNotAllowed)
    def handle_method_not_allowed_error(error):
        ''' Handle 405 errors. '''
        return {'error': 'Method not allowed'}, 405
    
    @api.errorhandler(Unauthorized)
    def handle_unauthorized_error(error):
        ''' Handle 401 errors. '''
        return {'error': 'Unauthorized'}, 401
    
    @api.errorhandler(Forbidden)
    def handle_forbidden_error(error):
        ''' Handle 403 errors. '''
        return {'error': 'Forbidden'}, 403
    
    @api.errorhandler(InternalServerError)
    def handle_internal_server_error(error):
        ''' Handle 500 errors. '''
        return {'error': 'Internal server error'}, 500

    return app
