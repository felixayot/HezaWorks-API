'''Module for the API's main views.'''
from flask_restx import Namespace, Resource

main_namespace=Namespace('main', description="a namespace for the main API")

@main_namespace.route('/status')
class Status(Resource):
    '''Resource for checking the API's status.'''
    def get(self):
        '''Check the API's status.'''
        return {'status': 'API is running'}, 200
