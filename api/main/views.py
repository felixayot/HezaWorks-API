'''Module for the API's main views.'''
from flask_restx import Namespace, Resource, fields
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import (
    BadRequest, RequestEntityTooLarge,
    NotFound
)
import os
from config import basedir
import secrets
from flask import request, send_from_directory

# basedir = os.path.abspath(os.path.dirname(__file__))
# This gets the cwd of the file that is being run,
# which is hezaworks/api/main/views.py but I need the cwd
# of root directory of the project.
# Since I already have a basedir variable in the root folder of the app,
# I will import it from config.py located just at the root of the project.


RESUME_ALLOWED_EXTENSIONS = ['pdf', 'doc', 'docx']
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads/resumes/')
MAX_CONTENT_LENGTH = 2 * 1024 * 1024 # 2MB

main_namespace=Namespace('main', description="a namespace for the main API")

upload_parser = main_namespace.parser()
upload_parser.add_argument('file', location='files',
                           type=FileStorage)
upload_parser.add_argument('full_name', location='form', type=str, required=True)
upload_parser.add_argument('age', location='form', type=str, required=True)


"""
resume_model=main_namespace.model('ResumeUpload', {
    'resume': fields.String(required=True, description='Resume file to upload')
})
"""


def get_file(filename):
    ''' Get an uploaded file from storage. '''
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)

def remove_file(filename):
    ''' Remove an uploaded file. '''
    os.remove(UPLOAD_FOLDER + filename)

def save_file(form_file) -> str:
    if form_file.filename == '':
        raise BadRequest('No file selected')
    try:
        if not os.path.exists(UPLOAD_FOLDER):
            raise FileNotFoundError('Destination Directory not found')
            # Or you could just create it like below
            # os.makedirs(UPLOAD_FOLDER, mode = 0o755, exist_ok=True)
            # where mode=0o755 == chmod u=rwx,g=rx,o=rx,
            # the default dir permission
            # exist_ok=True means it will not raise
            # OSError if the directory exists,
            # but leaves the existing directory as is/unaltered.
            # It should work like $ mkdir -p /path/to/directory
        if form_file.content_length > MAX_CONTENT_LENGTH:
            raise RequestEntityTooLarge('File larger than 2MB')  
        random_hex = secrets.token_hex(8)
        _, f_ext = os.path.splitext(form_file.filename)
        f_ext_lower = f_ext.lower()
        if f_ext_lower[1:] not in RESUME_ALLOWED_EXTENSIONS:
            raise BadRequest('Invalid file type')
        resume_fn = random_hex + f_ext_lower
        resume_path = UPLOAD_FOLDER + resume_fn
        form_file.save(resume_path)
    except Exception as e:
        return 'Error saving file'
    return resume_fn


@main_namespace.route('/status')
class Status(Resource):
    '''Resource for checking the API's status.'''
    def get(self):
        '''Check the API's status.'''
        return {'status': 'API is running'}, 200


@main_namespace.route('/cv')
class UploadResume(Resource):
    '''Resource for uploading a resume.'''
    # @main_namespace.response(201,'Created',headers={'Content-Type':'multipart/form-data'})
    
    # @main_namespace.expect(resume_model)
    @main_namespace.expect(upload_parser)
    def post(self):
        '''Upload a resume.'''

        # Using RequestParser
        #payload = request.files['file']
        # print(payload)
        args = upload_parser.parse_args()
        uploaded_file = args['file'] # This is FileStorage instance
        full_name = args['full_name']
        age = args['age']
        print(f'Full name: {full_name}')
        print(f'Age: {age}')
        try:
            secure_fn = save_file(uploaded_file)
            save_path = UPLOAD_FOLDER + secure_fn
            return {
                'message': 'Resume uploaded successfully',
                'secure_file_name': secure_fn,
                'file_path': save_path,
                'full_name': full_name,
                'age': age
                }, 201
        except Exception as e:
            # if e.code == 413:
            #     return {'error': 'File too large. Max size is 2MB'}, 413
            # if e.code == 400:
            #     return {
            #         'error': 'Invalid file type. Allowed types are pdf, doc, docx'
            #         }, 400
            # raise BadRequest('No file selected')
            # raise RequestEntityTooLarge('File larger than 2MB')
            pass   
        '''
        resume = request.files['file']
        try:
            uploaded_file = save_file(resume)
            print(uploaded_file)
        except Exception as e:
            print(f'ERROR: {e}')
        '''

    def get(self):
        '''Get all resumes.'''
        files = os.listdir(UPLOAD_FOLDER)
        return {
            'message': 'Resumes retrieved successfully',
            'files': files
            }, 200

@main_namespace.route('/cv/<path:filename>')
class ViewResume(Resource):

    # @main_namespace.marshal_with(upload_parser)
    def get(self, filename):
        '''Get a resume.'''
        try:
            return get_file(filename)
        except Exception:
            return {'message': 'File not found'}, 404

    def delete(self, filename):
        '''Delete a resume.'''
        os.remove(UPLOAD_FOLDER + filename)
        return {'message': 'Resume deleted successfully'}, 204
