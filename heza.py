'''Module for the application entry point.'''
from api import create_app
from api.utils.db import db
from api.models.users import User
from api.models.job_posts import JobPost


app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'JobPost': JobPost}
