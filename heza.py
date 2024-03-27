'''Module for the application entry point.'''
from api import create_app
from api.utils.db import db
from api.models.users import User
from api.models.job_posts import JobPost
from api.models.applications import Application
from api.models.talent_profile import TalentProfile


app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'JobPost': JobPost,
        'Application': Application,
        'TalentProfile': TalentProfile
        }
