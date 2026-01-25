# -*- encoding: utf-8 -*-
"""
RijanAuth - Authentication Blueprint
Handles login, logout, and session management
"""

from flask import Blueprint
from apps import login_manager

auth_bp = Blueprint(
    'auth_bp',
    __name__,
    template_folder='templates',
    url_prefix='/auth'
)

# Move user loaders here
@login_manager.user_loader
def user_loader(id):
    from flask import current_app
    current_app.logger.debug(f"USER LOADER INVOKED: id={id}")
    from apps.models.user import User
    try:
        user = User.find_by_id(id)
        if user:
            current_app.logger.debug(f"USER LOADED SUCCESSFULLY: {user.username}")
        else:
            current_app.logger.warning(f"USER NOT FOUND: id={id}")
        return user
    except Exception as e:
        current_app.logger.error(f"USER LOADER EXCEPTION: {e}", extra={'stack': True})
        return None

# REMOVED: request_loader was incorrectly authenticating users based on form username
# without verifying password. This was a security vulnerability and also caused
# login to fail because current_user.is_authenticated was True before password check.
#
# The correct flow is:
# 1. User submits username/password via form
# 2. Login route manually verifies credentials
# 3. login_user() is called to set session
# 4. user_loader loads user from session cookie on subsequent requests

from apps.blueprints.auth import routes
