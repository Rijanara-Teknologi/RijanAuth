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

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    try:
        from apps.models.user import User
        from apps.models.realm import Realm
        
        master = Realm.get_master_realm()
        if master:
            user = User.find_by_username(master.id, username)
            return user
    except:
        pass
    return None

from apps.blueprints.auth import routes
