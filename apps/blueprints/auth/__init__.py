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
    try:
        from apps.models.user import User
        return User.query.get(id)
    except:
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
