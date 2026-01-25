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
    print(f"DEBUG_V2: user_loader called with id={id}", flush=True)
    from apps.models.user import User
    try:
        user = User.find_by_id(id)
        if user:
            print(f"DEBUG_V2: user_loader found user: {user.username}", flush=True)
        else:
            print(f"DEBUG_V2: user_loader returned None for id={id}", flush=True)
        return user
    except Exception as e:
        print(f"ERROR in user_loader: {e}", flush=True)
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
