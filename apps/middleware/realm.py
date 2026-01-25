# -*- encoding: utf-8 -*-
"""
RijanAuth - Realm Middleware
Extracts realm context from URL for multi-tenancy
"""

from functools import wraps
from flask import g, request, abort, current_app, redirect, url_for, flash, session
from flask_login import current_user
import traceback
from apps.models.realm import Realm
from apps.models.role import Role


def get_realm_from_path():
    """
    Extract realm name from URL path.
    
    Expected URL patterns:
    - /auth/realms/{realm}/...
    - /realms/{realm}/...
    """
    path = request.path
    
    # Check for /auth/realms/{realm}/... pattern
    if path.startswith('/auth/realms/'):
        parts = path[len('/auth/realms/'):].split('/')
        if parts:
            return parts[0]
    
    # Check for /realms/{realm}/... pattern
    if path.startswith('/realms/'):
        parts = path[len('/realms/'):].split('/')
        if parts:
            return parts[0]
    
    return None


def load_realm():
    """
    Load the current realm from the URL path.
    Sets g.realm to the Realm instance or None.
    """
    realm_name = get_realm_from_path()
    
    if realm_name:
        realm = Realm.find_by_name(realm_name)
        g.realm = realm
        g.realm_name = realm_name
        current_app.logger.debug(f"Realm context loaded: {realm_name}", extra={'realm_id': realm.id if realm else 'None'})
    else:
        g.realm = None
        g.realm_name = None
        # current_app.logger.debug("No realm context found in path")


def require_realm(f):
    """
    Decorator to require a valid realm in the URL.
    Returns 404 if realm is not found.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.get('realm') is None:
            abort(404, description='Realm not found')
        if not g.realm.enabled:
            abort(404, description='Realm is disabled')
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_app.logger.debug("ADMIN ACCESS ATTEMPT", extra={
            'route': request.path,
            'user_authenticated': current_user.is_authenticated,
            'current_user_id': getattr(current_user, 'id', 'NOT AUTHENTICATED'),
            'session_id': session.get('_id', 'NO SESSION')
        })
        
        # Check authentication first
        if not current_user.is_authenticated:
            current_app.logger.warning("ADMIN ACCESS DENIED - NOT AUTHENTICATED", extra={
                'attempted_route': request.path,
                'client_ip': request.remote_addr
            })
            # flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth_bp.login', next=request.url))
        
        # Check admin permissions
        is_admin = False
        try:
            # Log user's roles for debugging
            user_roles = [role.name for role in current_user.roles]
            current_app.logger.debug("USER ROLES CHECK", extra={
                'user_id': current_user.id,
                'roles': user_roles,
                'has_admin_role': 'admin' in user_roles
            })
            
            # Check for admin role in current realm (or master if no realm context set, usually admin is master)
            # Logic: Admin needs 'admin' role in 'master' realm?
            # Or 'admin' role in current realm?
            
            # For now, simplistic check as per previous logic (if any)
            # Checking 'admin' role in user roles
            
            if 'admin' in user_roles:
                 is_admin = True
                 
        except Exception as e:
            current_app.logger.error("PERMISSION CHECK ERROR", extra={
                'exception': str(e),
                'stack_trace': traceback.format_exc()
            })
        
        if not is_admin:
            current_app.logger.warning("ADMIN ACCESS DENIED - INSUFFICIENT PERMISSIONS", extra={
                'user_id': current_user.id,
                'username': current_user.username,
                'attempted_route': request.path
            })
            flash('You do not have sufficient permissions to access this page.', 'danger')
            return redirect(url_for('admin.dashboard', realm_name='master'))
        
        return f(*args, **kwargs)
    return decorated_function


def get_current_realm():
    """Get the current realm from Flask's g object"""
    return g.get('realm')


def get_current_realm_name():
    """Get the current realm name"""
    return g.get('realm_name')


class RealmMiddleware:
    """
    WSGI middleware to handle realm context.
    Can be used for additional processing before Flask handles the request.
    """
    
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        # Additional realm-related processing can be added here
        return self.app(environ, start_response)
