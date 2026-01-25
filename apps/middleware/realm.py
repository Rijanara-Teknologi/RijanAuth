# -*- encoding: utf-8 -*-
"""
RijanAuth - Realm Middleware
Extracts realm context from URL for multi-tenancy
"""

from functools import wraps
from flask import g, request, abort
from apps.models.realm import Realm


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
    else:
        g.realm = None
        g.realm_name = None


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
