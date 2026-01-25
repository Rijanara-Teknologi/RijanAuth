# -*- encoding: utf-8 -*-
"""
RijanAuth Application Factory
Copyright (c) 2019 - present AppSeed.us
Extended for RijanAuth - OpenID Connect / SSO Server
"""

import os
from flask import Flask, g
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from importlib import import_module

db = SQLAlchemy()
login_manager = LoginManager()


def register_extensions(app):
    """Register Flask extensions"""
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'authentication_blueprint.login'


def register_blueprints(app):
    """Register application blueprints"""
    # Original Datta Able blueprints
    for module_name in ('authentication', 'home'):
        module = import_module('apps.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint)
    
    # RijanAuth Admin Blueprint
    try:
        from apps.blueprints.admin import admin_bp
        app.register_blueprint(admin_bp)
        print('> Admin blueprint registered at /admin')
    except ImportError as e:
        print(f'> Warning: Could not load admin blueprint: {e}')
    
    # RijanAuth OIDC Blueprint (will be added in Phase 3)
    # try:
    #     from apps.blueprints.oidc import oidc_bp
    #     app.register_blueprint(oidc_bp, url_prefix='/auth/realms')
    # except ImportError:
    #     pass


def configure_database(app):
    """Configure database initialization"""
    
    with app.app_context():
        # Import all models to register them with SQLAlchemy
        # This is required before db.create_all() can create the tables
        from apps.models.base import BaseModel, RealmScopedModel
        from apps.models.realm import Realm, RealmAttribute
        from apps.models.user import User, UserAttribute, Credential
        from apps.models.role import Role, RoleMapping
        from apps.models.group import Group, GroupMembership, GroupAttribute, GroupRoleMapping
        from apps.models.client import Client, ClientScope, ClientScopeMapping, ProtocolMapper
        from apps.models.session import UserSession, AuthenticatedClientSession, RefreshToken, AuthorizationCode
        from apps.models.identity_provider import IdentityProvider, IdentityProviderMapper, FederatedIdentity
        from apps.models.authentication import AuthenticationFlow, AuthenticationExecution, AuthenticatorConfig, RequiredAction
        from apps.models.event import Event, AdminEvent
        
        try:
            db.create_all()
            print('> Database tables created successfully')
            
            # Initialize master realm on first run
            _initialize_master_realm()
            
        except Exception as e:
            print('> Error: DBMS Exception: ' + str(e))
            
            # Fallback to SQLite
            basedir = os.path.abspath(os.path.dirname(__file__))
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3')
            
            print('> Fallback to SQLite ')
            db.create_all()
            _initialize_master_realm()
    
    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()


def _initialize_master_realm():
    """Initialize the database using the seeder system"""
    try:
        from apps.seeders import needs_seeding, run_initial_seed
        from apps.seeders.admin_user_seeder import InitialSetupToken
        
        # Create setup tokens table if not exists
        InitialSetupToken.__table__.create(db.engine, checkfirst=True)
        
        if needs_seeding():
            print('> First run detected - running initial database seeding...')
            admin_info = run_initial_seed()
            
            if admin_info and admin_info.get('password'):
                print('')
                print('=' * 60)
                print('  INITIAL ADMIN CREDENTIALS')
                print('=' * 60)
                print(f"  Username: {admin_info['user'].username}")
                print(f"  Password: {admin_info['password']}")
                print(f"  Expires:  {admin_info['expires_at']}")
                print('=' * 60)
                print('  ⚠️  SAVE THESE NOW - They will not be shown again!')
                print('=' * 60)
                print('')
        else:
            print('> Database already seeded')
    except Exception as e:
        print(f'> Warning: Could not run database seeding: {e}')
        import traceback
        traceback.print_exc()


def configure_realm_middleware(app):
    """Configure realm context middleware"""
    from apps.middleware.realm import load_realm
    
    @app.before_request
    def before_request():
        load_realm()


# Import OAuth blueprint
try:
    from apps.authentication.oauth import github_blueprint
    HAS_GITHUB_OAUTH = True
except ImportError:
    HAS_GITHUB_OAUTH = False


def create_app(config):
    """
    Application factory for creating the Flask app.
    
    Args:
        config: Configuration object
    
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    app.config.from_object(config)
    
    # Register extensions
    register_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register OAuth blueprint if available
    if HAS_GITHUB_OAUTH:
        app.register_blueprint(github_blueprint, url_prefix="/login")
    
    # Configure database
    configure_database(app)
    
    # Configure realm middleware
    configure_realm_middleware(app)
    
    # Add RijanAuth context
    @app.context_processor
    def inject_rijanauth_context():
        return {
            'rijanauth_version': '0.1.0',
            'current_realm': g.get('realm'),
            'current_realm_name': g.get('realm_name'),
        }
    
    return app
