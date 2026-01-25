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
    login_manager.login_view = 'auth_bp.login'


def register_blueprints(app):
    """Register application blueprints"""
    
    # 1. Admin Blueprint (RijanAuth console)
    from apps.blueprints.admin import admin_bp
    app.register_blueprint(admin_bp)
    
    # 2. Auth Blueprint (Login/Logout)
    from apps.blueprints.auth import auth_bp
    app.register_blueprint(auth_bp)
    
    # Root redirect
    @app.route('/')
    def index():
        from flask import redirect, url_for
        return redirect(url_for('admin.index'))
    
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


def configure_logging(app):
    """Configure logging subsystem"""
    from apps.logging import setup_logging, LoggingMiddleware
    setup_logging(app)
    LoggingMiddleware(app)


def configure_realm_middleware(app):
    """Configure realm context middleware"""
    from apps.middleware.realm import load_realm
    
    @app.before_request
    def before_request():
        load_realm()


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
    
    # Configure logging
    configure_logging(app)
    
    # Register extensions
    register_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
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
