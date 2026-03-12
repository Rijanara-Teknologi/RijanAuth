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
    
    # Health check endpoint at root level
    @app.route('/api/health', methods=['GET'])
    def api_health():
        from flask import jsonify
        return jsonify({
            'status': 'ok',
            'version': '2.2.0',
            'service': 'RijanAuth'
        })
    
    # 3. OIDC Blueprint (OpenID Connect Protocol)
    from apps.blueprints.oidc import oidc_bp
    app.register_blueprint(oidc_bp)
    
    # 4. Media serving route
    @app.route('/media/<asset_id>/<filename>')
    def serve_media(asset_id, filename):
        """Serve media files for customization"""
        import os
        from flask import send_from_directory, abort
        from apps.models.customization import MediaAsset
        from apps.utils.media_handler import MediaHandler
        
        asset = MediaAsset.find_by_id(asset_id)
        if not asset or asset.stored_path != filename:
            abort(404)
        
        file_path = MediaHandler.get_file_path(asset)
        if not file_path or not os.path.exists(file_path):
            abort(404)
        
        upload_dir = MediaHandler.get_upload_directory()
        absolute_dir = os.path.abspath(upload_dir)
        return send_from_directory(absolute_dir, asset.stored_path, mimetype=asset.content_type)


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
        from apps.models.federation import UserFederationProvider, UserFederationMapper, UserFederationLink, FederationSyncLog
        from apps.models.customization import RealmPageCustomization, MediaAsset
        
        try:
            db.create_all()
            print('> Database tables created successfully')
            
            # Initialize master realm on first run
            _initialize_master_realm()
            
        except Exception as e:
            print('> Error: DBMS Exception: ' + str(e))

            # When an external database (e.g. MySQL) is explicitly configured,
            # do NOT silently fall back to SQLite.  The SQLAlchemy engine is
            # cached after the first connection attempt, so a second
            # db.create_all() call inside this except block would reuse the
            # same broken engine and raise another uncaught exception, causing
            # gunicorn to crash with a confusing "above exception was the
            # direct cause" chain.  Surface the problem clearly instead so the
            # operator knows exactly what to fix.
            current_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
            if current_uri.lower().startswith('mysql'):
                raise RuntimeError(
                    'Cannot connect to the configured MySQL database.\n'
                    f'Error: {e}\n'
                    'Please verify DB_HOST, DB_PORT, DB_NAME, DB_USERNAME, '
                    'and DB_PASS, and ensure the MySQL server is running and '
                    'the user has the required access privileges.\n'
                    'Error 1045 (Access Denied) or error 1130 (Host not '
                    'allowed) both indicate the MySQL user lacks the correct '
                    'grants for the connecting host.  To fix a pre-existing '
                    'volume, re-create it (docker compose down -v && docker '
                    'compose up -d), or connect as root and run:\n'
                    "  CREATE USER IF NOT EXISTS 'rijanauth_user'@'%' "
                    "IDENTIFIED BY '<your DB_PASS value>';\n"
                    "  GRANT ALL PRIVILEGES ON rijanauth.* TO "
                    "'rijanauth_user'@'%';\n"
                    '  FLUSH PRIVILEGES;'
                ) from e

            # Fallback to SQLite only when no external DB was configured
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
    if isinstance(config, dict):
        app.config.from_mapping(config)
    else:
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
