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


def _run_schema_migrations():
    """
    Apply incremental schema changes to existing databases.

    ``db.create_all()`` only creates missing *tables*; it never adds columns to
    tables that already exist.  This function uses SQLAlchemy's inspection API
    to detect and add any columns that are present in the ORM models but
    absent from the live database schema.
    """
    from sqlalchemy import inspect as sa_inspect, text

    inspector = sa_inspect(db.engine)
    existing_tables = inspector.get_table_names()

    def _get_columns(table):
        return {col['name'] for col in inspector.get_columns(table)}

    # ------------------------------------------------------------------
    # backup_records – local_file_path column (added in v2.x)
    # ------------------------------------------------------------------
    if 'backup_records' in existing_tables:
        if 'local_file_path' not in _get_columns('backup_records'):
            try:
                with db.engine.connect() as conn:
                    conn.execute(text(
                        'ALTER TABLE backup_records ADD COLUMN local_file_path VARCHAR(1000)'
                    ))
                    conn.commit()
                print('> Migration: Added column local_file_path to backup_records')
            except Exception as exc:
                print('> Migration warning (backup_records.local_file_path): ' + str(exc))

    # ------------------------------------------------------------------
    # protocol_mappers – priority and consent_text columns (v2.4.0)
    # ------------------------------------------------------------------
    if 'protocol_mappers' in existing_tables:
        existing_cols = _get_columns('protocol_mappers')
        if 'priority' not in existing_cols:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text(
                        'ALTER TABLE protocol_mappers ADD COLUMN priority INTEGER DEFAULT 0 NOT NULL'
                    ))
                    conn.commit()
                print('> Migration: Added column priority to protocol_mappers')
            except Exception as exc:
                print('> Migration warning (protocol_mappers.priority): ' + str(exc))
        if 'consent_text' not in existing_cols:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text(
                        'ALTER TABLE protocol_mappers ADD COLUMN consent_text VARCHAR(255)'
                    ))
                    conn.commit()
                print('> Migration: Added column consent_text to protocol_mappers')
            except Exception as exc:
                print('> Migration warning (protocol_mappers.consent_text): ' + str(exc))

    # ------------------------------------------------------------------
    # import_jobs – create table if missing (added in queue-import feature)
    # db.create_all() handles this for fresh installs; this guard covers
    # existing databases that were created before the feature was added.
    # ------------------------------------------------------------------
    if 'import_jobs' not in existing_tables:
        try:
            from apps.models.import_job import ImportJob
            ImportJob.__table__.create(db.engine, checkfirst=True)
            print('> Migration: Created table import_jobs')
        except Exception as exc:
            print('> Migration warning (import_jobs): ' + str(exc))


def configure_database(app):
    """Configure database initialization"""

    # Enable SQLite performance optimisations for large imports.
    # These are applied once per new connection via the engine "connect" event.
    try:
        import sqlite3
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        @event.listens_for(Engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, connection_record):
            if isinstance(dbapi_connection, sqlite3.Connection):
                cursor = dbapi_connection.cursor()
                # WAL mode allows concurrent reads during writes and is much
                # faster for bulk inserts than the default DELETE journal mode.
                cursor.execute("PRAGMA journal_mode=WAL")
                # NORMAL sync is safe with WAL and avoids the overhead of
                # fsync after every write.
                cursor.execute("PRAGMA synchronous=NORMAL")
                # 64 MB page cache (negative value = kibibytes).
                cursor.execute("PRAGMA cache_size=-65536")
                # Store temp tables in memory instead of on disk.
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.close()
    except (ImportError, Exception) as _pragma_exc:
        print(f'> Warning: could not register SQLite pragma listener: {_pragma_exc}')
    
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
        from apps.models.backup import BackupConfig, BackupRecord
        from apps.models.import_job import ImportJob
        
        try:
            db.create_all()
            print('> Database tables created successfully')
            
            # Apply any incremental schema changes to existing tables
            _run_schema_migrations()
            
            # Initialize master realm on first run
            _initialize_master_realm()
            
        except Exception as e:
            print('> Error: DBMS Exception: ' + str(e))
    
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
    
    # Start backup auto-scheduler
    try:
        from apps.services.backup_service import BackupService
        BackupService.init_scheduler(app)
    except Exception as _e:
        pass
    
    # Add RijanAuth context
    @app.context_processor
    def inject_rijanauth_context():
        from config.seeding import SeedingConfig
        return {
            'rijanauth_version': '0.1.0',
            'current_realm': g.get('realm'),
            'current_realm_name': g.get('realm_name'),
            'master_realm_name': SeedingConfig.MASTER_REALM_NAME,
        }
    
    return app
