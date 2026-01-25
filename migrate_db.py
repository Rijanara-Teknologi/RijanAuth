# -*- encoding: utf-8 -*-
"""
Database Migration Script
Adds new columns and tables for v2.5.0 - Federated Role Synchronization
and v2.4.0 - Protocol Mapper enhancements
"""

import sqlite3
import os
import sys

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def get_db_path():
    """Get the database path from environment or default"""
    # Try to get from Flask app config
    try:
        from apps import create_app
        app = create_app()
        with app.app_context():
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
            if db_uri.startswith('sqlite:///'):
                db_path = db_uri.replace('sqlite:///', '')
                print(f"Found DB URI in config: {db_path}")
                return db_path
    except Exception as e:
        print(f"Could not get config from Flask app: {e}")
    
    # Default paths to check - relative and absolute
    basedir = os.path.dirname(os.path.abspath(__file__))
    apps_dir = os.path.join(basedir, 'apps')
    
    default_paths = [
        os.path.join(apps_dir, 'db.sqlite3'),
        os.path.join(basedir, 'db.sqlite3'),
        os.path.join(basedir, 'instance', 'rijanauth.db'),
        os.path.join(basedir, 'rijanauth.db'),
        os.path.join(basedir, 'app.db'),
    ]
    
    print("Checking paths:")
    for path in default_paths:
        exists = os.path.exists(path)
        print(f"  {path}: {'EXISTS' if exists else 'not found'}")
        if exists:
            return path
    
    # Final fallback to the apps/db.sqlite3 which is what config specifies
    return os.path.join(apps_dir, 'db.sqlite3')


def column_exists(cursor, table, column):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns


def table_exists(cursor, table):
    """Check if a table exists"""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,)
    )
    return cursor.fetchone() is not None


def run_migration():
    """Run database migrations"""
    db_path = get_db_path()
    
    print(f"Database path: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"Database file not found at {db_path}")
        print("Please run the application first to create the database.")
        return False
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    migrations = []
    
    # ==========================================================================
    # Protocol Mappers Table - Add priority and consent_text columns
    # ==========================================================================
    if table_exists(cursor, 'protocol_mappers'):
        if not column_exists(cursor, 'protocol_mappers', 'priority'):
            migrations.append((
                "ALTER TABLE protocol_mappers ADD COLUMN priority INTEGER DEFAULT 0 NOT NULL",
                "Added 'priority' column to protocol_mappers"
            ))
        
        if not column_exists(cursor, 'protocol_mappers', 'consent_text'):
            migrations.append((
                "ALTER TABLE protocol_mappers ADD COLUMN consent_text VARCHAR(255)",
                "Added 'consent_text' column to protocol_mappers"
            ))
    
    # ==========================================================================
    # Federation Role Mappings Table
    # ==========================================================================
    if not table_exists(cursor, 'federation_role_mappings'):
        migrations.append((
            """
            CREATE TABLE federation_role_mappings (
                id VARCHAR(36) PRIMARY KEY,
                provider_id VARCHAR(36) NOT NULL,
                external_role_name VARCHAR(255) NOT NULL,
                internal_role_id VARCHAR(36) NOT NULL,
                mapping_type VARCHAR(20) NOT NULL DEFAULT 'direct',
                mapping_value VARCHAR(255),
                enabled BOOLEAN DEFAULT 1 NOT NULL,
                priority INTEGER DEFAULT 0 NOT NULL,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY (provider_id) REFERENCES user_federation_providers(id) ON DELETE CASCADE,
                FOREIGN KEY (internal_role_id) REFERENCES roles(id) ON DELETE CASCADE,
                UNIQUE(provider_id, external_role_name)
            )
            """,
            "Created 'federation_role_mappings' table"
        ))
        
        migrations.append((
            "CREATE INDEX ix_federation_role_mappings_provider_id ON federation_role_mappings(provider_id)",
            "Created index on federation_role_mappings.provider_id"
        ))
    
    # ==========================================================================
    # Federation Role Format Config Table
    # ==========================================================================
    if not table_exists(cursor, 'federation_role_format_configs'):
        migrations.append((
            """
            CREATE TABLE federation_role_format_configs (
                id VARCHAR(36) PRIMARY KEY,
                provider_id VARCHAR(36) NOT NULL UNIQUE,
                format_type VARCHAR(20) NOT NULL DEFAULT 'string',
                format_pattern TEXT,
                delimiter VARCHAR(10) DEFAULT ',',
                array_path VARCHAR(100),
                role_field VARCHAR(100) DEFAULT 'roles' NOT NULL,
                enabled BOOLEAN DEFAULT 1 NOT NULL,
                auto_detect BOOLEAN DEFAULT 1 NOT NULL,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY (provider_id) REFERENCES user_federation_providers(id) ON DELETE CASCADE
            )
            """,
            "Created 'federation_role_format_configs' table"
        ))
    
    # ==========================================================================
    # Federated Role Syncs Table
    # ==========================================================================
    if not table_exists(cursor, 'federated_role_syncs'):
        migrations.append((
            """
            CREATE TABLE federated_role_syncs (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL,
                provider_id VARCHAR(36) NOT NULL,
                external_roles JSON NOT NULL,
                synchronized_roles JSON NOT NULL,
                roles_added JSON,
                roles_removed JSON,
                unmapped_roles JSON,
                format_detected VARCHAR(20),
                last_sync DATETIME NOT NULL,
                sync_type VARCHAR(20) NOT NULL DEFAULT 'login',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (provider_id) REFERENCES user_federation_providers(id) ON DELETE CASCADE
            )
            """,
            "Created 'federated_role_syncs' table"
        ))
        
        migrations.append((
            "CREATE INDEX ix_federated_role_sync_user_provider ON federated_role_syncs(user_id, provider_id)",
            "Created composite index on federated_role_syncs(user_id, provider_id)"
        ))
    
    # ==========================================================================
    # Media Assets Table
    # ==========================================================================
    if not table_exists(cursor, 'media_assets'):
        migrations.append((
            """
            CREATE TABLE media_assets (
                id VARCHAR(36) PRIMARY KEY,
                realm_id VARCHAR(36) NOT NULL,
                asset_type VARCHAR(20) NOT NULL CHECK (asset_type IN ('logo', 'background')),
                original_filename VARCHAR(255) NOT NULL,
                stored_path VARCHAR(512) NOT NULL,
                content_type VARCHAR(100) NOT NULL,
                file_size INTEGER NOT NULL,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE
            )
            """,
            "Created 'media_assets' table"
        ))
        
        migrations.append((
            "CREATE INDEX ix_media_assets_realm_id ON media_assets(realm_id)",
            "Created index on media_assets.realm_id"
        ))
    
    # ==========================================================================
    # Realm Page Customizations Table
    # ==========================================================================
    if not table_exists(cursor, 'realm_page_customizations'):
        migrations.append((
            """
            CREATE TABLE realm_page_customizations (
                id VARCHAR(36) PRIMARY KEY,
                realm_id VARCHAR(36) NOT NULL,
                page_type VARCHAR(50) NOT NULL CHECK (page_type IN ('login', 'register', 'forgot_password', 'consent', 'error')),
                background_type VARCHAR(20) NOT NULL DEFAULT 'color' CHECK (background_type IN ('color', 'gradient', 'image')),
                background_color VARCHAR(20) DEFAULT '#673AB7',
                background_gradient TEXT,
                background_image_id VARCHAR(36),
                primary_color VARCHAR(20) DEFAULT '#673AB7',
                secondary_color VARCHAR(20) DEFAULT '#3F51B5',
                font_family VARCHAR(100) DEFAULT 'Inter, system-ui, -apple-system, sans-serif',
                button_radius INTEGER DEFAULT 4,
                form_radius INTEGER DEFAULT 4,
                logo_id VARCHAR(36),
                logo_position VARCHAR(20) DEFAULT 'center' CHECK (logo_position IN ('center', 'top', 'bottom')),
                custom_css TEXT,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE,
                FOREIGN KEY (background_image_id) REFERENCES media_assets(id) ON DELETE SET NULL,
                FOREIGN KEY (logo_id) REFERENCES media_assets(id) ON DELETE SET NULL,
                UNIQUE(realm_id, page_type)
            )
            """,
            "Created 'realm_page_customizations' table"
        ))
        
        migrations.append((
            "CREATE INDEX ix_realm_page_customizations_realm_id ON realm_page_customizations(realm_id)",
            "Created index on realm_page_customizations.realm_id"
        ))
    
    # ==========================================================================
    # Execute migrations
    # ==========================================================================
    if not migrations:
        print("Database is up to date. No migrations needed.")
        conn.close()
        return True
    
    print(f"\nRunning {len(migrations)} migration(s)...\n")
    
    success_count = 0
    error_count = 0
    
    for sql, description in migrations:
        try:
            cursor.execute(sql)
            conn.commit()
            print(f"  [OK] {description}")
            success_count += 1
        except sqlite3.Error as e:
            print(f"  [FAIL] {description}")
            print(f"    Error: {e}")
            error_count += 1
    
    conn.close()
    
    print(f"\nMigration complete: {success_count} successful, {error_count} failed")
    
    return error_count == 0


def seed_roles_scope():
    """Seed the 'roles' client scope with mappers for all realms"""
    print("\nSeeding 'roles' client scope...")
    
    try:
        from apps import create_app, db
        from apps.config import DebugConfig
        from apps.models.realm import Realm
        from apps.models.client import ClientScope, ProtocolMapper, Client
        
        app = create_app(DebugConfig)
        with app.app_context():
            realms = Realm.query.all()
            
            for realm in realms:
                # Check if 'roles' scope exists
                roles_scope = ClientScope.query.filter_by(realm_id=realm.id, name='roles').first()
                
                if not roles_scope:
                    # Create roles scope
                    roles_scope = ClientScope(
                        realm_id=realm.id,
                        name='roles',
                        description='OpenID Connect scope for role mappings',
                        protocol='openid-connect'
                    )
                    db.session.add(roles_scope)
                    db.session.commit()
                    print(f"  [OK] Created 'roles' scope for realm: {realm.name}")
                else:
                    print(f"  [OK] 'roles' scope already exists for realm: {realm.name}")
                
                # Check/create realm roles mapper
                realm_role_mapper = ProtocolMapper.query.filter_by(
                    client_scope_id=roles_scope.id,
                    protocol_mapper='oidc-usermodel-realm-role-mapper'
                ).first()
                
                if not realm_role_mapper:
                    realm_role_mapper = ProtocolMapper(
                        name='realm roles',
                        protocol='openid-connect',
                        protocol_mapper='oidc-usermodel-realm-role-mapper',
                        client_scope_id=roles_scope.id,
                        config={
                            'claim.name': 'realm_access.roles',
                            'multivalued': 'true',
                            'access.token.claim': 'true',
                            'id.token.claim': 'true',
                            'userinfo.token.claim': 'false',
                        },
                        priority=0
                    )
                    db.session.add(realm_role_mapper)
                    db.session.commit()
                    print(f"    [OK] Created 'realm roles' mapper for scope")
                
                # Add roles scope as default to all clients in this realm
                clients = Client.query.filter_by(realm_id=realm.id).all()
                for client in clients:
                    default_scopes = client.default_client_scopes or []
                    if roles_scope.id not in default_scopes:
                        default_scopes.append(roles_scope.id)
                        client.default_client_scopes = default_scopes
                        print(f"    [OK] Added 'roles' scope to client: {client.client_id}")
                
                db.session.commit()
            
            print("\n[OK] Roles scope seeding completed!")
            return True
            
    except Exception as e:
        print(f"\n[ERROR] Failed to seed roles scope: {e}")
        return False


if __name__ == '__main__':
    print("=" * 60)
    print("RijanAuth Database Migration")
    print("=" * 60)
    print()
    
    success = run_migration()
    
    if success:
        print("\n[OK] Database migration completed successfully!")
        
        # Also seed roles scope
        seed_roles_scope()
        
        print("\nYou can now restart the application.")
    else:
        print("\n[ERROR] Some migrations failed. Please check the errors above.")
    
    sys.exit(0 if success else 1)
