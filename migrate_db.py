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


if __name__ == '__main__':
    print("=" * 60)
    print("RijanAuth Database Migration")
    print("=" * 60)
    print()
    
    success = run_migration()
    
    if success:
        print("\n[OK] All migrations completed successfully!")
        print("\nYou can now restart the application.")
    else:
        print("\n[ERROR] Some migrations failed. Please check the errors above.")
    
    sys.exit(0 if success else 1)
