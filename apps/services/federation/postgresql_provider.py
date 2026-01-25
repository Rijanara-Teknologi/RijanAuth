# -*- encoding: utf-8 -*-
"""
RijanAuth - PostgreSQL Federation Provider
Provides user authentication and synchronization against PostgreSQL databases
"""

from typing import Optional, Dict, Any, List, Tuple, Generator
from datetime import datetime
import hashlib
import json
import logging

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

from apps.services.federation.base import (
    BaseFederationProvider,
    ConnectionError,
    AuthenticationError,
    ConfigurationError
)

logger = logging.getLogger(__name__)


class PostgreSQLFederationProvider(BaseFederationProvider):
    """
    PostgreSQL Federation Provider.
    
    Supports:
    - PostgreSQL 10+
    - JSONB column support for flexible attributes
    - Array type support for group memberships
    - Multiple password hash algorithms
    - SSL mode options (disable, prefer, require, verify-ca, verify-full)
    - Connection pooling
    """
    
    PROVIDER_TYPE = 'postgresql'
    
    DEFAULT_CONFIG = {
        # Connection settings
        'host': 'localhost',
        'port': 5432,
        'database': '',
        'username': '',
        'password': '',
        'connect_timeout': 10,
        'sslmode': 'prefer',  # disable, allow, prefer, require, verify-ca, verify-full
        'sslrootcert': '',
        'sslcert': '',
        'sslkey': '',
        
        # Table settings
        'user_table': 'users',
        'schema': 'public',
        'id_column': 'id',
        'username_column': 'username',
        'email_column': 'email',
        'password_column': 'password',
        'first_name_column': 'first_name',
        'last_name_column': 'last_name',
        'enabled_column': 'enabled',
        'created_at_column': 'created_at',
        'updated_at_column': 'updated_at',
        
        # PostgreSQL-specific: JSONB attributes column
        'attributes_column': '',  # JSONB column for additional attributes
        
        # PostgreSQL-specific: Array column for groups
        'groups_column': '',  # Array column for group memberships
        
        # Password settings
        'password_hash_algorithm': 'bcrypt',  # bcrypt, sha256, sha512, md5, plaintext
        'salt_column': '',
        'salt_position': 'prefix',
        
        # Account status mapping
        'enabled_true_value': 'true',  # Can be 'true', 't', '1', etc.
        'enabled_false_value': 'false',
        
        # Search settings
        'search_filter': '',  # Additional WHERE clause
        
        # Sync settings
        'batch_size': 100,
        
        # Additional columns (comma-separated)
        'attribute_columns': '',
    }
    
    REQUIRED_CONFIG_KEYS = ['host', 'database', 'user_table']
    
    SENSITIVE_CONFIG_KEYS = ['password']
    
    def __init__(self, provider_id: str, realm_id: str, config: Dict[str, Any]):
        if not PSYCOPG2_AVAILABLE:
            raise ConfigurationError("psycopg2 library is not installed. Run: pip install psycopg2-binary")
        super().__init__(provider_id, realm_id, config)
        self._connection = None
    
    # ==================== Connection Management ====================
    
    def connect(self) -> bool:
        """Establish connection to PostgreSQL server"""
        try:
            conn_params = {
                'host': self.config.get('host', 'localhost'),
                'port': int(self.config.get('port', 5432)),
                'dbname': self.config.get('database', ''),
                'user': self.config.get('username', ''),
                'password': self.config.get('password', ''),
                'connect_timeout': int(self.config.get('connect_timeout', 10)),
                'sslmode': self.config.get('sslmode', 'prefer'),
            }
            
            # SSL options
            if self.config.get('sslrootcert'):
                conn_params['sslrootcert'] = self.config['sslrootcert']
            if self.config.get('sslcert'):
                conn_params['sslcert'] = self.config['sslcert']
            if self.config.get('sslkey'):
                conn_params['sslkey'] = self.config['sslkey']
            
            self._connection = psycopg2.connect(**conn_params)
            self._connection.autocommit = True
            
            logger.info(f"Connected to PostgreSQL: {conn_params['host']}:{conn_params['port']}/{conn_params['dbname']}")
            return True
            
        except psycopg2.Error as e:
            raise ConnectionError(f"Failed to connect to PostgreSQL: {str(e)}")
    
    def disconnect(self):
        """Close PostgreSQL connection"""
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
            logger.debug("Disconnected from PostgreSQL")
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test connectivity to PostgreSQL server"""
        try:
            self.connect()
            
            # Verify table exists
            schema = self.config.get('schema', 'public')
            table = self.config.get('user_table', 'users')
            
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema = %s AND table_name = %s",
                    (schema, table)
                )
                if not cursor.fetchone():
                    return False, f"Table {schema}.{table} does not exist"
            
            self.disconnect()
            return True, f"Successfully connected to PostgreSQL database: {self.config['database']}"
            
        except ConnectionError as e:
            return False, str(e)
        except psycopg2.Error as e:
            return False, f"PostgreSQL error: {str(e)}"
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
        finally:
            self.disconnect()
    
    def _ensure_connected(self):
        """Ensure connection is established"""
        if not self._connection or self._connection.closed:
            self.connect()
    
    # ==================== Query Building ====================
    
    def _get_qualified_table(self) -> str:
        """Get fully qualified table name"""
        schema = self.config.get('schema', 'public')
        table = self.config.get('user_table', 'users')
        return f'"{schema}"."{table}"'
    
    def _get_select_columns(self) -> List[str]:
        """Get list of columns to select"""
        columns = [
            self.config.get('id_column', 'id'),
            self.config.get('username_column', 'username'),
            self.config.get('email_column', 'email'),
            self.config.get('password_column', 'password'),
        ]
        
        # Optional columns
        for col_key in ['first_name_column', 'last_name_column', 'enabled_column',
                       'created_at_column', 'updated_at_column', 'salt_column',
                       'attributes_column', 'groups_column']:
            col = self.config.get(col_key, '')
            if col:
                columns.append(col)
        
        # Additional attribute columns
        attr_cols = self.config.get('attribute_columns', '')
        if attr_cols:
            columns.extend([c.strip() for c in attr_cols.split(',') if c.strip()])
        
        return [c for c in columns if c]
    
    def _build_base_query(self) -> str:
        """Build base SELECT query"""
        table = self._get_qualified_table()
        columns = self._get_select_columns()
        
        # Quote column names
        quoted_cols = [f'"{c}"' for c in columns]
        
        return f"SELECT {', '.join(quoted_cols)} FROM {table}"
    
    def _parse_row(self, row: Dict) -> Dict[str, Any]:
        """Parse database row to user dict"""
        id_col = self.config.get('id_column', 'id')
        username_col = self.config.get('username_column', 'username')
        email_col = self.config.get('email_column', 'email')
        first_name_col = self.config.get('first_name_column', '')
        last_name_col = self.config.get('last_name_column', '')
        enabled_col = self.config.get('enabled_column', '')
        attributes_col = self.config.get('attributes_column', '')
        groups_col = self.config.get('groups_column', '')
        
        # Determine enabled status
        enabled = True
        if enabled_col and enabled_col in row:
            val = row[enabled_col]
            if isinstance(val, bool):
                enabled = val
            else:
                enabled_true = self.config.get('enabled_true_value', 'true').lower()
                enabled = str(val).lower() in [enabled_true, 'true', 't', '1', 'yes']
        
        # Build attributes from JSONB column and/or extra columns
        attributes = {}
        
        # Parse JSONB attributes column
        if attributes_col and attributes_col in row and row[attributes_col]:
            jsonb_attrs = row[attributes_col]
            if isinstance(jsonb_attrs, str):
                try:
                    jsonb_attrs = json.loads(jsonb_attrs)
                except json.JSONDecodeError:
                    jsonb_attrs = {}
            if isinstance(jsonb_attrs, dict):
                attributes.update(jsonb_attrs)
        
        # Add extra columns
        attr_cols = self.config.get('attribute_columns', '')
        if attr_cols:
            for col in attr_cols.split(','):
                col = col.strip()
                if col and col in row:
                    attributes[col] = row[col]
        
        # Parse groups array column
        groups = []
        if groups_col and groups_col in row and row[groups_col]:
            groups_val = row[groups_col]
            if isinstance(groups_val, list):
                groups = groups_val
            elif isinstance(groups_val, str):
                # Handle PostgreSQL array format: {val1,val2}
                if groups_val.startswith('{') and groups_val.endswith('}'):
                    groups = [g.strip() for g in groups_val[1:-1].split(',') if g.strip()]
        
        return {
            'external_id': str(row.get(id_col, '')),
            'username': row.get(username_col, ''),
            'email': row.get(email_col, ''),
            'first_name': row.get(first_name_col, '') if first_name_col else '',
            'last_name': row.get(last_name_col, '') if last_name_col else '',
            'enabled': enabled,
            'attributes': attributes,
            'groups': groups,
            '_password_hash': row.get(self.config.get('password_column', 'password'), ''),
            '_salt': row.get(self.config.get('salt_column', ''), '') if self.config.get('salt_column') else '',
        }
    
    # ==================== User Lookup ====================
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        self._ensure_connected()
        
        username_col = self.config.get('username_column', 'username')
        query = self._build_base_query() + f' WHERE "{username_col}" = %s'
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" AND ({search_filter})"
        
        query += " LIMIT 1"
        
        try:
            with self._connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (username,))
                row = cursor.fetchone()
                
                if row:
                    return self._parse_row(dict(row))
                return None
                
        except psycopg2.Error as e:
            logger.error(f"PostgreSQL query failed: {str(e)}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        self._ensure_connected()
        
        email_col = self.config.get('email_column', 'email')
        query = self._build_base_query() + f' WHERE "{email_col}" = %s'
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" AND ({search_filter})"
        
        query += " LIMIT 1"
        
        try:
            with self._connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (email,))
                row = cursor.fetchone()
                
                if row:
                    return self._parse_row(dict(row))
                return None
                
        except psycopg2.Error as e:
            logger.error(f"PostgreSQL query failed: {str(e)}")
            return None
    
    def get_user_by_id(self, external_id: str) -> Optional[Dict[str, Any]]:
        """Get user by external ID"""
        self._ensure_connected()
        
        id_col = self.config.get('id_column', 'id')
        query = self._build_base_query() + f' WHERE "{id_col}" = %s LIMIT 1'
        
        try:
            with self._connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (external_id,))
                row = cursor.fetchone()
                
                if row:
                    return self._parse_row(dict(row))
                return None
                
        except psycopg2.Error as e:
            logger.error(f"PostgreSQL query failed: {str(e)}")
            return None
    
    # ==================== Authentication ====================
    
    def _hash_password(self, password: str, salt: str = '') -> str:
        """Hash password using configured algorithm"""
        algorithm = self.config.get('password_hash_algorithm', 'bcrypt').lower()
        salt_position = self.config.get('salt_position', 'prefix')
        
        # Apply salt
        if salt:
            if salt_position == 'prefix':
                salted = salt + password
            elif salt_position == 'suffix':
                salted = password + salt
            else:
                salted = password
        else:
            salted = password
        
        if algorithm == 'bcrypt':
            return password
        elif algorithm == 'sha256':
            return hashlib.sha256(salted.encode('utf-8')).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(salted.encode('utf-8')).hexdigest()
        elif algorithm == 'md5':
            return hashlib.md5(salted.encode('utf-8')).hexdigest()
        elif algorithm == 'plaintext':
            return salted
        else:
            raise ConfigurationError(f"Unknown password hash algorithm: {algorithm}")
    
    def validate_credentials(self, external_user: Dict[str, Any], password: str) -> bool:
        """Validate password against stored hash"""
        if not password:
            return False
        
        stored_hash = external_user.get('_password_hash', '')
        stored_salt = external_user.get('_salt', '')
        
        if not stored_hash:
            return False
        
        algorithm = self.config.get('password_hash_algorithm', 'bcrypt').lower()
        
        try:
            if algorithm == 'bcrypt':
                if not BCRYPT_AVAILABLE:
                    raise ConfigurationError("bcrypt library not installed")
                
                if isinstance(stored_hash, str):
                    stored_hash = stored_hash.encode('utf-8')
                
                return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
            
            elif algorithm == 'plaintext':
                return password == stored_hash
            
            else:
                computed_hash = self._hash_password(password, stored_salt)
                return computed_hash.lower() == stored_hash.lower()
                
        except Exception as e:
            logger.error(f"Password validation error: {str(e)}")
            return False
    
    # ==================== User Synchronization ====================
    
    def get_all_users(self, batch_size: int = 100) -> Generator[Dict[str, Any], None, None]:
        """Retrieve all users from PostgreSQL"""
        self._ensure_connected()
        
        batch_size = self.config.get('batch_size', batch_size)
        query = self._build_base_query()
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" WHERE {search_filter}"
        
        id_col = self.config.get('id_column', 'id')
        query += f' ORDER BY "{id_col}"'
        
        offset = 0
        
        try:
            while True:
                paginated_query = query + f" LIMIT {batch_size} OFFSET {offset}"
                
                with self._connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute(paginated_query)
                    rows = cursor.fetchall()
                    
                    if not rows:
                        break
                    
                    for row in rows:
                        yield self._parse_row(dict(row))
                    
                    if len(rows) < batch_size:
                        break
                    
                    offset += batch_size
                    
        except psycopg2.Error as e:
            logger.error(f"PostgreSQL sync query failed: {str(e)}")
            raise
    
    def get_changed_users(self, since: datetime) -> Generator[Dict[str, Any], None, None]:
        """Get users changed since timestamp"""
        updated_col = self.config.get('updated_at_column', '')
        
        if not updated_col:
            return iter([])
        
        self._ensure_connected()
        
        query = self._build_base_query()
        query += f' WHERE "{updated_col}" >= %s'
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" AND ({search_filter})"
        
        query += f' ORDER BY "{updated_col}"'
        
        try:
            with self._connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (since,))
                
                for row in cursor.fetchall():
                    yield self._parse_row(dict(row))
                    
        except psycopg2.Error as e:
            logger.error(f"PostgreSQL changed users query failed: {str(e)}")
            raise
    
    def supports_changed_sync(self) -> bool:
        """Check if provider supports change tracking"""
        return bool(self.config.get('updated_at_column', ''))
    
    def get_user_count(self) -> int:
        """Get total user count"""
        self._ensure_connected()
        
        table = self._get_qualified_table()
        query = f"SELECT COUNT(*) as count FROM {table}"
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" WHERE {search_filter}"
        
        try:
            with self._connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query)
                result = cursor.fetchone()
                return result['count'] if result else 0
        except psycopg2.Error:
            return -1
    
    # ==================== Group Support ====================
    
    def get_user_groups(self, external_user: Dict[str, Any]) -> List[str]:
        """Get group memberships from array column"""
        return external_user.get('groups', [])
    
    # ==================== Configuration Schema ====================
    
    @classmethod
    def get_config_schema(cls) -> Dict[str, Any]:
        """Get JSON schema for PostgreSQL configuration"""
        return {
            'type': 'object',
            'required': ['host', 'database', 'user_table'],
            'properties': {
                'host': {
                    'type': 'string',
                    'title': 'Host',
                    'default': 'localhost'
                },
                'port': {
                    'type': 'integer',
                    'title': 'Port',
                    'default': 5432
                },
                'database': {
                    'type': 'string',
                    'title': 'Database Name'
                },
                'username': {
                    'type': 'string',
                    'title': 'Username'
                },
                'password': {
                    'type': 'string',
                    'title': 'Password',
                    'format': 'password'
                },
                'schema': {
                    'type': 'string',
                    'title': 'Schema',
                    'default': 'public'
                },
                'user_table': {
                    'type': 'string',
                    'title': 'User Table',
                    'default': 'users'
                },
                'username_column': {
                    'type': 'string',
                    'title': 'Username Column',
                    'default': 'username'
                },
                'email_column': {
                    'type': 'string',
                    'title': 'Email Column',
                    'default': 'email'
                },
                'password_column': {
                    'type': 'string',
                    'title': 'Password Column',
                    'default': 'password'
                },
                'password_hash_algorithm': {
                    'type': 'string',
                    'title': 'Password Hash Algorithm',
                    'enum': ['bcrypt', 'sha256', 'sha512', 'md5', 'plaintext'],
                    'default': 'bcrypt'
                },
                'attributes_column': {
                    'type': 'string',
                    'title': 'JSONB Attributes Column',
                    'description': 'Column containing JSONB user attributes'
                },
                'groups_column': {
                    'type': 'string',
                    'title': 'Groups Array Column',
                    'description': 'Array column containing group memberships'
                },
                'sslmode': {
                    'type': 'string',
                    'title': 'SSL Mode',
                    'enum': ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'],
                    'default': 'prefer'
                }
            }
        }
    
    @classmethod
    def get_default_mappers(cls) -> List[Dict[str, Any]]:
        """Get default attribute mappers for PostgreSQL"""
        return [
            {
                'name': 'username',
                'mapper_type': 'user-attribute-db-mapper',
                'internal_attribute': 'username',
                'external_attribute': 'username',
                'config': {'read_only': True}
            },
            {
                'name': 'email',
                'mapper_type': 'user-attribute-db-mapper',
                'internal_attribute': 'email',
                'external_attribute': 'email',
                'config': {'read_only': True}
            },
            {
                'name': 'firstName',
                'mapper_type': 'user-attribute-db-mapper',
                'internal_attribute': 'first_name',
                'external_attribute': 'first_name',
                'config': {'read_only': True}
            },
            {
                'name': 'lastName',
                'mapper_type': 'user-attribute-db-mapper',
                'internal_attribute': 'last_name',
                'external_attribute': 'last_name',
                'config': {'read_only': True}
            },
        ]
