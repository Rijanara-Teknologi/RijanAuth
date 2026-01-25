# -*- encoding: utf-8 -*-
"""
RijanAuth - MySQL/MariaDB Federation Provider
Provides user authentication and synchronization against MySQL/MariaDB databases
"""

from typing import Optional, Dict, Any, List, Tuple, Generator
from datetime import datetime
import hashlib
import logging

try:
    import pymysql
    from pymysql.cursors import DictCursor
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

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


class MySQLFederationProvider(BaseFederationProvider):
    """
    MySQL/MariaDB Federation Provider.
    
    Supports:
    - MySQL 5.7+ and MariaDB 10.3+
    - Configurable table and column mappings
    - Multiple password hash algorithms (bcrypt, sha256, sha512, md5, plaintext)
    - Salt handling (prefix, suffix, separate column)
    - Connection pooling
    - SSL/TLS connections
    """
    
    PROVIDER_TYPE = 'mysql'
    
    DEFAULT_CONFIG = {
        # Connection settings
        'host': 'localhost',
        'port': 3306,
        'database': '',
        'username': '',
        'password': '',
        'charset': 'utf8mb4',
        'connect_timeout': 10,
        'read_timeout': 30,
        'use_ssl': False,
        'ssl_ca': '',
        'ssl_cert': '',
        'ssl_key': '',
        
        # Table settings
        'user_table': 'users',
        'id_column': 'id',
        'username_column': 'username',
        'email_column': 'email',
        'password_column': 'password',
        'first_name_column': 'first_name',
        'last_name_column': 'last_name',
        'enabled_column': 'enabled',
        'created_at_column': 'created_at',
        'updated_at_column': 'updated_at',
        
        # Password settings
        'password_hash_algorithm': 'bcrypt',  # bcrypt, sha256, sha512, md5, plaintext
        'salt_column': '',  # Empty = no separate salt column
        'salt_position': 'prefix',  # prefix, suffix, none
        'password_encoding': 'utf-8',
        
        # Account status mapping
        'enabled_true_value': '1',  # Value that means enabled
        'enabled_false_value': '0',  # Value that means disabled
        
        # Search settings
        'search_filter': '',  # Additional WHERE clause (e.g., "status = 'active'")
        
        # Sync settings
        'batch_size': 100,
        
        # Additional attribute columns (comma-separated)
        'attribute_columns': '',  # e.g., 'phone,department,title'
        
        # Role mapping settings
        'role_sync_enabled': False,  # Enable role synchronization
        'role_source': 'column',  # 'column' (in user table) or 'table' (separate table)
        'role_column': 'roles',  # Column name if role_source is 'column'
        'role_table': '',  # Separate table for roles
        'role_user_id_column': 'user_id',  # User ID column in role table
        'role_name_column': 'role_name',  # Role name column in role table
        'role_delimiter': ',',  # Delimiter for string-based roles in column
        'create_missing_roles': False,  # Auto-create unmapped roles
        'default_role_if_empty': '',  # Default role if no roles found
    }
    
    REQUIRED_CONFIG_KEYS = ['host', 'database', 'user_table']
    
    SENSITIVE_CONFIG_KEYS = ['password']
    
    def __init__(self, provider_id: str, realm_id: str, config: Dict[str, Any]):
        if not PYMYSQL_AVAILABLE:
            raise ConfigurationError("pymysql library is not installed. Run: pip install pymysql")
        super().__init__(provider_id, realm_id, config)
        self._connection = None
    
    # ==================== Connection Management ====================
    
    def connect(self) -> bool:
        """Establish connection to MySQL server"""
        try:
            ssl_config = None
            if self.config.get('use_ssl', False):
                ssl_config = {
                    'ca': self.config.get('ssl_ca') or None,
                    'cert': self.config.get('ssl_cert') or None,
                    'key': self.config.get('ssl_key') or None,
                }
            
            self._connection = pymysql.connect(
                host=self.config.get('host', 'localhost'),
                port=int(self.config.get('port', 3306)),
                user=self.config.get('username', ''),
                password=self.config.get('password', ''),
                database=self.config.get('database', ''),
                charset=self.config.get('charset', 'utf8mb4'),
                connect_timeout=int(self.config.get('connect_timeout', 10)),
                read_timeout=int(self.config.get('read_timeout', 30)),
                cursorclass=DictCursor,
                ssl=ssl_config
            )
            
            logger.info(f"Connected to MySQL: {self.config['host']}:{self.config.get('port', 3306)}/{self.config['database']}")
            return True
            
        except pymysql.Error as e:
            raise ConnectionError(f"Failed to connect to MySQL: {str(e)}")
    
    def disconnect(self):
        """Close MySQL connection"""
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
            logger.debug("Disconnected from MySQL")
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test connectivity to MySQL server"""
        try:
            self.connect()
            
            # Verify table exists
            with self._connection.cursor() as cursor:
                table = self.config.get('user_table', 'users')
                cursor.execute(f"SELECT 1 FROM `{table}` LIMIT 1")
            
            self.disconnect()
            return True, f"Successfully connected to MySQL database: {self.config['database']}"
            
        except ConnectionError as e:
            return False, str(e)
        except pymysql.Error as e:
            return False, f"MySQL error: {str(e)}"
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
        finally:
            self.disconnect()
    
    def _ensure_connected(self):
        """Ensure connection is established"""
        if not self._connection or not self._connection.open:
            self.connect()
    
    # ==================== Query Building ====================
    
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
                       'created_at_column', 'updated_at_column', 'salt_column']:
            col = self.config.get(col_key, '')
            if col:
                columns.append(col)
        
        # Additional attribute columns
        attr_cols = self.config.get('attribute_columns', '')
        if attr_cols:
            columns.extend([c.strip() for c in attr_cols.split(',') if c.strip()])
        
        # Role column if role_source is 'column'
        if self.config.get('role_sync_enabled', False) and self.config.get('role_source') == 'column':
            role_col = self.config.get('role_column', 'roles')
            if role_col and role_col not in columns:
                columns.append(role_col)
        
        return [c for c in columns if c]
    
    def _build_base_query(self) -> str:
        """Build base SELECT query"""
        table = self.config.get('user_table', 'users')
        columns = self._get_select_columns()
        
        # Quote column names
        quoted_cols = [f"`{c}`" for c in columns]
        
        return f"SELECT {', '.join(quoted_cols)} FROM `{table}`"
    
    def _parse_row(self, row: Dict, include_roles: bool = True) -> Dict[str, Any]:
        """Parse database row to user dict"""
        id_col = self.config.get('id_column', 'id')
        username_col = self.config.get('username_column', 'username')
        email_col = self.config.get('email_column', 'email')
        first_name_col = self.config.get('first_name_column', '')
        last_name_col = self.config.get('last_name_column', '')
        enabled_col = self.config.get('enabled_column', '')
        
        # Determine enabled status
        enabled = True
        if enabled_col and enabled_col in row:
            enabled_true = self.config.get('enabled_true_value', '1')
            enabled = str(row[enabled_col]) == str(enabled_true)
        
        # Build attributes from extra columns
        attributes = {}
        attr_cols = self.config.get('attribute_columns', '')
        if attr_cols:
            for col in attr_cols.split(','):
                col = col.strip()
                if col and col in row:
                    attributes[col] = row[col]
        
        external_id = str(row.get(id_col, ''))
        
        # Get roles if enabled
        roles = []
        if include_roles and self.config.get('role_sync_enabled', False):
            roles = self._get_user_roles(external_id, row)
        
        return {
            'external_id': external_id,
            'username': row.get(username_col, ''),
            'email': row.get(email_col, ''),
            'first_name': row.get(first_name_col, '') if first_name_col else '',
            'last_name': row.get(last_name_col, '') if last_name_col else '',
            'enabled': enabled,
            'attributes': attributes,
            'roles': roles,
            '_password_hash': row.get(self.config.get('password_column', 'password'), ''),
            '_salt': row.get(self.config.get('salt_column', ''), '') if self.config.get('salt_column') else '',
        }
    
    def _get_user_roles(self, external_id: str, row: Dict = None) -> List[str]:
        """Get roles for a user from MySQL database"""
        role_source = self.config.get('role_source', 'column')
        
        if role_source == 'column':
            return self._get_roles_from_column(row)
        elif role_source == 'table':
            return self._get_roles_from_table(external_id)
        
        return []
    
    def _get_roles_from_column(self, row: Dict) -> List[str]:
        """Get roles from a column in the user table"""
        if not row:
            return []
        
        role_column = self.config.get('role_column', 'roles')
        role_data = row.get(role_column)
        
        if not role_data:
            return []
        
        # Handle different data types
        if isinstance(role_data, str):
            delimiter = self.config.get('role_delimiter', ',')
            return [r.strip() for r in role_data.split(delimiter) if r.strip()]
        elif isinstance(role_data, (list, tuple)):
            return [str(r).strip() for r in role_data if str(r).strip()]
        
        return []
    
    def _get_roles_from_table(self, external_id: str) -> List[str]:
        """Get roles from a separate role table"""
        role_table = self.config.get('role_table', '')
        if not role_table:
            return []
        
        self._ensure_connected()
        
        user_id_col = self.config.get('role_user_id_column', 'user_id')
        role_name_col = self.config.get('role_name_column', 'role_name')
        
        query = f"SELECT `{role_name_col}` FROM `{role_table}` WHERE `{user_id_col}` = %s"
        
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(query, (external_id,))
                rows = cursor.fetchall()
                return [row[role_name_col] for row in rows if row.get(role_name_col)]
        except pymysql.Error as e:
            logger.error(f"Failed to fetch roles from table: {e}")
            return []
    
    def get_user_roles_by_id(self, external_id: str) -> List[str]:
        """Get roles for a user by external ID (public method)"""
        if not self.config.get('role_sync_enabled', False):
            return []
        
        role_source = self.config.get('role_source', 'column')
        
        if role_source == 'table':
            return self._get_roles_from_table(external_id)
        elif role_source == 'column':
            # Need to fetch the user row first
            user = self.get_user_by_id(external_id)
            if user:
                return user.get('roles', [])
        
        return []
    
    # ==================== User Lookup ====================
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        self._ensure_connected()
        
        username_col = self.config.get('username_column', 'username')
        query = self._build_base_query() + f" WHERE `{username_col}` = %s"
        
        # Add custom filter
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" AND ({search_filter})"
        
        query += " LIMIT 1"
        
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(query, (username,))
                row = cursor.fetchone()
                
                if row:
                    return self._parse_row(row)
                return None
                
        except pymysql.Error as e:
            logger.error(f"MySQL query failed: {str(e)}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        self._ensure_connected()
        
        email_col = self.config.get('email_column', 'email')
        query = self._build_base_query() + f" WHERE `{email_col}` = %s"
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" AND ({search_filter})"
        
        query += " LIMIT 1"
        
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(query, (email,))
                row = cursor.fetchone()
                
                if row:
                    return self._parse_row(row)
                return None
                
        except pymysql.Error as e:
            logger.error(f"MySQL query failed: {str(e)}")
            return None
    
    def get_user_by_id(self, external_id: str) -> Optional[Dict[str, Any]]:
        """Get user by external ID"""
        self._ensure_connected()
        
        id_col = self.config.get('id_column', 'id')
        query = self._build_base_query() + f" WHERE `{id_col}` = %s LIMIT 1"
        
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(query, (external_id,))
                row = cursor.fetchone()
                
                if row:
                    return self._parse_row(row)
                return None
                
        except pymysql.Error as e:
            logger.error(f"MySQL query failed: {str(e)}")
            return None
    
    # ==================== Authentication ====================
    
    def _hash_password(self, password: str, salt: str = '') -> str:
        """Hash password using configured algorithm"""
        algorithm = self.config.get('password_hash_algorithm', 'bcrypt').lower()
        encoding = self.config.get('password_encoding', 'utf-8')
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
            # bcrypt doesn't use separate salt - it's embedded in the hash
            # We just return the password to compare with bcrypt.checkpw
            return password
        elif algorithm == 'sha256':
            return hashlib.sha256(salted.encode(encoding)).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(salted.encode(encoding)).hexdigest()
        elif algorithm == 'md5':
            return hashlib.md5(salted.encode(encoding)).hexdigest()
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
                
                # Ensure stored_hash is bytes
                if isinstance(stored_hash, str):
                    stored_hash = stored_hash.encode('utf-8')
                
                return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
            
            elif algorithm == 'plaintext':
                return password == stored_hash
            
            else:
                # Hash the password and compare
                computed_hash = self._hash_password(password, stored_salt)
                return computed_hash.lower() == stored_hash.lower()
                
        except Exception as e:
            logger.error(f"Password validation error: {str(e)}")
            return False
    
    # ==================== User Synchronization ====================
    
    def get_all_users(self, batch_size: int = 100) -> Generator[Dict[str, Any], None, None]:
        """Retrieve all users from MySQL"""
        self._ensure_connected()
        
        batch_size = self.config.get('batch_size', batch_size)
        query = self._build_base_query()
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" WHERE {search_filter}"
        
        id_col = self.config.get('id_column', 'id')
        query += f" ORDER BY `{id_col}`"
        
        offset = 0
        
        try:
            while True:
                paginated_query = query + f" LIMIT {batch_size} OFFSET {offset}"
                
                with self._connection.cursor() as cursor:
                    cursor.execute(paginated_query)
                    rows = cursor.fetchall()
                    
                    if not rows:
                        break
                    
                    for row in rows:
                        yield self._parse_row(row)
                    
                    if len(rows) < batch_size:
                        break
                    
                    offset += batch_size
                    
        except pymysql.Error as e:
            logger.error(f"MySQL sync query failed: {str(e)}")
            raise
    
    def get_changed_users(self, since: datetime) -> Generator[Dict[str, Any], None, None]:
        """Get users changed since timestamp"""
        updated_col = self.config.get('updated_at_column', '')
        
        if not updated_col:
            return iter([])
        
        self._ensure_connected()
        
        query = self._build_base_query()
        query += f" WHERE `{updated_col}` >= %s"
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" AND ({search_filter})"
        
        query += f" ORDER BY `{updated_col}`"
        
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(query, (since,))
                
                for row in cursor.fetchall():
                    yield self._parse_row(row)
                    
        except pymysql.Error as e:
            logger.error(f"MySQL changed users query failed: {str(e)}")
            raise
    
    def supports_changed_sync(self) -> bool:
        """Check if provider supports change tracking"""
        return bool(self.config.get('updated_at_column', ''))
    
    def get_user_count(self) -> int:
        """Get total user count"""
        self._ensure_connected()
        
        table = self.config.get('user_table', 'users')
        query = f"SELECT COUNT(*) as count FROM `{table}`"
        
        search_filter = self.config.get('search_filter', '')
        if search_filter:
            query += f" WHERE {search_filter}"
        
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(query)
                result = cursor.fetchone()
                return result['count'] if result else 0
        except pymysql.Error:
            return -1
    
    # ==================== Configuration Schema ====================
    
    @classmethod
    def get_config_schema(cls) -> Dict[str, Any]:
        """Get JSON schema for MySQL configuration"""
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
                    'default': 3306
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
                }
            }
        }
    
    @classmethod
    def get_default_mappers(cls) -> List[Dict[str, Any]]:
        """Get default attribute mappers for MySQL"""
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
