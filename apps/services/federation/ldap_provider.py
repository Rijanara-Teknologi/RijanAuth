# -*- encoding: utf-8 -*-
"""
RijanAuth - LDAP/Active Directory Federation Provider
Provides user authentication and synchronization against LDAP/AD servers
"""

from typing import Optional, Dict, Any, List, Tuple, Generator
from datetime import datetime
import logging

try:
    from ldap3 import Server, Connection, ALL, SUBTREE, LEVEL, BASE, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
    from ldap3.utils.conv import escape_filter_chars
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False

from apps.services.federation.base import (
    BaseFederationProvider, 
    ConnectionError, 
    AuthenticationError, 
    ConfigurationError
)

logger = logging.getLogger(__name__)


class LDAPFederationProvider(BaseFederationProvider):
    """
    LDAP/Active Directory Federation Provider.
    
    Supports:
    - LDAP and LDAPS connections
    - Active Directory specific schemas
    - Subtree/one-level/object searches
    - Connection pooling
    - User authentication via bind
    - Group membership synchronization
    """
    
    PROVIDER_TYPE = 'ldap'
    
    DEFAULT_CONFIG = {
        # Connection settings
        'connection_url': 'ldap://localhost:389',
        'bind_dn': '',
        'bind_credential': '',
        'use_ssl': False,
        'use_starttls': False,
        'connection_timeout': 30,
        'response_timeout': 30,
        
        # Search settings
        'users_dn': '',  # Base DN for user searches
        'user_object_classes': ['inetOrgPerson', 'organizationalPerson', 'person'],
        'search_scope': 'subtree',  # 'base', 'one', 'subtree'
        'username_ldap_attribute': 'uid',
        'rdn_ldap_attribute': 'uid',
        'uuid_ldap_attribute': 'entryUUID',
        'user_search_filter': '',  # Additional filter, e.g., (objectClass=person)
        
        # Attribute mappings
        'email_ldap_attribute': 'mail',
        'first_name_ldap_attribute': 'givenName',
        'last_name_ldap_attribute': 'sn',
        'full_name_ldap_attribute': 'cn',
        
        # Authentication
        'auth_type': 'simple',  # 'simple', 'none'
        'custom_user_search_filter': '',  # Filter with {0} placeholder for username
        
        # Sync settings
        'batch_size': 100,
        'pagination': True,
        'read_timeout': 0,  # 0 = no timeout
        
        # Active Directory specific
        'vendor': 'other',  # 'other', 'ad', 'rhds', 'tivoli'
        'trust_email': False,
        
        # Group settings
        'groups_dn': '',
        'group_name_ldap_attribute': 'cn',
        'group_object_classes': ['groupOfNames', 'groupOfUniqueNames', 'group'],
        'membership_ldap_attribute': 'member',
        'membership_user_ldap_attribute': 'dn',
        'mode': 'READ_ONLY',  # 'READ_ONLY', 'LDAP_ONLY', 'IMPORT'
    }
    
    REQUIRED_CONFIG_KEYS = ['connection_url', 'users_dn']
    
    SENSITIVE_CONFIG_KEYS = ['bind_credential']
    
    # Search scope mapping
    SEARCH_SCOPES = {
        'base': BASE,
        'one': LEVEL,
        'subtree': SUBTREE,
    }
    
    def __init__(self, provider_id: str, realm_id: str, config: Dict[str, Any]):
        if not LDAP3_AVAILABLE:
            raise ConfigurationError("ldap3 library is not installed. Run: pip install ldap3")
        super().__init__(provider_id, realm_id, config)
        self._server = None
        self._connection = None
    
    # ==================== Connection Management ====================
    
    def connect(self) -> bool:
        """Establish connection to LDAP server"""
        try:
            # Parse connection URL
            url = self.config['connection_url']
            use_ssl = self.config.get('use_ssl', False) or url.startswith('ldaps://')
            
            # Create server
            self._server = Server(
                url,
                use_ssl=use_ssl,
                get_info=ALL,
                connect_timeout=self.config.get('connection_timeout', 30)
            )
            
            # Determine auto_bind mode
            auto_bind = AUTO_BIND_NO_TLS
            if self.config.get('use_starttls', False):
                auto_bind = AUTO_BIND_TLS_BEFORE_BIND
            
            # Create connection
            bind_dn = self.config.get('bind_dn', '')
            bind_credential = self.config.get('bind_credential', '')
            
            if bind_dn:
                self._connection = Connection(
                    self._server,
                    user=bind_dn,
                    password=bind_credential,
                    auto_bind=auto_bind,
                    read_only=True,
                    receive_timeout=self.config.get('response_timeout', 30)
                )
            else:
                # Anonymous bind
                self._connection = Connection(
                    self._server,
                    auto_bind=auto_bind,
                    read_only=True,
                    receive_timeout=self.config.get('response_timeout', 30)
                )
            
            logger.info(f"Connected to LDAP server: {url}")
            return True
            
        except LDAPSocketOpenError as e:
            raise ConnectionError(f"Failed to connect to LDAP server: {str(e)}")
        except LDAPBindError as e:
            raise ConnectionError(f"LDAP bind failed: {str(e)}")
        except LDAPException as e:
            raise ConnectionError(f"LDAP error: {str(e)}")
    
    def disconnect(self):
        """Close LDAP connection"""
        if self._connection:
            try:
                self._connection.unbind()
            except Exception:
                pass
            self._connection = None
            self._server = None
            logger.debug("Disconnected from LDAP server")
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test connectivity to LDAP server"""
        try:
            self.connect()
            
            # Try a simple search to verify read access
            users_dn = self.config.get('users_dn', '')
            if users_dn:
                self._connection.search(
                    search_base=users_dn,
                    search_filter='(objectClass=*)',
                    search_scope=BASE,
                    attributes=['objectClass'],
                    size_limit=1
                )
            
            self.disconnect()
            return True, f"Successfully connected to {self.config['connection_url']}"
            
        except ConnectionError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
        finally:
            self.disconnect()
    
    # ==================== User Lookup ====================
    
    def _build_user_filter(self, attribute: str, value: str) -> str:
        """Build LDAP filter for user search"""
        escaped_value = escape_filter_chars(value)
        
        # Object class filter
        object_classes = self.config.get('user_object_classes', ['inetOrgPerson'])
        if len(object_classes) == 1:
            class_filter = f"(objectClass={object_classes[0]})"
        else:
            class_filter = "(|" + "".join(f"(objectClass={oc})" for oc in object_classes) + ")"
        
        # Attribute filter
        attr_filter = f"({attribute}={escaped_value})"
        
        # Additional user filter
        user_filter = self.config.get('user_search_filter', '')
        
        # Combine filters
        if user_filter:
            return f"(&{class_filter}{attr_filter}{user_filter})"
        return f"(&{class_filter}{attr_filter})"
    
    def _get_search_scope(self) -> int:
        """Get LDAP search scope from config"""
        scope = self.config.get('search_scope', 'subtree').lower()
        return self.SEARCH_SCOPES.get(scope, SUBTREE)
    
    def _get_user_attributes(self) -> List[str]:
        """Get list of attributes to retrieve for users"""
        attrs = [
            self.config.get('username_ldap_attribute', 'uid'),
            self.config.get('uuid_ldap_attribute', 'entryUUID'),
            self.config.get('email_ldap_attribute', 'mail'),
            self.config.get('first_name_ldap_attribute', 'givenName'),
            self.config.get('last_name_ldap_attribute', 'sn'),
            self.config.get('full_name_ldap_attribute', 'cn'),
            'userAccountControl',  # AD account status
            'nsAccountLock',  # RHDS account status
        ]
        return [a for a in attrs if a]
    
    def _parse_user_entry(self, entry) -> Dict[str, Any]:
        """Parse LDAP entry to user dict"""
        attrs = entry.entry_attributes_as_dict
        
        # Get UUID
        uuid_attr = self.config.get('uuid_ldap_attribute', 'entryUUID')
        external_id = str(entry.entry_dn)  # Use DN as fallback
        if uuid_attr in attrs and attrs[uuid_attr]:
            external_id = str(attrs[uuid_attr][0])
        
        # Get username
        username_attr = self.config.get('username_ldap_attribute', 'uid')
        username = attrs.get(username_attr, [''])[0] if username_attr in attrs else ''
        
        # Get email
        email_attr = self.config.get('email_ldap_attribute', 'mail')
        email = attrs.get(email_attr, [''])[0] if email_attr in attrs else ''
        
        # Get names
        first_name_attr = self.config.get('first_name_ldap_attribute', 'givenName')
        last_name_attr = self.config.get('last_name_ldap_attribute', 'sn')
        full_name_attr = self.config.get('full_name_ldap_attribute', 'cn')
        
        first_name = attrs.get(first_name_attr, [''])[0] if first_name_attr in attrs else ''
        last_name = attrs.get(last_name_attr, [''])[0] if last_name_attr in attrs else ''
        full_name = attrs.get(full_name_attr, [''])[0] if full_name_attr in attrs else ''
        
        # Determine account status
        enabled = True
        
        # Check AD userAccountControl (bit 2 = ACCOUNTDISABLE)
        if 'userAccountControl' in attrs:
            try:
                uac = int(attrs['userAccountControl'][0])
                enabled = not (uac & 2)  # Bit 2 = disabled
            except (ValueError, IndexError):
                pass
        
        # Check RHDS nsAccountLock
        if 'nsAccountLock' in attrs:
            enabled = str(attrs['nsAccountLock'][0]).lower() != 'true'
        
        return {
            'external_id': external_id,
            'dn': str(entry.entry_dn),
            'username': username,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'full_name': full_name,
            'enabled': enabled,
            'attributes': {k: v[0] if len(v) == 1 else v for k, v in attrs.items()},
        }
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        if not self._connection:
            self.connect()
        
        username_attr = self.config.get('username_ldap_attribute', 'uid')
        search_filter = self._build_user_filter(username_attr, username)
        
        try:
            self._connection.search(
                search_base=self.config['users_dn'],
                search_filter=search_filter,
                search_scope=self._get_search_scope(),
                attributes=self._get_user_attributes(),
                size_limit=1
            )
            
            if self._connection.entries:
                return self._parse_user_entry(self._connection.entries[0])
            return None
            
        except LDAPException as e:
            logger.error(f"LDAP search failed: {str(e)}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        if not self._connection:
            self.connect()
        
        email_attr = self.config.get('email_ldap_attribute', 'mail')
        search_filter = self._build_user_filter(email_attr, email)
        
        try:
            self._connection.search(
                search_base=self.config['users_dn'],
                search_filter=search_filter,
                search_scope=self._get_search_scope(),
                attributes=self._get_user_attributes(),
                size_limit=1
            )
            
            if self._connection.entries:
                return self._parse_user_entry(self._connection.entries[0])
            return None
            
        except LDAPException as e:
            logger.error(f"LDAP search failed: {str(e)}")
            return None
    
    def get_user_by_id(self, external_id: str) -> Optional[Dict[str, Any]]:
        """Get user by external ID (DN or UUID)"""
        if not self._connection:
            self.connect()
        
        try:
            # Try searching by UUID first
            uuid_attr = self.config.get('uuid_ldap_attribute', 'entryUUID')
            search_filter = self._build_user_filter(uuid_attr, external_id)
            
            self._connection.search(
                search_base=self.config['users_dn'],
                search_filter=search_filter,
                search_scope=self._get_search_scope(),
                attributes=self._get_user_attributes(),
                size_limit=1
            )
            
            if self._connection.entries:
                return self._parse_user_entry(self._connection.entries[0])
            
            # Try as DN if it looks like one
            if '=' in external_id:
                self._connection.search(
                    search_base=external_id,
                    search_filter='(objectClass=*)',
                    search_scope=BASE,
                    attributes=self._get_user_attributes()
                )
                
                if self._connection.entries:
                    return self._parse_user_entry(self._connection.entries[0])
            
            return None
            
        except LDAPException as e:
            logger.error(f"LDAP search by ID failed: {str(e)}")
            return None
    
    # ==================== Authentication ====================
    
    def validate_credentials(self, external_user: Dict[str, Any], password: str) -> bool:
        """Validate credentials by attempting LDAP bind"""
        if not password:
            return False
        
        user_dn = external_user.get('dn')
        if not user_dn:
            logger.warning("No DN available for user authentication")
            return False
        
        try:
            # Create new connection for bind test
            url = self.config['connection_url']
            use_ssl = self.config.get('use_ssl', False) or url.startswith('ldaps://')
            
            server = Server(url, use_ssl=use_ssl, connect_timeout=10)
            
            # Determine auto_bind mode
            auto_bind = AUTO_BIND_NO_TLS
            if self.config.get('use_starttls', False):
                auto_bind = AUTO_BIND_TLS_BEFORE_BIND
            
            # Try to bind as user
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=auto_bind,
                receive_timeout=10
            )
            
            # If we get here, bind succeeded
            conn.unbind()
            logger.debug(f"LDAP authentication successful for: {user_dn}")
            return True
            
        except LDAPBindError:
            logger.debug(f"LDAP authentication failed for: {user_dn}")
            return False
        except LDAPException as e:
            logger.error(f"LDAP authentication error: {str(e)}")
            raise AuthenticationError(f"LDAP authentication error: {str(e)}")
    
    # ==================== User Synchronization ====================
    
    def get_all_users(self, batch_size: int = 100) -> Generator[Dict[str, Any], None, None]:
        """Retrieve all users from LDAP"""
        if not self._connection:
            self.connect()
        
        batch_size = self.config.get('batch_size', batch_size)
        
        # Build filter for all users
        object_classes = self.config.get('user_object_classes', ['inetOrgPerson'])
        if len(object_classes) == 1:
            class_filter = f"(objectClass={object_classes[0]})"
        else:
            class_filter = "(|" + "".join(f"(objectClass={oc})" for oc in object_classes) + ")"
        
        user_filter = self.config.get('user_search_filter', '')
        if user_filter:
            search_filter = f"(&{class_filter}{user_filter})"
        else:
            search_filter = class_filter
        
        try:
            # Use paged search if pagination is enabled
            if self.config.get('pagination', True):
                entry_generator = self._connection.extend.standard.paged_search(
                    search_base=self.config['users_dn'],
                    search_filter=search_filter,
                    search_scope=self._get_search_scope(),
                    attributes=self._get_user_attributes(),
                    paged_size=batch_size,
                    generator=True
                )
                
                for entry in entry_generator:
                    if entry.get('type') == 'searchResEntry':
                        # Convert to Entry-like object
                        yield self._parse_paged_entry(entry)
            else:
                # Simple search without pagination
                self._connection.search(
                    search_base=self.config['users_dn'],
                    search_filter=search_filter,
                    search_scope=self._get_search_scope(),
                    attributes=self._get_user_attributes()
                )
                
                for entry in self._connection.entries:
                    yield self._parse_user_entry(entry)
                    
        except LDAPException as e:
            logger.error(f"LDAP sync search failed: {str(e)}")
            raise
    
    def _parse_paged_entry(self, entry: Dict) -> Dict[str, Any]:
        """Parse paged search result entry"""
        attrs = entry.get('attributes', {})
        dn = entry.get('dn', '')
        
        # Get UUID
        uuid_attr = self.config.get('uuid_ldap_attribute', 'entryUUID')
        external_id = dn  # Use DN as fallback
        if uuid_attr in attrs and attrs[uuid_attr]:
            val = attrs[uuid_attr]
            external_id = str(val[0] if isinstance(val, list) else val)
        
        # Get values helper
        def get_val(attr_key):
            if attr_key in attrs:
                val = attrs[attr_key]
                if isinstance(val, list):
                    return val[0] if val else ''
                return val
            return ''
        
        username_attr = self.config.get('username_ldap_attribute', 'uid')
        email_attr = self.config.get('email_ldap_attribute', 'mail')
        first_name_attr = self.config.get('first_name_ldap_attribute', 'givenName')
        last_name_attr = self.config.get('last_name_ldap_attribute', 'sn')
        full_name_attr = self.config.get('full_name_ldap_attribute', 'cn')
        
        # Determine account status
        enabled = True
        if 'userAccountControl' in attrs:
            try:
                uac = int(get_val('userAccountControl'))
                enabled = not (uac & 2)
            except (ValueError, TypeError):
                pass
        if 'nsAccountLock' in attrs:
            enabled = str(get_val('nsAccountLock')).lower() != 'true'
        
        return {
            'external_id': external_id,
            'dn': dn,
            'username': get_val(username_attr),
            'email': get_val(email_attr),
            'first_name': get_val(first_name_attr),
            'last_name': get_val(last_name_attr),
            'full_name': get_val(full_name_attr),
            'enabled': enabled,
            'attributes': attrs,
        }
    
    def get_user_count(self) -> int:
        """Get total number of users"""
        if not self._connection:
            self.connect()
        
        object_classes = self.config.get('user_object_classes', ['inetOrgPerson'])
        if len(object_classes) == 1:
            class_filter = f"(objectClass={object_classes[0]})"
        else:
            class_filter = "(|" + "".join(f"(objectClass={oc})" for oc in object_classes) + ")"
        
        user_filter = self.config.get('user_search_filter', '')
        if user_filter:
            search_filter = f"(&{class_filter}{user_filter})"
        else:
            search_filter = class_filter
        
        try:
            self._connection.search(
                search_base=self.config['users_dn'],
                search_filter=search_filter,
                search_scope=self._get_search_scope(),
                attributes=['1.1'],  # No attributes, just count
            )
            return len(self._connection.entries)
        except LDAPException:
            return -1
    
    # ==================== Configuration Schema ====================
    
    @classmethod
    def get_config_schema(cls) -> Dict[str, Any]:
        """Get JSON schema for LDAP configuration"""
        return {
            'type': 'object',
            'required': ['connection_url', 'users_dn'],
            'properties': {
                'connection_url': {
                    'type': 'string',
                    'title': 'Connection URL',
                    'description': 'LDAP server URL (e.g., ldap://localhost:389 or ldaps://localhost:636)'
                },
                'bind_dn': {
                    'type': 'string',
                    'title': 'Bind DN',
                    'description': 'DN for binding to LDAP (e.g., cn=admin,dc=example,dc=com)'
                },
                'bind_credential': {
                    'type': 'string',
                    'title': 'Bind Credential',
                    'description': 'Password for bind DN',
                    'format': 'password'
                },
                'users_dn': {
                    'type': 'string',
                    'title': 'Users DN',
                    'description': 'Base DN for user searches (e.g., ou=users,dc=example,dc=com)'
                },
                'username_ldap_attribute': {
                    'type': 'string',
                    'title': 'Username Attribute',
                    'default': 'uid'
                },
                'email_ldap_attribute': {
                    'type': 'string',
                    'title': 'Email Attribute',
                    'default': 'mail'
                },
                'search_scope': {
                    'type': 'string',
                    'title': 'Search Scope',
                    'enum': ['base', 'one', 'subtree'],
                    'default': 'subtree'
                },
                'vendor': {
                    'type': 'string',
                    'title': 'Vendor',
                    'enum': ['other', 'ad', 'rhds', 'tivoli'],
                    'default': 'other'
                }
            }
        }
    
    @classmethod
    def get_default_mappers(cls) -> List[Dict[str, Any]]:
        """Get default attribute mappers for LDAP"""
        return [
            {
                'name': 'username',
                'mapper_type': 'user-attribute-ldap-mapper',
                'internal_attribute': 'username',
                'external_attribute': 'uid',
                'config': {'read_only': True}
            },
            {
                'name': 'email',
                'mapper_type': 'user-attribute-ldap-mapper',
                'internal_attribute': 'email',
                'external_attribute': 'mail',
                'config': {'read_only': True}
            },
            {
                'name': 'firstName',
                'mapper_type': 'user-attribute-ldap-mapper',
                'internal_attribute': 'first_name',
                'external_attribute': 'givenName',
                'config': {'read_only': True}
            },
            {
                'name': 'lastName',
                'mapper_type': 'user-attribute-ldap-mapper',
                'internal_attribute': 'last_name',
                'external_attribute': 'sn',
                'config': {'read_only': True}
            },
        ]
