# -*- encoding: utf-8 -*-
"""
RijanAuth - Base Federation Provider
Abstract base class for all user federation providers
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple, Generator
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class FederationError(Exception):
    """Base exception for federation errors"""
    pass


class ConnectionError(FederationError):
    """Connection to external source failed"""
    pass


class AuthenticationError(FederationError):
    """Authentication against external source failed"""
    pass


class ConfigurationError(FederationError):
    """Invalid provider configuration"""
    pass


class BaseFederationProvider(ABC):
    """
    Abstract base class for User Federation Providers.
    
    All federation providers (LDAP, MySQL, PostgreSQL) must implement this interface
    to enable consistent integration with RijanAuth authentication flow.
    
    Attributes:
        provider_id (str): Unique identifier of the provider configuration
        realm_id (str): Realm this provider belongs to
        config (dict): Provider-specific configuration
    """
    
    # Provider type identifier (override in subclasses)
    PROVIDER_TYPE = 'base'
    
    # Default configuration (override in subclasses)
    DEFAULT_CONFIG = {}
    
    # Required configuration keys (override in subclasses)
    REQUIRED_CONFIG_KEYS = []
    
    # Sensitive configuration keys that should be encrypted (override in subclasses)
    SENSITIVE_CONFIG_KEYS = []
    
    def __init__(self, provider_id: str, realm_id: str, config: Dict[str, Any]):
        """
        Initialize the federation provider.
        
        Args:
            provider_id: Unique identifier for this provider instance
            realm_id: Realm this provider belongs to
            config: Provider-specific configuration dictionary
        """
        self.provider_id = provider_id
        self.realm_id = realm_id
        self.config = {**self.DEFAULT_CONFIG, **config}
        self._connection = None
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate that all required configuration keys are present"""
        missing_keys = [key for key in self.REQUIRED_CONFIG_KEYS if key not in self.config]
        if missing_keys:
            raise ConfigurationError(f"Missing required configuration keys: {', '.join(missing_keys)}")
    
    # ==================== Connection Management ====================
    
    @abstractmethod
    def connect(self) -> bool:
        """
        Establish connection to the external identity source.
        
        Returns:
            bool: True if connection successful
            
        Raises:
            ConnectionError: If connection fails
        """
        pass
    
    @abstractmethod
    def disconnect(self):
        """Close connection to external source"""
        pass
    
    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test connectivity to the external source.
        
        Returns:
            Tuple[bool, str]: (success, message)
            - success: True if connection test passed
            - message: Descriptive message about connection status
        """
        pass
    
    def is_connected(self) -> bool:
        """Check if currently connected to external source"""
        return self._connection is not None
    
    # ==================== User Lookup ====================
    
    @abstractmethod
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user by username from external source.
        
        Args:
            username: Username to search for
            
        Returns:
            Dict with user data or None if not found
            Standard fields:
            - external_id: Unique ID in external system
            - username: Username
            - email: Email address
            - first_name: First name
            - last_name: Last name
            - enabled: Account status
            - attributes: Additional attributes dict
        """
        pass
    
    @abstractmethod
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user by email from external source.
        
        Args:
            email: Email address to search for
            
        Returns:
            Dict with user data or None if not found
        """
        pass
    
    def get_user_by_id(self, external_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user by their external ID.
        
        Args:
            external_id: Unique identifier in external system
            
        Returns:
            Dict with user data or None if not found
        """
        # Default implementation - subclasses should override for efficiency
        return None
    
    # ==================== Authentication ====================
    
    @abstractmethod
    def validate_credentials(self, external_user: Dict[str, Any], password: str) -> bool:
        """
        Validate user credentials against external source.
        
        Args:
            external_user: User data dict from get_user_by_*
            password: Password to validate
            
        Returns:
            bool: True if credentials are valid
            
        Raises:
            AuthenticationError: If authentication fails due to external error
        """
        pass
    
    # ==================== User Synchronization ====================
    
    @abstractmethod
    def get_all_users(self, batch_size: int = 100) -> Generator[Dict[str, Any], None, None]:
        """
        Retrieve all users from external source for full synchronization.
        
        Args:
            batch_size: Number of users to fetch per batch
            
        Yields:
            Dict with user data for each user
        """
        pass
    
    def get_changed_users(self, since: datetime) -> Generator[Dict[str, Any], None, None]:
        """
        Retrieve users modified since given timestamp.
        
        This is optional - providers that don't support change tracking
        should return an empty generator.
        
        Args:
            since: Timestamp to check changes from
            
        Yields:
            Dict with user data for each changed user
        """
        # Default: Not supported - full sync will be used instead
        return iter([])
    
    def get_user_count(self) -> int:
        """
        Get total number of users in external source.
        
        Returns:
            int: Total user count, or -1 if not supported
        """
        return -1
    
    def supports_changed_sync(self) -> bool:
        """
        Check if provider supports incremental/changed user sync.
        
        Returns:
            bool: True if get_changed_users is implemented
        """
        return False
    
    # ==================== Attribute Mapping ====================
    
    def map_user_attributes(self, external_user: Dict[str, Any], 
                           mappers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Apply attribute mappers to convert external user to internal format.
        
        Args:
            external_user: Raw user data from external source
            mappers: List of mapper configurations
            
        Returns:
            Dict with mapped user attributes
        """
        mapped = {
            'external_id': external_user.get('external_id'),
            'username': external_user.get('username'),
            'email': external_user.get('email'),
            'first_name': external_user.get('first_name'),
            'last_name': external_user.get('last_name'),
            'enabled': external_user.get('enabled', True),
            'attributes': {},
        }
        
        for mapper in mappers:
            mapper_type = mapper.get('mapper_type')
            internal_attr = mapper.get('internal_attribute')
            external_attr = mapper.get('external_attribute')
            config = mapper.get('config', {})
            
            if mapper_type == 'user-attribute-ldap-mapper' or mapper_type == 'user-attribute-db-mapper':
                if external_attr and external_attr in external_user:
                    value = external_user[external_attr]
                    if internal_attr in ['username', 'email', 'first_name', 'last_name', 'enabled']:
                        mapped[internal_attr] = value
                    else:
                        mapped['attributes'][internal_attr] = value
                        
            elif mapper_type == 'hardcoded-attribute-mapper':
                value = config.get('attribute_value')
                if internal_attr and value is not None:
                    if internal_attr in ['username', 'email', 'first_name', 'last_name', 'enabled']:
                        mapped[internal_attr] = value
                    else:
                        mapped['attributes'][internal_attr] = value
        
        return mapped
    
    # ==================== Group/Role Mapping ====================
    
    def get_user_groups(self, external_user: Dict[str, Any]) -> List[str]:
        """
        Get group memberships for user from external source.
        
        Args:
            external_user: User data from external source
            
        Returns:
            List of group names/paths
        """
        return external_user.get('groups', [])
    
    def get_user_roles(self, external_user: Dict[str, Any]) -> List[str]:
        """
        Get role assignments for user from external source.
        
        Args:
            external_user: User data from external source
            
        Returns:
            List of role names
        """
        return external_user.get('roles', [])
    
    # ==================== Context Manager ====================
    
    def __enter__(self):
        """Support context manager usage"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure connection is closed"""
        self.disconnect()
        return False
    
    # ==================== Utility Methods ====================
    
    @classmethod
    def get_config_schema(cls) -> Dict[str, Any]:
        """
        Get JSON schema for provider configuration.
        Override in subclasses to provide detailed schema.
        
        Returns:
            Dict describing configuration options
        """
        return {
            'type': 'object',
            'required': cls.REQUIRED_CONFIG_KEYS,
            'properties': {}
        }
    
    @classmethod
    def get_default_mappers(cls) -> List[Dict[str, Any]]:
        """
        Get default attribute mappers for this provider type.
        Override in subclasses.
        
        Returns:
            List of default mapper configurations
        """
        return []
