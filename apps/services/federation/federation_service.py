# -*- encoding: utf-8 -*-
"""
RijanAuth - Federation Service
Orchestrates user federation providers and integrates with authentication flow
"""

from typing import Optional, Dict, Any, List, Type
from datetime import datetime
import logging

from apps import db
from apps.models.federation import (
    UserFederationProvider, 
    UserFederationMapper, 
    UserFederationLink
)
from apps.models.user import User, UserAttribute
from apps.services.federation.base import BaseFederationProvider, FederationError
from apps.services.user_service import UserService
from apps.utils.crypto import encrypt_data, decrypt_data

logger = logging.getLogger(__name__)

# Lazy import for RoleSyncService to avoid circular imports
_role_sync_service = None

def _get_role_sync_service():
    """Get RoleSyncService lazily to avoid circular imports"""
    global _role_sync_service
    if _role_sync_service is None:
        from apps.services.federation.role_sync_service import RoleSyncService
        _role_sync_service = RoleSyncService
    return _role_sync_service


class FederationService:
    """
    Main service for user federation operations.
    
    Provides:
    - Provider instance creation and management
    - Federated user authentication
    - User import and linking
    - Provider configuration management
    """
    
    # Provider type to class mapping
    _provider_classes: Dict[str, Type[BaseFederationProvider]] = {}
    
    @classmethod
    def register_provider(cls, provider_type: str, provider_class: Type[BaseFederationProvider]):
        """Register a federation provider class"""
        cls._provider_classes[provider_type] = provider_class
        logger.info(f"Registered federation provider: {provider_type}")
    
    @classmethod
    def get_provider_class(cls, provider_type: str) -> Optional[Type[BaseFederationProvider]]:
        """Get provider class by type"""
        return cls._provider_classes.get(provider_type)
    
    @classmethod
    def get_available_providers(cls) -> List[str]:
        """Get list of available provider types"""
        return list(cls._provider_classes.keys())
    
    # ==================== Provider Instance Management ====================
    
    @classmethod
    def create_provider_instance(cls, provider: UserFederationProvider) -> BaseFederationProvider:
        """
        Create a provider instance from database configuration.
        
        Args:
            provider: UserFederationProvider model instance
            
        Returns:
            Configured provider instance
            
        Raises:
            FederationError: If provider type is not registered or configuration is invalid
        """
        provider_class = cls.get_provider_class(provider.provider_type)
        if not provider_class:
            raise FederationError(f"Unknown provider type: {provider.provider_type}")
        
        # Decrypt sensitive config fields
        config = cls._decrypt_config(provider.config, provider.provider_type)
        
        return provider_class(
            provider_id=provider.id,
            realm_id=provider.realm_id,
            config=config
        )
    
    @classmethod
    def _decrypt_config(cls, config: Dict[str, Any], provider_type: str) -> Dict[str, Any]:
        """Decrypt sensitive configuration fields"""
        provider_class = cls.get_provider_class(provider_type)
        if not provider_class:
            return config
        
        decrypted = config.copy()
        for key in provider_class.SENSITIVE_CONFIG_KEYS:
            if key in decrypted and decrypted[key]:
                try:
                    decrypted[key] = decrypt_data(decrypted[key])
                except Exception:
                    # If decryption fails, assume it's not encrypted
                    pass
        
        return decrypted
    
    @classmethod
    def _encrypt_config(cls, config: Dict[str, Any], provider_type: str) -> Dict[str, Any]:
        """Encrypt sensitive configuration fields"""
        provider_class = cls.get_provider_class(provider_type)
        if not provider_class:
            return config
        
        encrypted = config.copy()
        for key in provider_class.SENSITIVE_CONFIG_KEYS:
            if key in encrypted and encrypted[key]:
                encrypted[key] = encrypt_data(encrypted[key])
        
        return encrypted
    
    # ==================== Federated Authentication ====================
    
    @classmethod
    def authenticate_federated(cls, realm_id: str, username: str, password: str) -> Optional[User]:
        """
        Authenticate user against federation providers.
        
        This is called after local authentication fails.
        Tries each enabled provider in priority order.
        
        Args:
            realm_id: Realm to authenticate in
            username: Username or email
            password: Password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        providers = UserFederationProvider.get_enabled_providers(realm_id)
        
        if not providers:
            logger.debug(f"No federation providers configured for realm {realm_id}")
            return None
        
        for provider_config in providers:
            try:
                logger.debug(f"Trying federation provider: {provider_config.name}")
                
                # Create provider instance
                provider = cls.create_provider_instance(provider_config)
                
                with provider:
                    # Search for user
                    external_user = provider.get_user_by_username(username)
                    if not external_user:
                        # Try by email
                        external_user = provider.get_user_by_email(username)
                    
                    if not external_user:
                        logger.debug(f"User {username} not found in {provider_config.name}")
                        continue
                    
                    # Validate credentials
                    if not provider.validate_credentials(external_user, password):
                        logger.debug(f"Invalid credentials for {username} in {provider_config.name}")
                        continue
                    
                    # Check if user is enabled in external source
                    if not external_user.get('enabled', True):
                        logger.debug(f"User {username} is disabled in {provider_config.name}")
                        continue
                    
                    # Import is enabled - create/update local user
                    if provider_config.import_enabled:
                        user = cls.import_federated_user(
                            realm_id=realm_id,
                            provider_id=provider_config.id,
                            external_user=external_user,
                            provider_instance=provider
                        )
                        
                        if user:
                            logger.info(f"Federated authentication successful: {username} via {provider_config.name}")
                            return user
                    
            except FederationError as e:
                logger.error(f"Federation provider {provider_config.name} error: {str(e)}")
                continue
            except Exception as e:
                logger.exception(f"Unexpected error with provider {provider_config.name}: {str(e)}")
                continue
        
        return None
    
    # ==================== User Import/Link ====================
    
    @classmethod
    def import_federated_user(cls, realm_id: str, provider_id: str, 
                             external_user: Dict[str, Any],
                             provider_instance: Optional[BaseFederationProvider] = None,
                             sync_roles: bool = True) -> Optional[User]:
        """
        Import or update a federated user.
        
        Creates local user reference if not exists, or updates existing.
        Links user to federation provider.
        Optionally synchronizes roles from external source.
        
        Args:
            realm_id: Realm ID
            provider_id: Federation provider ID
            external_user: User data from external source
            provider_instance: Optional provider instance for attribute mapping
            sync_roles: Whether to synchronize roles from external source
            
        Returns:
            User object or None on failure
        """
        external_id = external_user.get('external_id')
        if not external_id:
            logger.error("External user has no external_id")
            return None
        
        # Get provider config for role sync check
        provider_config = UserFederationProvider.find_by_id(provider_id)
        
        # Check if user is already linked
        link = UserFederationLink.find_by_external_id(provider_id, external_id)
        
        if link:
            # Update existing user
            user = User.find_by_id(link.user_id)
            if user:
                cls._update_user_from_external(user, external_user, provider_instance)
                link.last_sync = datetime.utcnow()
                link.external_username = external_user.get('username', '')
                link.external_email = external_user.get('email', '')
                db.session.commit()
                
                # Synchronize roles if enabled
                if sync_roles and provider_config:
                    cls._sync_user_roles(user, provider_config, external_user, realm_id)
                
                return user
        
        # Check if user exists locally by username or email
        username = external_user.get('username', '')
        email = external_user.get('email', '')
        
        user = None
        if username:
            user = User.find_by_username(realm_id, username)
        if not user and email:
            user = User.find_by_email(realm_id, email)
        
        if user:
            # Link existing local user to federation
            cls._create_federation_link(user, provider_id, external_user)
            cls._update_user_from_external(user, external_user, provider_instance)
            
            # Synchronize roles if enabled
            if sync_roles and provider_config:
                cls._sync_user_roles(user, provider_config, external_user, realm_id)
            
            return user
        
        # Create new local user
        user = cls._create_federated_user(realm_id, external_user, provider_instance)
        if user:
            cls._create_federation_link(user, provider_id, external_user)
            
            # Synchronize roles if enabled
            if sync_roles and provider_config:
                cls._sync_user_roles(user, provider_config, external_user, realm_id)
            
            return user
        
        return None
    
    @classmethod
    def _sync_user_roles(cls, user: User, provider: UserFederationProvider, 
                        external_user: Dict[str, Any], realm_id: str):
        """
        Synchronize roles from external source to internal RijanAuth roles.
        
        Args:
            user: The local user object
            provider: The federation provider
            external_user: User data from external source
            realm_id: The realm ID
        """
        # Check if role sync is enabled for this provider
        config = provider.config or {}
        if not config.get('role_sync_enabled', False):
            logger.debug(f"Role sync not enabled for provider {provider.name}")
            return
        
        try:
            RoleSyncService = _get_role_sync_service()
            result = RoleSyncService.synchronize_user_roles(
                user=user,
                provider=provider,
                external_user=external_user,
                realm_id=realm_id,
                sync_type='login'
            )
            
            if result.get('success'):
                logger.info(f"Role sync completed for user {user.username}: "
                           f"added={len(result.get('added', []))}, "
                           f"removed={len(result.get('removed', []))}")
            else:
                logger.warning(f"Role sync failed for user {user.username}: {result.get('error')}")
                
        except Exception as e:
            logger.error(f"Error during role synchronization for user {user.username}: {e}", exc_info=True)
    
    @classmethod
    def _create_federated_user(cls, realm_id: str, external_user: Dict[str, Any],
                               provider_instance: Optional[BaseFederationProvider] = None) -> Optional[User]:
        """Create a new local user from external data"""
        try:
            # Apply attribute mapping if provider instance available
            if provider_instance:
                provider_config = UserFederationProvider.find_by_id(provider_instance.provider_id)
                if provider_config:
                    mappers = [m.to_dict() for m in provider_config.mappers.all()]
                    external_user = provider_instance.map_user_attributes(external_user, mappers)
            
            username = external_user.get('username', '')
            email = external_user.get('email', '')
            
            if not username:
                logger.error("Cannot create federated user without username")
                return None
            
            # Create user without password (federated)
            user = UserService.create_user(
                realm_id=realm_id,
                username=username,
                email=email or None,
                enabled=external_user.get('enabled', True),
                email_verified=True,  # Trust email from federation
                password=None,  # No local password
                first_name=external_user.get('first_name', ''),
                last_name=external_user.get('last_name', ''),
            )
            
            # Set federation link marker
            user.federation_link = 'federated'
            db.session.commit()
            
            # Set additional attributes
            attributes = external_user.get('attributes', {})
            if attributes:
                UserService.set_attributes(user.id, attributes)
            
            logger.info(f"Created federated user: {username}")
            return user
            
        except Exception as e:
            logger.error(f"Failed to create federated user: {str(e)}")
            db.session.rollback()
            return None
    
    @classmethod
    def _update_user_from_external(cls, user: User, external_user: Dict[str, Any],
                                   provider_instance: Optional[BaseFederationProvider] = None):
        """Update local user from external data"""
        try:
            # Apply attribute mapping if provider instance available
            if provider_instance:
                provider_config = UserFederationProvider.find_by_id(provider_instance.provider_id)
                if provider_config:
                    mappers = [m.to_dict() for m in provider_config.mappers.all()]
                    external_user = provider_instance.map_user_attributes(external_user, mappers)
            
            # Update basic fields
            if external_user.get('email'):
                user.email = external_user['email']
            if external_user.get('first_name'):
                user.first_name = external_user['first_name']
            if external_user.get('last_name'):
                user.last_name = external_user['last_name']
            
            user.enabled = external_user.get('enabled', True)
            user.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            # Update attributes
            attributes = external_user.get('attributes', {})
            if attributes:
                UserService.set_attributes(user.id, attributes)
                
        except Exception as e:
            logger.error(f"Failed to update user from external: {str(e)}")
            db.session.rollback()
    
    @classmethod
    def _create_federation_link(cls, user: User, provider_id: str, external_user: Dict[str, Any]):
        """Create federation link between local user and external identity"""
        try:
            link = UserFederationLink(
                user_id=user.id,
                provider_id=provider_id,
                external_id=external_user.get('external_id', ''),
                external_username=external_user.get('username', ''),
                external_email=external_user.get('email', ''),
                last_sync=datetime.utcnow(),
                storage_mode='FEDERATED'
            )
            db.session.add(link)
            db.session.commit()
            logger.debug(f"Created federation link for user {user.username}")
        except Exception as e:
            logger.error(f"Failed to create federation link: {str(e)}")
            db.session.rollback()
    
    # ==================== Provider CRUD ====================
    
    @classmethod
    def create_provider(cls, realm_id: str, name: str, provider_type: str,
                       config: Dict[str, Any], **kwargs) -> UserFederationProvider:
        """
        Create a new federation provider.
        
        Args:
            realm_id: Realm ID
            name: Provider name (unique within realm)
            provider_type: Provider type (ldap, mysql, postgresql)
            config: Provider configuration
            **kwargs: Additional provider settings
            
        Returns:
            Created UserFederationProvider
        """
        # Validate provider type
        if provider_type not in cls._provider_classes:
            raise FederationError(f"Unknown provider type: {provider_type}")
        
        # Encrypt sensitive fields
        encrypted_config = cls._encrypt_config(config, provider_type)
        
        provider = UserFederationProvider(
            realm_id=realm_id,
            name=name,
            display_name=kwargs.get('display_name', name),
            provider_type=provider_type,
            config=encrypted_config,
            enabled=kwargs.get('enabled', True),
            priority=kwargs.get('priority', 0),
            import_enabled=kwargs.get('import_enabled', True),
            sync_registrations=kwargs.get('sync_registrations', False),
            full_sync_period=kwargs.get('full_sync_period', -1),
            changed_sync_period=kwargs.get('changed_sync_period', -1),
        )
        
        db.session.add(provider)
        db.session.commit()
        
        # Create default mappers
        cls._create_default_mappers(provider)
        
        logger.info(f"Created federation provider: {name} ({provider_type})")
        return provider
    
    @classmethod
    def _create_default_mappers(cls, provider: UserFederationProvider):
        """Create default attribute mappers for a provider"""
        provider_class = cls.get_provider_class(provider.provider_type)
        if not provider_class:
            return
        
        default_mappers = provider_class.get_default_mappers()
        
        for mapper_config in default_mappers:
            mapper = UserFederationMapper(
                provider_id=provider.id,
                name=mapper_config['name'],
                mapper_type=mapper_config['mapper_type'],
                internal_attribute=mapper_config.get('internal_attribute'),
                external_attribute=mapper_config.get('external_attribute'),
                config=mapper_config.get('config', {})
            )
            db.session.add(mapper)
        
        db.session.commit()
    
    @classmethod
    def update_provider(cls, provider_id: str, config: Dict[str, Any] = None, **kwargs) -> Optional[UserFederationProvider]:
        """
        Update federation provider.
        
        Args:
            provider_id: Provider ID
            config: Updated configuration (optional)
            **kwargs: Other fields to update
            
        Returns:
            Updated provider or None
        """
        provider = UserFederationProvider.find_by_id(provider_id)
        if not provider:
            return None
        
        # Update config with encryption
        if config is not None:
            encrypted_config = cls._encrypt_config(config, provider.provider_type)
            provider.config = encrypted_config
        
        # Update other fields
        for key, value in kwargs.items():
            if hasattr(provider, key):
                setattr(provider, key, value)
        
        provider.updated_at = datetime.utcnow()
        db.session.commit()
        
        return provider
    
    @classmethod
    def delete_provider(cls, provider_id: str) -> bool:
        """
        Delete federation provider and all associated data.
        
        Args:
            provider_id: Provider ID
            
        Returns:
            True if deleted, False if not found
        """
        provider = UserFederationProvider.find_by_id(provider_id)
        if not provider:
            return False
        
        # Cascade deletes mappers and links
        db.session.delete(provider)
        db.session.commit()
        
        logger.info(f"Deleted federation provider: {provider.name}")
        return True
    
    @classmethod
    def test_provider_connection(cls, provider_id: str) -> Dict[str, Any]:
        """
        Test connection to federation provider.
        
        Args:
            provider_id: Provider ID
            
        Returns:
            Dict with 'success' and 'message' keys
        """
        provider = UserFederationProvider.find_by_id(provider_id)
        if not provider:
            return {'success': False, 'message': 'Provider not found'}
        
        try:
            instance = cls.create_provider_instance(provider)
            success, message = instance.test_connection()
            return {'success': success, 'message': message}
        except Exception as e:
            return {'success': False, 'message': str(e)}


# Register default providers
def _register_default_providers():
    """Register built-in federation providers"""
    try:
        from apps.services.federation.ldap_provider import LDAPFederationProvider
        FederationService.register_provider('ldap', LDAPFederationProvider)
    except ImportError:
        logger.warning("LDAP provider not available (ldap3 not installed)")
    
    try:
        from apps.services.federation.mysql_provider import MySQLFederationProvider
        FederationService.register_provider('mysql', MySQLFederationProvider)
    except ImportError:
        logger.warning("MySQL provider not available (pymysql not installed)")
    
    try:
        from apps.services.federation.postgresql_provider import PostgreSQLFederationProvider
        FederationService.register_provider('postgresql', PostgreSQLFederationProvider)
    except ImportError:
        logger.warning("PostgreSQL provider not available (psycopg2 not installed)")


# Auto-register providers on import
_register_default_providers()
