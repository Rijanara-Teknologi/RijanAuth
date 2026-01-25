# -*- encoding: utf-8 -*-
"""
RijanAuth - Protocol Mapper Service
Handles JWT token claim customization and transformation
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from apps import db
from apps.models.client import Client, ClientScope, ClientScopeMapping, ProtocolMapper
from apps.models.user import User
from apps.models.role import Role
from apps.models.group import Group

logger = logging.getLogger(__name__)


class MapperService:
    """
    Service for processing protocol mappers and generating custom JWT claims.
    Mirrors Keycloak's protocol mapper functionality.
    """
    
    # Protected claims that mappers cannot override
    PROTECTED_CLAIMS = {'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'auth_time', 'nonce', 'acr', 'azp', 'typ'}
    
    @classmethod
    def get_applicable_mappers(cls, client: Client, requested_scopes: str = None) -> List[ProtocolMapper]:
        """
        Get all applicable mappers for a client, including inherited from client scopes.
        
        Args:
            client: The client requesting the token
            requested_scopes: Space-separated list of requested scopes
            
        Returns:
            List of ProtocolMapper objects sorted by priority
        """
        mappers = []
        
        # 1. Get client's own mappers
        client_mappers = ProtocolMapper.find_by_client(client.id)
        mappers.extend(client_mappers)
        
        # 2. Get mappers from default client scopes
        default_scope_ids = client.default_client_scopes or []
        for scope_id in default_scope_ids:
            scope = ClientScope.query.get(scope_id)
            if scope:
                scope_mappers = ProtocolMapper.find_by_client_scope(scope.id)
                mappers.extend(scope_mappers)
        
        # 3. Get mappers from optional client scopes (if requested)
        if requested_scopes:
            requested_scope_list = requested_scopes.split()
            optional_scope_ids = client.optional_client_scopes or []
            
            for scope_id in optional_scope_ids:
                scope = ClientScope.query.get(scope_id)
                if scope and scope.name in requested_scope_list:
                    scope_mappers = ProtocolMapper.find_by_client_scope(scope.id)
                    mappers.extend(scope_mappers)
        
        # 4. Also check ClientScopeMapping
        scope_mappings = ClientScopeMapping.query.filter_by(client_id=client.id).all()
        for mapping in scope_mappings:
            if mapping.default_scope or (requested_scopes and mapping.scope.name in requested_scopes.split()):
                scope_mappers = ProtocolMapper.find_by_client_scope(mapping.scope_id)
                for mapper in scope_mappers:
                    if mapper not in mappers:
                        mappers.extend([mapper])
        
        # Sort by priority (lower = higher priority)
        mappers.sort(key=lambda m: m.priority)
        
        return mappers
    
    @classmethod
    def apply_mappers(cls, token: Dict[str, Any], user: User, client: Client, 
                      token_type: str, requested_scopes: str = None) -> Dict[str, Any]:
        """
        Apply all applicable mappers to a token.
        
        Args:
            token: Base token dictionary
            user: The user for whom the token is generated
            client: The client requesting the token
            token_type: 'access', 'id', or 'userinfo'
            requested_scopes: Space-separated list of requested scopes
            
        Returns:
            Modified token dictionary with custom claims
        """
        mappers = cls.get_applicable_mappers(client, requested_scopes)
        
        for mapper in mappers:
            try:
                # Check if mapper applies to this token type
                if not mapper.applies_to_token_type(token_type):
                    continue
                
                # Skip if trying to override protected claims
                if mapper.is_claim_protected():
                    logger.warning(f"Mapper {mapper.name} tried to override protected claim {mapper.get_claim_name()}")
                    continue
                
                # Apply the mapper
                token = cls._apply_mapper(token, mapper, user, client)
                
            except Exception as e:
                logger.error(f"Error applying mapper {mapper.name}: {str(e)}")
                continue
        
        return token
    
    @classmethod
    def _apply_mapper(cls, token: Dict[str, Any], mapper: ProtocolMapper, 
                      user: User, client: Client) -> Dict[str, Any]:
        """
        Apply a single mapper to a token.
        
        Args:
            token: Token dictionary
            mapper: The mapper to apply
            user: The user
            client: The client
            
        Returns:
            Modified token dictionary
        """
        config = mapper.config or {}
        mapper_type = mapper.protocol_mapper
        
        if mapper_type == 'oidc-usermodel-attribute-mapper':
            token = cls._apply_user_attribute_mapper(token, config, user)
        
        elif mapper_type == 'oidc-hardcoded-claim-mapper':
            token = cls._apply_hardcoded_claim_mapper(token, config)
        
        elif mapper_type == 'oidc-usermodel-realm-role-mapper':
            token = cls._apply_realm_role_mapper(token, config, user)
        
        elif mapper_type == 'oidc-usermodel-client-role-mapper':
            token = cls._apply_client_role_mapper(token, config, user, client)
        
        elif mapper_type == 'oidc-group-membership-mapper':
            token = cls._apply_group_membership_mapper(token, config, user)
        
        elif mapper_type == 'oidc-audience-mapper':
            token = cls._apply_audience_mapper(token, config, client)
        
        elif mapper_type == 'oidc-full-name-mapper':
            token = cls._apply_full_name_mapper(token, config, user)
        
        elif mapper_type == 'oidc-address-mapper':
            token = cls._apply_address_mapper(token, config, user)
        
        return token
    
    @classmethod
    def _apply_user_attribute_mapper(cls, token: Dict[str, Any], config: Dict[str, Any], 
                                     user: User) -> Dict[str, Any]:
        """Map a user attribute to a token claim"""
        user_attr = config.get('user.attribute', '')
        claim_name = config.get('claim.name', user_attr)
        claim_value = config.get('claim.value', '')  # Optional hardcoded value override
        json_type = config.get('jsonType.label', 'String')
        multivalued = config.get('multivalued', 'false') == 'true'
        aggregate = config.get('aggregate.attrs', 'false') == 'true'
        
        if not claim_name:
            return token
        
        # Get value from user
        if claim_value:
            value = claim_value
        else:
            # Try to get from user's direct attributes first
            if hasattr(user, user_attr) and getattr(user, user_attr) is not None:
                value = getattr(user, user_attr)
            # Then try user_attributes table
            elif hasattr(user, 'attributes') and user.attributes:
                # Check if user has attributes relationship
                user_attrs = {attr.name: attr.value for attr in user.attributes} if hasattr(user.attributes, '__iter__') else {}
                value = user_attrs.get(user_attr)
            else:
                value = None
        
        if value is not None:
            # Type conversion
            value = cls._convert_value(value, json_type, multivalued)
            
            # Set the claim (supports nested claims with dot notation)
            cls._set_nested_claim(token, claim_name, value)
        
        return token
    
    @classmethod
    def _apply_hardcoded_claim_mapper(cls, token: Dict[str, Any], 
                                      config: Dict[str, Any]) -> Dict[str, Any]:
        """Add a hardcoded claim to the token"""
        claim_name = config.get('claim.name', '')
        claim_value = config.get('claim.value', '')
        json_type = config.get('jsonType.label', 'String')
        
        if not claim_name:
            return token
        
        # Type conversion
        value = cls._convert_value(claim_value, json_type, False)
        
        # Set the claim
        cls._set_nested_claim(token, claim_name, value)
        
        return token
    
    @classmethod
    def _apply_realm_role_mapper(cls, token: Dict[str, Any], config: Dict[str, Any], 
                                 user: User) -> Dict[str, Any]:
        """Map user's realm roles to a token claim"""
        claim_name = config.get('claim.name', 'realm_access.roles')
        prefix = config.get('role.prefix', '')
        multivalued = config.get('multivalued', 'true') == 'true'
        
        if not claim_name:
            return token
        
        # Get user's realm roles
        roles = []
        if hasattr(user, 'role_mappings'):
            for role_mapping in user.role_mappings:
                role = role_mapping.role
                if role and not role.client_id:  # Realm role (no client)
                    role_name = f"{prefix}{role.name}" if prefix else role.name
                    roles.append(role_name)
        
        # Also check for realm_role attribute if stored differently
        if hasattr(user, 'get_realm_roles'):
            realm_roles = user.get_realm_roles()
            for role in realm_roles:
                role_name = f"{prefix}{role.name}" if prefix else role.name
                if role_name not in roles:
                    roles.append(role_name)
        
        if roles:
            if multivalued:
                cls._set_nested_claim(token, claim_name, roles)
            else:
                cls._set_nested_claim(token, claim_name, roles[0] if roles else '')
        
        return token
    
    @classmethod
    def _apply_client_role_mapper(cls, token: Dict[str, Any], config: Dict[str, Any], 
                                  user: User, client: Client) -> Dict[str, Any]:
        """Map user's client roles to a token claim"""
        claim_name = config.get('claim.name', 'resource_access')
        client_id_setting = config.get('client.id', '')  # Specific client or empty for current
        prefix = config.get('role.prefix', '')
        multivalued = config.get('multivalued', 'true') == 'true'
        add_to_access_token = config.get('add.to.access.token', 'true') == 'true'
        
        if not claim_name:
            return token
        
        target_client_id = client_id_setting or client.client_id
        
        # Get user's client roles
        roles = []
        if hasattr(user, 'role_mappings'):
            for role_mapping in user.role_mappings:
                role = role_mapping.role
                if role and role.client_id:
                    role_client = Client.query.get(role.client_id)
                    if role_client and role_client.client_id == target_client_id:
                        role_name = f"{prefix}{role.name}" if prefix else role.name
                        roles.append(role_name)
        
        if roles:
            # Format as resource_access structure
            if claim_name == 'resource_access':
                if 'resource_access' not in token:
                    token['resource_access'] = {}
                token['resource_access'][target_client_id] = {'roles': roles}
            else:
                if multivalued:
                    cls._set_nested_claim(token, claim_name, roles)
                else:
                    cls._set_nested_claim(token, claim_name, roles[0] if roles else '')
        
        return token
    
    @classmethod
    def _apply_group_membership_mapper(cls, token: Dict[str, Any], config: Dict[str, Any], 
                                       user: User) -> Dict[str, Any]:
        """Map user's group memberships to a token claim"""
        claim_name = config.get('claim.name', 'groups')
        full_path = config.get('full.path', 'true') == 'true'
        
        if not claim_name:
            return token
        
        # Get user's groups
        groups = []
        if hasattr(user, 'group_memberships'):
            for membership in user.group_memberships:
                group = membership.group
                if group:
                    if full_path:
                        # Build full path
                        path = cls._get_group_path(group)
                        groups.append(path)
                    else:
                        groups.append(group.name)
        
        if groups:
            cls._set_nested_claim(token, claim_name, groups)
        
        return token
    
    @classmethod
    def _apply_audience_mapper(cls, token: Dict[str, Any], config: Dict[str, Any], 
                               client: Client) -> Dict[str, Any]:
        """Add additional audience to the token"""
        included_audience = config.get('included.client.audience', '')
        included_custom = config.get('included.custom.audience', '')
        add_to_access_token = config.get('add.to.access.token', 'true') == 'true'
        add_to_id_token = config.get('add.to.id.token', 'false') == 'true'
        
        audiences_to_add = []
        
        if included_audience:
            audiences_to_add.append(included_audience)
        if included_custom:
            audiences_to_add.append(included_custom)
        
        if audiences_to_add:
            current_aud = token.get('aud', [])
            if isinstance(current_aud, str):
                current_aud = [current_aud]
            
            for aud in audiences_to_add:
                if aud not in current_aud:
                    current_aud.append(aud)
            
            token['aud'] = current_aud if len(current_aud) > 1 else current_aud[0]
        
        return token
    
    @classmethod
    def _apply_full_name_mapper(cls, token: Dict[str, Any], config: Dict[str, Any], 
                                user: User) -> Dict[str, Any]:
        """Map user's full name to a token claim"""
        claim_name = config.get('claim.name', 'name')
        
        if not claim_name:
            return token
        
        # Build full name
        parts = []
        if user.first_name:
            parts.append(user.first_name)
        if user.last_name:
            parts.append(user.last_name)
        
        if parts:
            full_name = ' '.join(parts)
            cls._set_nested_claim(token, claim_name, full_name)
        
        return token
    
    @classmethod
    def _apply_address_mapper(cls, token: Dict[str, Any], config: Dict[str, Any], 
                              user: User) -> Dict[str, Any]:
        """Map user's address attributes to address claim"""
        claim_name = config.get('claim.name', 'address')
        
        if not claim_name:
            return token
        
        # Get address components from user attributes
        address = {}
        address_fields = ['street_address', 'locality', 'region', 'postal_code', 'country', 'formatted']
        
        if hasattr(user, 'attributes') and user.attributes:
            user_attrs = {attr.name: attr.value for attr in user.attributes} if hasattr(user.attributes, '__iter__') else {}
            
            for field in address_fields:
                if field in user_attrs:
                    address[field] = user_attrs[field]
        
        if address:
            cls._set_nested_claim(token, claim_name, address)
        
        return token
    
    @classmethod
    def _convert_value(cls, value: Any, json_type: str, multivalued: bool) -> Any:
        """Convert value to the specified JSON type"""
        if value is None:
            return None
        
        if multivalued and not isinstance(value, list):
            value = [value]
        
        if json_type == 'int' or json_type == 'long':
            if isinstance(value, list):
                return [int(v) for v in value if v]
            return int(value) if value else 0
        
        elif json_type == 'boolean':
            if isinstance(value, list):
                return [str(v).lower() in ('true', '1', 'yes') for v in value]
            return str(value).lower() in ('true', '1', 'yes')
        
        elif json_type == 'JSON':
            import json
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except:
                    return value
            return value
        
        # Default: String
        if isinstance(value, list):
            return [str(v) for v in value]
        return str(value)
    
    @classmethod
    def _set_nested_claim(cls, token: Dict[str, Any], claim_path: str, value: Any) -> None:
        """Set a nested claim using dot notation (e.g., 'address.street')"""
        parts = claim_path.split('.')
        current = token
        
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            elif not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        
        current[parts[-1]] = value
    
    @classmethod
    def _get_group_path(cls, group: Group) -> str:
        """Build the full path for a group"""
        path_parts = [group.name]
        current = group
        
        while current.parent_id:
            parent = Group.query.get(current.parent_id)
            if parent:
                path_parts.insert(0, parent.name)
                current = parent
            else:
                break
        
        return '/' + '/'.join(path_parts)
    
    # ==================== Default Mappers ====================
    
    @classmethod
    def get_default_mappers_for_scope(cls, scope_name: str) -> List[Dict[str, Any]]:
        """Get default mapper configurations for a standard scope"""
        
        if scope_name == 'profile':
            return [
                {
                    'name': 'username',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'username',
                        'claim.name': 'preferred_username',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'full name',
                    'protocol_mapper': 'oidc-full-name-mapper',
                    'config': {
                        'claim.name': 'name',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'given name',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'first_name',
                        'claim.name': 'given_name',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'family name',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'last_name',
                        'claim.name': 'family_name',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'locale',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'locale',
                        'claim.name': 'locale',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        
        elif scope_name == 'email':
            return [
                {
                    'name': 'email',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'email',
                        'claim.name': 'email',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'email verified',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'email_verified',
                        'claim.name': 'email_verified',
                        'jsonType.label': 'boolean',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        
        elif scope_name == 'roles':
            return [
                {
                    'name': 'realm roles',
                    'protocol_mapper': 'oidc-usermodel-realm-role-mapper',
                    'config': {
                        'claim.name': 'realm_access.roles',
                        'multivalued': 'true',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'client roles',
                    'protocol_mapper': 'oidc-usermodel-client-role-mapper',
                    'config': {
                        'claim.name': 'resource_access',
                        'multivalued': 'true',
                        'access.token.claim': 'true',
                        'id.token.claim': 'false',
                        'userinfo.token.claim': 'false',
                    }
                },
            ]
        
        elif scope_name == 'groups':
            return [
                {
                    'name': 'groups',
                    'protocol_mapper': 'oidc-group-membership-mapper',
                    'config': {
                        'claim.name': 'groups',
                        'full.path': 'true',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        
        elif scope_name == 'address':
            return [
                {
                    'name': 'address',
                    'protocol_mapper': 'oidc-address-mapper',
                    'config': {
                        'claim.name': 'address',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        
        return []
    
    # ==================== Token Preview ====================
    
    @classmethod
    def preview_token(cls, client: Client, user: User, token_type: str = 'access',
                      requested_scopes: str = 'openid') -> Dict[str, Any]:
        """
        Generate a preview of what the token would look like with current mappers.
        
        Args:
            client: The client
            user: The user
            token_type: 'access', 'id', or 'userinfo'
            requested_scopes: Space-separated list of scopes
            
        Returns:
            Preview token dictionary
        """
        from datetime import datetime, timedelta
        
        # Build base token
        now = datetime.utcnow()
        
        if token_type == 'access':
            token = {
                'exp': int((now + timedelta(minutes=5)).timestamp()),
                'iat': int(now.timestamp()),
                'jti': 'preview-token-id',
                'iss': f'http://localhost:3000/auth/realms/{client.realm.name}',
                'aud': client.client_id,
                'sub': user.id,
                'typ': 'Bearer',
                'azp': client.client_id,
                'scope': requested_scopes,
            }
        elif token_type == 'id':
            token = {
                'exp': int((now + timedelta(minutes=5)).timestamp()),
                'iat': int(now.timestamp()),
                'auth_time': int(now.timestamp()),
                'jti': 'preview-id-token',
                'iss': f'http://localhost:3000/auth/realms/{client.realm.name}',
                'aud': client.client_id,
                'sub': user.id,
                'typ': 'ID',
                'azp': client.client_id,
            }
        else:  # userinfo
            token = {
                'sub': user.id,
            }
        
        # Apply mappers
        token = cls.apply_mappers(token, user, client, token_type, requested_scopes)
        
        return token
    
    # ==================== Mapper Validation ====================
    
    @classmethod
    def validate_mapper_config(cls, mapper_type: str, config: Dict[str, Any]) -> List[str]:
        """
        Validate mapper configuration.
        
        Args:
            mapper_type: The mapper type
            config: Configuration dictionary
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check claim name
        claim_name = config.get('claim.name', '')
        if claim_name in cls.PROTECTED_CLAIMS:
            errors.append(f"Cannot override protected claim '{claim_name}'")
        
        # Validate based on mapper type
        if mapper_type == 'oidc-usermodel-attribute-mapper':
            if not config.get('user.attribute') and not config.get('claim.value'):
                errors.append("Either 'user.attribute' or 'claim.value' must be specified")
        
        elif mapper_type == 'oidc-hardcoded-claim-mapper':
            if not claim_name:
                errors.append("'claim.name' is required for hardcoded claim mapper")
            if not config.get('claim.value'):
                errors.append("'claim.value' is required for hardcoded claim mapper")
        
        return errors
