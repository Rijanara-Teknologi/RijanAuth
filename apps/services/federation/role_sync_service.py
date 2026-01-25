# -*- encoding: utf-8 -*-
"""
RijanAuth - Federated Role Synchronization Service
Intelligent role synchronization with format detection for federated users.
"""

import json
import re
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from apps import db
from apps.models.role import Role, RoleMapping
from apps.models.federation import (
    UserFederationProvider, FederationRoleMapping, 
    FederationRoleFormatConfig, FederatedRoleSync
)

logger = logging.getLogger(__name__)


class RoleFormatDetector:
    """
    Intelligent role format detection engine.
    Detects and normalizes role data from various formats (string, array, JSON, custom).
    """
    
    @staticmethod
    def detect_and_parse(
        data: Any, 
        config: Optional[FederationRoleFormatConfig] = None
    ) -> Tuple[List[str], str]:
        """
        Detect format and parse roles from external data.
        
        Args:
            data: Raw role data from external source
            config: Optional format configuration
            
        Returns:
            Tuple of (parsed_roles, detected_format)
        """
        if data is None:
            return [], 'empty'
        
        # Use explicit config if available
        if config and config.enabled and not config.auto_detect:
            roles = RoleFormatDetector._parse_with_config(data, config)
            return roles, config.format_type
        
        # Auto-detect format
        return RoleFormatDetector._auto_detect_and_parse(data, config)
    
    @staticmethod
    def _parse_with_config(
        data: Any, 
        config: FederationRoleFormatConfig
    ) -> List[str]:
        """Parse roles using explicit configuration."""
        format_type = config.format_type
        
        if format_type == 'string':
            return RoleFormatDetector._parse_string_roles(
                data, config.delimiter or ','
            )
        elif format_type == 'array':
            return RoleFormatDetector._parse_array_roles(data)
        elif format_type == 'json':
            return RoleFormatDetector._parse_json_roles(
                data, config.array_path
            )
        elif format_type == 'custom':
            return RoleFormatDetector._parse_custom_roles(
                data, config.format_pattern
            )
        
        return []
    
    @staticmethod
    def _auto_detect_and_parse(
        data: Any,
        config: Optional[FederationRoleFormatConfig] = None
    ) -> Tuple[List[str], str]:
        """Auto-detect format and parse roles."""
        
        # Handle None or empty
        if data is None or data == '':
            return [], 'empty'
        
        # Handle list/tuple directly
        if isinstance(data, (list, tuple)):
            roles = RoleFormatDetector._parse_array_roles(data)
            return roles, 'array'
        
        # Handle dict - look for role-related keys
        if isinstance(data, dict):
            roles, format_type = RoleFormatDetector._parse_dict_roles(data)
            return roles, format_type
        
        # Handle string
        if isinstance(data, str):
            data = data.strip()
            if not data:
                return [], 'empty'
            
            # Try JSON first
            if data.startswith('[') or data.startswith('{'):
                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, (list, tuple)):
                        roles = RoleFormatDetector._parse_array_roles(parsed)
                        return roles, 'json_array'
                    elif isinstance(parsed, dict):
                        roles, _ = RoleFormatDetector._parse_dict_roles(parsed)
                        return roles, 'json_object'
                except json.JSONDecodeError:
                    pass
            
            # Detect delimiter-separated string
            delimiter = RoleFormatDetector._detect_delimiter(data)
            if delimiter:
                roles = RoleFormatDetector._parse_string_roles(data, delimiter)
                return roles, f'string_{delimiter}'
            
            # Single value
            return [data], 'single'
        
        # Fallback - try to convert to string
        try:
            return [str(data).strip()], 'unknown'
        except Exception:
            return [], 'unknown'
    
    @staticmethod
    def _parse_string_roles(data: Any, delimiter: str = ',') -> List[str]:
        """Parse roles from delimiter-separated string."""
        if isinstance(data, str):
            return [role.strip() for role in data.split(delimiter) if role.strip()]
        elif isinstance(data, (list, tuple)):
            return [str(role).strip() for role in data if str(role).strip()]
        return []
    
    @staticmethod
    def _parse_array_roles(data: Any) -> List[str]:
        """Parse roles from array format."""
        if isinstance(data, (list, tuple)):
            result = []
            for item in data:
                if isinstance(item, str):
                    clean = item.strip()
                    if clean:
                        result.append(clean)
                elif isinstance(item, dict):
                    # Handle objects like {"name": "role_name", ...}
                    role_name = item.get('name') or item.get('role') or item.get('roleName')
                    if role_name:
                        result.append(str(role_name).strip())
                else:
                    clean = str(item).strip()
                    if clean:
                        result.append(clean)
            return result
        elif isinstance(data, str):
            # Try to parse as JSON array
            try:
                parsed = json.loads(data)
                if isinstance(parsed, (list, tuple)):
                    return RoleFormatDetector._parse_array_roles(parsed)
            except json.JSONDecodeError:
                pass
            
            # Try common delimiters
            for delim in [',', ';', '|', '\n']:
                roles = [r.strip() for r in data.split(delim) if r.strip()]
                if len(roles) > 1:
                    return roles
            
            return [data.strip()] if data.strip() else []
        
        return []
    
    @staticmethod
    def _parse_json_roles(data: Any, array_path: Optional[str] = None) -> List[str]:
        """Parse roles from JSON format with optional path."""
        try:
            # Ensure we have a dict/list to work with
            if isinstance(data, str):
                data = json.loads(data)
            
            # Navigate to array path if specified
            if array_path and isinstance(data, dict):
                keys = array_path.strip('.').split('.')
                current = data
                for key in keys:
                    if isinstance(current, dict) and key in current:
                        current = current[key]
                    elif isinstance(current, list):
                        # Handle array index
                        try:
                            idx = int(key)
                            current = current[idx]
                        except (ValueError, IndexError):
                            return []
                    else:
                        return []
                data = current
            
            # Extract roles from the target data
            return RoleFormatDetector._parse_array_roles(data)
            
        except (json.JSONDecodeError, TypeError, KeyError):
            return []
    
    @staticmethod
    def _parse_custom_roles(data: Any, pattern: Optional[str] = None) -> List[str]:
        """Parse roles using custom regex pattern."""
        if not pattern:
            return RoleFormatDetector._parse_array_roles(data)
        
        try:
            data_str = str(data) if not isinstance(data, str) else data
            matches = re.findall(pattern, data_str)
            
            # Flatten if nested tuples from groups
            result = []
            for match in matches:
                if isinstance(match, tuple):
                    result.extend([m.strip() for m in match if m and m.strip()])
                elif match and match.strip():
                    result.append(match.strip())
            
            return result
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            return []
    
    @staticmethod
    def _parse_dict_roles(data: dict) -> Tuple[List[str], str]:
        """Parse roles from a dictionary, looking for common role keys."""
        # Common keys that might contain roles
        role_keys = ['roles', 'groups', 'authorities', 'permissions', 'role', 
                     'memberOf', 'groupMembership', 'realmRoles', 'clientRoles']
        
        for key in role_keys:
            if key in data:
                value = data[key]
                if isinstance(value, (list, tuple)):
                    roles = RoleFormatDetector._parse_array_roles(value)
                    return roles, f'dict_{key}'
                elif isinstance(value, str):
                    roles = RoleFormatDetector._parse_string_roles(value, ',')
                    return roles, f'dict_{key}'
        
        # Fallback - try to get all string values
        return [], 'dict_unknown'
    
    @staticmethod
    def _detect_delimiter(data: str) -> Optional[str]:
        """Detect the most likely delimiter in a string."""
        # Common delimiters in order of preference
        delimiters = [',', ';', '|', '\t', '\n']
        
        for delim in delimiters:
            if delim in data:
                parts = [p.strip() for p in data.split(delim) if p.strip()]
                if len(parts) > 1:
                    return delim
        
        return None


class RoleSyncService:
    """
    Service for synchronizing roles between external identity providers 
    and RijanAuth's internal role system.
    """
    
    # Protected roles that cannot be overridden by federation
    PROTECTED_ROLES = {'admin', 'create-realm', 'realm-admin', 'manage-users', 'manage-realm'}
    
    @staticmethod
    def synchronize_user_roles(
        user,
        provider: UserFederationProvider,
        external_user: Dict[str, Any],
        realm_id: str,
        sync_type: str = 'login'
    ) -> Dict[str, Any]:
        """
        Synchronize roles from external source to internal RijanAuth roles.
        
        Args:
            user: The local user object
            provider: The federation provider
            external_user: User data from external source
            realm_id: The realm ID
            sync_type: Type of sync ('login', 'scheduled', 'manual')
            
        Returns:
            Dictionary with sync results
        """
        try:
            # 1. Extract raw role data based on provider configuration
            raw_role_data = RoleSyncService._extract_raw_role_data(provider, external_user)
            
            logger.debug(f"Raw role data for user {user.id}: {raw_role_data}")
            
            # 2. Get format configuration
            format_config = FederationRoleFormatConfig.get_for_provider(provider.id)
            
            # 3. Detect format and parse roles
            external_roles, format_detected = RoleFormatDetector.detect_and_parse(
                raw_role_data, format_config
            )
            
            logger.info(f"Detected {len(external_roles)} external roles for user {user.id}: "
                       f"{external_roles} (format: {format_detected})")
            
            # 4. Get role mappings for this provider
            mappings = FederationRoleMapping.find_by_provider(provider.id)
            
            # 5. Get all realm roles for mapping/creation
            realm_roles = Role.query.filter_by(realm_id=realm_id).all()
            realm_role_map = {r.name.lower(): r for r in realm_roles}
            
            # 6. Process each external role
            internal_role_ids = set()
            unmapped_roles = []
            
            for ext_role in external_roles:
                matched = False
                
                # Check explicit mappings first
                for mapping in mappings:
                    if mapping.matches(ext_role):
                        internal_role_ids.add(mapping.internal_role_id)
                        matched = True
                        logger.debug(f"Mapped external role '{ext_role}' to internal role {mapping.internal_role_id}")
                        break
                
                if not matched:
                    # Try direct name match with existing realm roles
                    clean_role = ext_role.lower().strip()
                    
                    # Check if role exists in realm
                    if clean_role in realm_role_map:
                        internal_role_ids.add(realm_role_map[clean_role].id)
                        matched = True
                        logger.debug(f"Direct matched external role '{ext_role}' to realm role")
                    
                    # Handle LDAP DN format (cn=rolename,ou=groups,...)
                    elif ext_role.lower().startswith('cn='):
                        cn_match = re.match(r'cn=([^,]+)', ext_role, re.IGNORECASE)
                        if cn_match:
                            cn_name = cn_match.group(1).lower().strip()
                            if cn_name in realm_role_map:
                                internal_role_ids.add(realm_role_map[cn_name].id)
                                matched = True
                                logger.debug(f"DN matched external role '{ext_role}' to realm role '{cn_name}'")
                
                if not matched:
                    unmapped_roles.append(ext_role)
                    
                    # Auto-create role if configured
                    if provider.config.get('create_missing_roles', False):
                        new_role = RoleSyncService._create_role_from_external(
                            realm_id, ext_role, provider.id
                        )
                        if new_role:
                            internal_role_ids.add(new_role.id)
                            realm_role_map[new_role.name.lower()] = new_role
                            unmapped_roles.remove(ext_role)
                            logger.info(f"Auto-created role '{new_role.name}' for external role '{ext_role}'")
            
            # 7. Handle default role if no roles mapped
            if not internal_role_ids:
                default_role_name = provider.config.get('default_role_if_empty')
                if default_role_name and default_role_name.lower() in realm_role_map:
                    internal_role_ids.add(realm_role_map[default_role_name.lower()].id)
                    logger.debug(f"Added default role '{default_role_name}' for user with no mapped roles")
            
            # 8. Calculate role changes
            current_role_ids = RoleSyncService._get_user_realm_roles(user.id, realm_id)
            
            # Don't remove protected roles
            protected_role_ids = RoleSyncService._get_protected_role_ids(realm_roles)
            
            roles_to_add = internal_role_ids - current_role_ids
            roles_to_remove = current_role_ids - internal_role_ids - protected_role_ids
            
            # 9. Apply role changes
            if roles_to_add or roles_to_remove:
                RoleSyncService._apply_role_changes(user.id, roles_to_add, roles_to_remove)
            
            # 10. Record sync history
            sync_record = FederatedRoleSync(
                user_id=user.id,
                provider_id=provider.id,
                external_roles=external_roles,
                synchronized_roles=list(internal_role_ids),
                roles_added=list(roles_to_add),
                roles_removed=list(roles_to_remove),
                unmapped_roles=unmapped_roles,
                format_detected=format_detected,
                sync_type=sync_type
            )
            db.session.add(sync_record)
            db.session.commit()
            
            result = {
                'success': True,
                'external_roles': external_roles,
                'mapped_roles': list(internal_role_ids),
                'unmapped_roles': unmapped_roles,
                'added': list(roles_to_add),
                'removed': list(roles_to_remove),
                'format_detected': format_detected,
                'sync_id': sync_record.id
            }
            
            logger.info(f"Role sync completed for user {user.id}: "
                       f"added={len(roles_to_add)}, removed={len(roles_to_remove)}, "
                       f"unmapped={len(unmapped_roles)}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error synchronizing roles for user {user.id}: {e}", exc_info=True)
            db.session.rollback()
            return {
                'success': False,
                'error': str(e),
                'external_roles': [],
                'mapped_roles': [],
                'unmapped_roles': [],
                'added': [],
                'removed': []
            }
    
    @staticmethod
    def _extract_raw_role_data(
        provider: UserFederationProvider, 
        external_user: Dict[str, Any]
    ) -> Any:
        """Extract raw role data based on provider type and configuration."""
        config = provider.config or {}
        
        # Get format config if exists
        format_config = FederationRoleFormatConfig.get_for_provider(provider.id)
        role_field = format_config.role_field if format_config else 'roles'
        
        if provider.provider_type == 'ldap':
            # LDAP: Check memberOf attribute or groups
            data = (external_user.get('memberOf') or 
                   external_user.get('member_of') or
                   external_user.get('groups') or 
                   external_user.get(role_field) or
                   [])
            return data
        
        elif provider.provider_type in ['mysql', 'postgresql']:
            # Database: Check configured role field/column
            role_field_config = config.get('role_field', role_field)
            return external_user.get(role_field_config, [])
        
        # Default fallback
        return (external_user.get('roles') or 
                external_user.get('groups') or 
                external_user.get(role_field) or
                [])
    
    @staticmethod
    def _get_user_realm_roles(user_id: str, realm_id: str) -> Set[str]:
        """Get current realm role IDs for a user."""
        mappings = RoleMapping.query.filter_by(user_id=user_id).all()
        
        # Filter to realm-level roles (exclude client roles)
        realm_role_ids = set()
        for mapping in mappings:
            if mapping.role and mapping.role.realm_id == realm_id and not mapping.role.client_id:
                realm_role_ids.add(mapping.role_id)
        
        return realm_role_ids
    
    @staticmethod
    def _get_protected_role_ids(realm_roles: List[Role]) -> Set[str]:
        """Get IDs of protected roles that shouldn't be removed by federation."""
        protected_ids = set()
        for role in realm_roles:
            if role.name.lower() in RoleSyncService.PROTECTED_ROLES:
                protected_ids.add(role.id)
        return protected_ids
    
    @staticmethod
    def _apply_role_changes(
        user_id: str, 
        roles_to_add: Set[str], 
        roles_to_remove: Set[str]
    ) -> None:
        """Apply role assignment changes to user."""
        # Remove roles
        if roles_to_remove:
            RoleMapping.query.filter(
                RoleMapping.user_id == user_id,
                RoleMapping.role_id.in_(roles_to_remove)
            ).delete(synchronize_session='fetch')
        
        # Add roles
        for role_id in roles_to_add:
            existing = RoleMapping.query.filter_by(
                user_id=user_id, role_id=role_id
            ).first()
            if not existing:
                mapping = RoleMapping(user_id=user_id, role_id=role_id)
                db.session.add(mapping)
        
        db.session.commit()
    
    @staticmethod
    def _create_role_from_external(
        realm_id: str, 
        external_role: str, 
        provider_id: str
    ) -> Optional[Role]:
        """Create a new realm role from external role name."""
        # Sanitize role name
        role_name = RoleSyncService._sanitize_role_name(external_role)
        
        if not role_name:
            return None
        
        # Check if protected
        if role_name.lower() in RoleSyncService.PROTECTED_ROLES:
            logger.warning(f"Cannot auto-create protected role: {role_name}")
            return None
        
        # Check if already exists
        existing = Role.query.filter_by(realm_id=realm_id, name=role_name).first()
        if existing:
            return existing
        
        try:
            role = Role(
                realm_id=realm_id,
                name=role_name,
                description=f"Auto-created from federation provider (external: {external_role})",
                composite=False
            )
            db.session.add(role)
            
            # Create mapping for this role
            mapping = FederationRoleMapping(
                provider_id=provider_id,
                external_role_name=external_role,
                internal_role_id=role.id,
                mapping_type='direct',
                enabled=True
            )
            db.session.add(mapping)
            
            db.session.commit()
            return role
            
        except Exception as e:
            logger.error(f"Failed to create role from external '{external_role}': {e}")
            db.session.rollback()
            return None
    
    @staticmethod
    def _sanitize_role_name(name: str) -> str:
        """Sanitize external role name for use as internal role name."""
        if not name:
            return ''
        
        # Handle LDAP DN format
        if name.lower().startswith('cn='):
            match = re.match(r'cn=([^,]+)', name, re.IGNORECASE)
            if match:
                name = match.group(1)
        
        # Remove special characters except hyphen and underscore
        sanitized = re.sub(r'[^\w\-_]', '_', name.strip())
        
        # Collapse multiple underscores
        sanitized = re.sub(r'_+', '_', sanitized)
        
        # Remove leading/trailing underscores
        sanitized = sanitized.strip('_')
        
        return sanitized[:100]  # Limit length
    
    @staticmethod
    def create_role_mapping(
        provider_id: str,
        external_role: str,
        internal_role_id: str,
        mapping_type: str = 'direct',
        mapping_value: Optional[str] = None,
        priority: int = 0
    ) -> FederationRoleMapping:
        """Create a new role mapping."""
        mapping = FederationRoleMapping(
            provider_id=provider_id,
            external_role_name=external_role,
            internal_role_id=internal_role_id,
            mapping_type=mapping_type,
            mapping_value=mapping_value,
            priority=priority,
            enabled=True
        )
        db.session.add(mapping)
        db.session.commit()
        return mapping
    
    @staticmethod
    def update_role_mapping(
        mapping_id: str,
        **kwargs
    ) -> Optional[FederationRoleMapping]:
        """Update an existing role mapping."""
        mapping = FederationRoleMapping.query.get(mapping_id)
        if not mapping:
            return None
        
        for key, value in kwargs.items():
            if hasattr(mapping, key):
                setattr(mapping, key, value)
        
        mapping.updated_at = datetime.utcnow()
        db.session.commit()
        return mapping
    
    @staticmethod
    def delete_role_mapping(mapping_id: str) -> bool:
        """Delete a role mapping."""
        mapping = FederationRoleMapping.query.get(mapping_id)
        if not mapping:
            return False
        
        db.session.delete(mapping)
        db.session.commit()
        return True
    
    @staticmethod
    def get_role_mappings(provider_id: str) -> List[FederationRoleMapping]:
        """Get all role mappings for a provider."""
        return FederationRoleMapping.find_by_provider(provider_id)
    
    @staticmethod
    def test_role_format(
        data: Any,
        format_type: Optional[str] = None,
        delimiter: Optional[str] = None,
        array_path: Optional[str] = None,
        pattern: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test role format detection with sample data.
        
        Args:
            data: Sample role data
            format_type: Optional explicit format type
            delimiter: Optional delimiter for string format
            array_path: Optional JSON path for JSON format
            pattern: Optional regex pattern for custom format
            
        Returns:
            Dictionary with detected format and parsed roles
        """
        # Create temp config if explicit format specified
        if format_type:
            config = FederationRoleFormatConfig(
                format_type=format_type,
                delimiter=delimiter,
                array_path=array_path,
                format_pattern=pattern,
                auto_detect=False,
                enabled=True
            )
            roles = RoleFormatDetector._parse_with_config(data, config)
            return {
                'roles': roles,
                'format': format_type,
                'count': len(roles)
            }
        
        # Auto-detect
        roles, detected_format = RoleFormatDetector.detect_and_parse(data, None)
        return {
            'roles': roles,
            'format': detected_format,
            'count': len(roles)
        }
    
    @staticmethod
    def preview_role_sync(
        provider: UserFederationProvider,
        external_user: Dict[str, Any],
        realm_id: str
    ) -> Dict[str, Any]:
        """
        Preview role synchronization without applying changes.
        
        Returns what roles would be added/removed.
        """
        try:
            # Extract and parse roles
            raw_role_data = RoleSyncService._extract_raw_role_data(provider, external_user)
            format_config = FederationRoleFormatConfig.get_for_provider(provider.id)
            external_roles, format_detected = RoleFormatDetector.detect_and_parse(
                raw_role_data, format_config
            )
            
            # Get mappings
            mappings = FederationRoleMapping.find_by_provider(provider.id)
            realm_roles = Role.query.filter_by(realm_id=realm_id).all()
            realm_role_map = {r.name.lower(): r for r in realm_roles}
            
            # Process roles
            mapped_roles = []
            unmapped_roles = []
            
            for ext_role in external_roles:
                matched = False
                
                for mapping in mappings:
                    if mapping.matches(ext_role):
                        mapped_roles.append({
                            'external': ext_role,
                            'internal': mapping.internal_role.name if mapping.internal_role else 'Unknown',
                            'mapping_type': mapping.mapping_type
                        })
                        matched = True
                        break
                
                if not matched:
                    # Check direct match
                    clean_role = ext_role.lower().strip()
                    if clean_role in realm_role_map:
                        mapped_roles.append({
                            'external': ext_role,
                            'internal': realm_role_map[clean_role].name,
                            'mapping_type': 'auto'
                        })
                        matched = True
                
                if not matched:
                    unmapped_roles.append(ext_role)
            
            return {
                'raw_data': str(raw_role_data)[:500],  # Truncate for display
                'format_detected': format_detected,
                'external_roles': external_roles,
                'mapped_roles': mapped_roles,
                'unmapped_roles': unmapped_roles,
                'would_create': provider.config.get('create_missing_roles', False),
                'default_role': provider.config.get('default_role_if_empty')
            }
            
        except Exception as e:
            logger.error(f"Error previewing role sync: {e}", exc_info=True)
            return {
                'error': str(e),
                'raw_data': None,
                'format_detected': None,
                'external_roles': [],
                'mapped_roles': [],
                'unmapped_roles': []
            }
    
    @staticmethod
    def get_sync_history(
        user_id: str,
        provider_id: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get role synchronization history for a user."""
        records = FederatedRoleSync.get_history(user_id, provider_id, limit)
        return [r.to_dict() for r in records]
    
    @staticmethod
    def configure_role_format(
        provider_id: str,
        format_type: str = 'string',
        delimiter: Optional[str] = ',',
        array_path: Optional[str] = None,
        format_pattern: Optional[str] = None,
        role_field: str = 'roles',
        auto_detect: bool = True
    ) -> FederationRoleFormatConfig:
        """
        Configure role format detection for a provider.
        """
        config = FederationRoleFormatConfig.query.filter_by(provider_id=provider_id).first()
        
        if config:
            config.format_type = format_type
            config.delimiter = delimiter
            config.array_path = array_path
            config.format_pattern = format_pattern
            config.role_field = role_field
            config.auto_detect = auto_detect
            config.updated_at = datetime.utcnow()
        else:
            config = FederationRoleFormatConfig(
                provider_id=provider_id,
                format_type=format_type,
                delimiter=delimiter,
                array_path=array_path,
                format_pattern=format_pattern,
                role_field=role_field,
                auto_detect=auto_detect,
                enabled=True
            )
            db.session.add(config)
        
        db.session.commit()
        return config
