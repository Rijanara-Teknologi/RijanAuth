# -*- encoding: utf-8 -*-
"""
RijanAuth - User Federation Models
Models for external user federation (LDAP, MySQL, PostgreSQL)
"""

from datetime import datetime
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, JSON, Enum
from sqlalchemy.orm import relationship
from apps import db
from apps.models.base import BaseModel, RealmScopedModel, generate_uuid, TimestampMixin


class UserFederationProvider(RealmScopedModel):
    """
    User Federation Provider Configuration.
    Stores configuration for external identity sources (LDAP, MySQL, PostgreSQL).
    """
    __tablename__ = 'user_federation_providers'
    
    # Basic info
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=True)
    provider_type = Column(String(50), nullable=False)  # 'ldap', 'mysql', 'postgresql'
    
    # Status
    enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=0, nullable=False)  # Lower = higher priority
    
    # Configuration (JSON) - provider-specific settings
    # Sensitive fields (passwords) should be encrypted before storing
    config = Column(JSON, default=dict, nullable=False)
    
    # Import/Export settings
    import_enabled = Column(Boolean, default=True, nullable=False)  # Import users on login
    sync_registrations = Column(Boolean, default=False, nullable=False)  # Sync new users to external
    
    # Sync scheduling (in seconds, -1 = disabled)
    full_sync_period = Column(Integer, default=-1, nullable=False)
    changed_sync_period = Column(Integer, default=-1, nullable=False)
    
    # Sync status
    last_sync = Column(DateTime, nullable=True)
    last_sync_status = Column(String(50), nullable=True)  # 'success', 'failed', 'running'
    last_sync_error = Column(Text, nullable=True)
    
    # Cache settings
    cache_policy = Column(String(50), default='DEFAULT', nullable=False)  # DEFAULT, EVICT_DAILY, etc.
    eviction_day = Column(Integer, nullable=True)  # Day of week for eviction
    eviction_hour = Column(Integer, nullable=True)  # Hour for eviction
    eviction_minute = Column(Integer, nullable=True)  # Minute for eviction
    max_lifespan = Column(Integer, nullable=True)  # Cache max lifespan in ms
    
    # Relationships
    mappers = relationship('UserFederationMapper', back_populates='provider', 
                          cascade='all, delete-orphan', lazy='dynamic')
    links = relationship('UserFederationLink', back_populates='provider',
                        cascade='all, delete-orphan', lazy='dynamic')
    
    # Unique constraint: name must be unique within realm
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'name', name='uq_federation_provider_name'),
    )
    
    def __repr__(self):
        return f'<UserFederationProvider {self.name} ({self.provider_type})>'
    
    @classmethod
    def find_by_name(cls, realm_id, name):
        """Find provider by name within realm"""
        return cls.query.filter_by(realm_id=realm_id, name=name).first()
    
    @classmethod
    def get_enabled_providers(cls, realm_id):
        """Get all enabled providers for a realm, ordered by priority"""
        return cls.query.filter_by(
            realm_id=realm_id, 
            enabled=True
        ).order_by(cls.priority.asc()).all()
    
    @classmethod
    def get_by_type(cls, realm_id, provider_type):
        """Get all providers of a specific type for a realm"""
        return cls.query.filter_by(
            realm_id=realm_id,
            provider_type=provider_type
        ).all()
    
    def to_dict(self, include_config=False):
        """Convert to dictionary, optionally including config"""
        result = {
            'id': self.id,
            'realm_id': self.realm_id,
            'name': self.name,
            'display_name': self.display_name,
            'provider_type': self.provider_type,
            'enabled': self.enabled,
            'priority': self.priority,
            'import_enabled': self.import_enabled,
            'sync_registrations': self.sync_registrations,
            'full_sync_period': self.full_sync_period,
            'changed_sync_period': self.changed_sync_period,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'last_sync_status': self.last_sync_status,
            'cache_policy': self.cache_policy,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_config:
            # Note: Sensitive fields should be masked when exposing config
            result['config'] = self.config
        return result


class UserFederationMapper(db.Model, TimestampMixin):
    """
    Attribute Mapper for Federation Provider.
    Maps attributes from external source to RijanAuth user attributes.
    """
    __tablename__ = 'user_federation_mappers'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Provider relationship
    provider_id = Column(String(36), db.ForeignKey('user_federation_providers.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    
    # Mapper identification
    name = Column(String(255), nullable=False)
    mapper_type = Column(String(100), nullable=False)
    # Mapper types:
    # - 'user-attribute-ldap-mapper': Map LDAP attribute to user attribute
    # - 'user-attribute-db-mapper': Map DB column to user attribute
    # - 'hardcoded-attribute-mapper': Set hardcoded value
    # - 'hardcoded-role-mapper': Assign hardcoded role
    # - 'group-mapper': Map external groups to RijanAuth groups
    # - 'role-mapper': Map external roles to RijanAuth roles
    
    # Attribute mapping
    internal_attribute = Column(String(255), nullable=True)  # RijanAuth attribute name
    external_attribute = Column(String(255), nullable=True)  # External source attribute/column
    
    # Additional configuration
    config = Column(JSON, default=dict, nullable=False)
    # Config examples:
    # For user-attribute: {"read_only": true, "always_read_value_from_ldap": false}
    # For hardcoded: {"attribute_value": "some_value"}
    # For group-mapper: {"groups_path": "/external", "preserve_group_inheritance": true}
    
    # Relationships
    provider = relationship('UserFederationProvider', back_populates='mappers')
    
    # Unique constraint: mapper name must be unique within provider
    __table_args__ = (
        db.UniqueConstraint('provider_id', 'name', name='uq_federation_mapper_name'),
    )
    
    def __repr__(self):
        return f'<UserFederationMapper {self.name} ({self.mapper_type})>'
    
    @classmethod
    def find_by_provider(cls, provider_id):
        """Get all mappers for a provider"""
        return cls.query.filter_by(provider_id=provider_id).all()
    
    @classmethod
    def find_by_type(cls, provider_id, mapper_type):
        """Get all mappers of a specific type for a provider"""
        return cls.query.filter_by(provider_id=provider_id, mapper_type=mapper_type).all()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'provider_id': self.provider_id,
            'name': self.name,
            'mapper_type': self.mapper_type,
            'internal_attribute': self.internal_attribute,
            'external_attribute': self.external_attribute,
            'config': self.config,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class UserFederationLink(db.Model, TimestampMixin):
    """
    Links a local RijanAuth user to their external identity.
    Each user can be linked to multiple federation providers.
    """
    __tablename__ = 'user_federation_links'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # User relationship
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'),
                    nullable=False, index=True)
    
    # Provider relationship
    provider_id = Column(String(36), db.ForeignKey('user_federation_providers.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    
    # External identity information
    external_id = Column(String(255), nullable=False)  # Unique ID in external system (e.g., LDAP DN, DB primary key)
    external_username = Column(String(255), nullable=True)  # Username in external system
    external_email = Column(String(255), nullable=True)  # Email in external system
    
    # Sync tracking
    last_sync = Column(DateTime, nullable=True)
    
    # Storage mode
    storage_mode = Column(String(50), default='FEDERATED', nullable=False)
    # FEDERATED: User data comes from external source
    # IMPORT: User data was imported and is now local
    # UNLINKED: Link was broken but user kept locally
    
    # Relationships
    provider = relationship('UserFederationProvider', back_populates='links')
    user = relationship('User', backref=db.backref('federation_links', lazy='dynamic',
                                                   cascade='all, delete-orphan'))
    
    # Unique constraint: user can only be linked once per provider
    __table_args__ = (
        db.UniqueConstraint('user_id', 'provider_id', name='uq_user_federation_link'),
        db.UniqueConstraint('provider_id', 'external_id', name='uq_federation_external_id'),
    )
    
    def __repr__(self):
        return f'<UserFederationLink user={self.user_id} provider={self.provider_id}>'
    
    @classmethod
    def find_by_user(cls, user_id):
        """Get all federation links for a user"""
        return cls.query.filter_by(user_id=user_id).all()
    
    @classmethod
    def find_by_provider(cls, provider_id):
        """Get all federation links for a provider"""
        return cls.query.filter_by(provider_id=provider_id).all()
    
    @classmethod
    def find_by_external_id(cls, provider_id, external_id):
        """Find link by external ID within provider"""
        return cls.query.filter_by(provider_id=provider_id, external_id=external_id).first()
    
    @classmethod
    def find_user_provider_link(cls, user_id, provider_id):
        """Find specific link between user and provider"""
        return cls.query.filter_by(user_id=user_id, provider_id=provider_id).first()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'provider_id': self.provider_id,
            'external_id': self.external_id,
            'external_username': self.external_username,
            'external_email': self.external_email,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'storage_mode': self.storage_mode,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class FederationSyncLog(db.Model):
    """
    Log of federation synchronization operations.
    Tracks sync history for debugging and monitoring.
    """
    __tablename__ = 'federation_sync_logs'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Provider relationship
    provider_id = Column(String(36), db.ForeignKey('user_federation_providers.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    
    # Sync info
    sync_type = Column(String(50), nullable=False)  # 'full', 'changed', 'manual'
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), default='running', nullable=False)  # 'running', 'success', 'failed'
    
    # Statistics
    users_processed = Column(Integer, default=0, nullable=False)
    users_created = Column(Integer, default=0, nullable=False)
    users_updated = Column(Integer, default=0, nullable=False)
    users_removed = Column(Integer, default=0, nullable=False)
    errors_count = Column(Integer, default=0, nullable=False)
    
    # Error details
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, default=list, nullable=True)  # List of individual errors
    
    def __repr__(self):
        return f'<FederationSyncLog {self.sync_type} {self.status}>'
    
    @classmethod
    def get_recent_logs(cls, provider_id, limit=10):
        """Get recent sync logs for a provider"""
        return cls.query.filter_by(provider_id=provider_id)\
            .order_by(cls.started_at.desc())\
            .limit(limit).all()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'provider_id': self.provider_id,
            'sync_type': self.sync_type,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status,
            'users_processed': self.users_processed,
            'users_created': self.users_created,
            'users_updated': self.users_updated,
            'users_removed': self.users_removed,
            'errors_count': self.errors_count,
            'error_message': self.error_message,
        }


class FederationRoleMapping(db.Model, TimestampMixin):
    """
    Maps external roles from federation providers to internal RijanAuth roles.
    Supports direct mapping, prefix matching, and regex patterns.
    """
    __tablename__ = 'federation_role_mappings'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Provider relationship
    provider_id = Column(String(36), db.ForeignKey('user_federation_providers.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    
    # External role name or pattern
    external_role_name = Column(String(255), nullable=False)
    
    # Internal role relationship
    internal_role_id = Column(String(36), db.ForeignKey('roles.id', ondelete='CASCADE'),
                             nullable=False, index=True)
    
    # Mapping type: 'direct' (exact match), 'prefix' (starts with), 'regex' (pattern match)
    mapping_type = Column(String(20), nullable=False, default='direct')
    
    # For prefix/regex mappings, store the pattern value
    mapping_value = Column(String(255), nullable=True)
    
    # Enable/disable this mapping
    enabled = Column(Boolean, default=True, nullable=False)
    
    # Priority (lower = higher priority, processed first)
    priority = Column(Integer, default=0, nullable=False)
    
    # Relationships
    provider = relationship('UserFederationProvider', 
                           backref=db.backref('role_mappings', lazy='dynamic', cascade='all, delete-orphan'))
    internal_role = relationship('Role')
    
    # Unique constraint: external role name must be unique per provider
    __table_args__ = (
        db.UniqueConstraint('provider_id', 'external_role_name', name='uq_federation_role_mapping'),
    )
    
    def __repr__(self):
        return f'<FederationRoleMapping {self.external_role_name} -> {self.internal_role_id}>'
    
    @classmethod
    def find_by_provider(cls, provider_id):
        """Get all role mappings for a provider, ordered by priority"""
        return cls.query.filter_by(provider_id=provider_id, enabled=True)\
            .order_by(cls.priority.asc()).all()
    
    @classmethod
    def find_by_external_role(cls, provider_id, external_role):
        """Find mapping for a specific external role"""
        return cls.query.filter_by(
            provider_id=provider_id, 
            external_role_name=external_role,
            enabled=True
        ).first()
    
    def matches(self, role_name: str) -> bool:
        """Check if this mapping matches the given role name"""
        if self.mapping_type == 'direct':
            return role_name.lower() == self.external_role_name.lower()
        elif self.mapping_type == 'prefix':
            prefix = self.mapping_value or self.external_role_name
            return role_name.lower().startswith(prefix.lower())
        elif self.mapping_type == 'regex':
            import re
            pattern = self.mapping_value or self.external_role_name
            try:
                return bool(re.match(pattern, role_name, re.IGNORECASE))
            except re.error:
                return False
        return False
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'provider_id': self.provider_id,
            'external_role_name': self.external_role_name,
            'internal_role_id': self.internal_role_id,
            'internal_role_name': self.internal_role.name if self.internal_role else None,
            'mapping_type': self.mapping_type,
            'mapping_value': self.mapping_value,
            'enabled': self.enabled,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class FederationRoleFormatConfig(db.Model, TimestampMixin):
    """
    Configuration for detecting and parsing role data formats from external sources.
    Supports string (delimited), array, JSON, and custom formats.
    """
    __tablename__ = 'federation_role_format_configs'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Provider relationship
    provider_id = Column(String(36), db.ForeignKey('user_federation_providers.id', ondelete='CASCADE'),
                        nullable=False, unique=True, index=True)
    
    # Format type: 'string', 'array', 'json', 'custom'
    format_type = Column(String(20), nullable=False, default='string')
    
    # For custom formats, store the parsing pattern/regex
    format_pattern = Column(Text, nullable=True)
    
    # For string formats, the delimiter character(s)
    delimiter = Column(String(10), default=',', nullable=True)
    
    # For JSON formats, the path to the roles array (e.g., 'data.roles')
    array_path = Column(String(100), nullable=True)
    
    # Role field name in external data
    role_field = Column(String(100), default='roles', nullable=False)
    
    # Enable/disable format detection
    enabled = Column(Boolean, default=True, nullable=False)
    
    # Auto-detect format on first sync
    auto_detect = Column(Boolean, default=True, nullable=False)
    
    # Relationships
    provider = relationship('UserFederationProvider', 
                           backref=db.backref('role_format_config', uselist=False, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<FederationRoleFormatConfig {self.format_type} for provider {self.provider_id}>'
    
    @classmethod
    def get_for_provider(cls, provider_id):
        """Get format config for a provider, or return default"""
        config = cls.query.filter_by(provider_id=provider_id).first()
        if not config:
            # Return default config without saving
            return cls(
                provider_id=provider_id,
                format_type='string',
                delimiter=',',
                role_field='roles',
                enabled=True,
                auto_detect=True
            )
        return config
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'provider_id': self.provider_id,
            'format_type': self.format_type,
            'format_pattern': self.format_pattern,
            'delimiter': self.delimiter,
            'array_path': self.array_path,
            'role_field': self.role_field,
            'enabled': self.enabled,
            'auto_detect': self.auto_detect,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class FederatedRoleSync(db.Model):
    """
    Tracks role synchronization history for federated users.
    Records what roles were synchronized and when.
    """
    __tablename__ = 'federated_role_syncs'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # User relationship
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'),
                    nullable=False, index=True)
    
    # Provider relationship
    provider_id = Column(String(36), db.ForeignKey('user_federation_providers.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    
    # External roles received from provider (raw data)
    external_roles = Column(JSON, nullable=False, default=list)
    
    # Internal roles synchronized (role IDs)
    synchronized_roles = Column(JSON, nullable=False, default=list)
    
    # Roles that were added in this sync
    roles_added = Column(JSON, nullable=True, default=list)
    
    # Roles that were removed in this sync
    roles_removed = Column(JSON, nullable=True, default=list)
    
    # Unmapped external roles (couldn't find mapping)
    unmapped_roles = Column(JSON, nullable=True, default=list)
    
    # Detected format type
    format_detected = Column(String(20), nullable=True)
    
    # Sync metadata
    last_sync = Column(DateTime, default=datetime.utcnow, nullable=False)
    sync_type = Column(String(20), nullable=False, default='login')  # 'login', 'scheduled', 'manual'
    
    # Relationships
    user = relationship('User', backref=db.backref('role_syncs', lazy='dynamic', cascade='all, delete-orphan'))
    provider = relationship('UserFederationProvider')
    
    __table_args__ = (
        db.Index('ix_federated_role_sync_user_provider', 'user_id', 'provider_id'),
    )
    
    def __repr__(self):
        return f'<FederatedRoleSync user={self.user_id} provider={self.provider_id}>'
    
    @classmethod
    def get_latest_for_user(cls, user_id, provider_id=None):
        """Get the latest role sync for a user"""
        query = cls.query.filter_by(user_id=user_id)
        if provider_id:
            query = query.filter_by(provider_id=provider_id)
        return query.order_by(cls.last_sync.desc()).first()
    
    @classmethod
    def get_history(cls, user_id, provider_id=None, limit=10):
        """Get role sync history for a user"""
        query = cls.query.filter_by(user_id=user_id)
        if provider_id:
            query = query.filter_by(provider_id=provider_id)
        return query.order_by(cls.last_sync.desc()).limit(limit).all()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'provider_id': self.provider_id,
            'external_roles': self.external_roles,
            'synchronized_roles': self.synchronized_roles,
            'roles_added': self.roles_added,
            'roles_removed': self.roles_removed,
            'unmapped_roles': self.unmapped_roles,
            'format_detected': self.format_detected,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'sync_type': self.sync_type,
        }
