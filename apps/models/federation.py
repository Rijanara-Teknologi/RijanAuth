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
