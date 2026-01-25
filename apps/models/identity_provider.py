# -*- encoding: utf-8 -*-
"""
RijanAuth - Identity Provider Model
External identity provider configurations for federation
"""

from sqlalchemy import Column, String, Boolean, Text, JSON
from sqlalchemy.orm import relationship
from apps.models.base import RealmScopedModel, generate_uuid
from apps import db


class IdentityProvider(RealmScopedModel):
    """
    Identity Provider - External IdP configuration for federation.
    Supports OIDC, SAML, and social login providers.
    """
    __tablename__ = 'identity_providers'
    
    # Unique alias within realm (e.g., 'google', 'facebook', 'corporate-saml')
    alias = Column(String(255), nullable=False, index=True)
    
    # Display name
    display_name = Column(String(255), nullable=True)
    
    # Provider type (e.g., 'oidc', 'saml', 'google', 'facebook', 'github')
    provider_id = Column(String(50), nullable=False)
    
    # Enabled
    enabled = Column(Boolean, default=True)
    
    # Trust email from this provider
    trust_email = Column(Boolean, default=False)
    
    # Store tokens from this provider
    store_token = Column(Boolean, default=False)
    
    # Add read token role scope
    add_read_token_role_on_create = Column(Boolean, default=False)
    
    # Authenticate by default (skip login page)
    authenticate_by_default = Column(Boolean, default=False)
    
    # Link only (don't create new users)
    link_only = Column(Boolean, default=False)
    
    # First broker login flow
    first_broker_login_flow_alias = Column(String(255), nullable=True)
    
    # Post broker login flow
    post_broker_login_flow_alias = Column(String(255), nullable=True)
    
    # Configuration (JSON) - provider-specific settings
    # For OIDC: authorization_url, token_url, client_id, client_secret, etc.
    # For SAML: entity_id, sso_url, certificate, etc.
    config = Column(JSON, default=dict)
    
    # Relationships
    realm = relationship('Realm', back_populates='identity_providers')
    mappers = relationship('IdentityProviderMapper', back_populates='identity_provider', 
                          cascade='all, delete-orphan', lazy='dynamic')
    
    # Unique constraint
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'alias', name='uq_idp_alias'),
    )
    
    def __repr__(self):
        return f'<IdentityProvider {self.alias}>'
    
    @classmethod
    def find_by_alias(cls, realm_id, alias):
        """Find an identity provider by alias"""
        return cls.query.filter_by(realm_id=realm_id, alias=alias).first()
    
    def get_config(self, key, default=None):
        """Get a configuration value"""
        return (self.config or {}).get(key, default)
    
    def set_config(self, key, value):
        """Set a configuration value"""
        if self.config is None:
            self.config = {}
        self.config[key] = value
    
    def to_dict(self):
        """Serialize to dictionary"""
        return {
            'alias': self.alias,
            'displayName': self.display_name,
            'providerId': self.provider_id,
            'enabled': self.enabled,
            'trustEmail': self.trust_email,
            'storeToken': self.store_token,
            'addReadTokenRoleOnCreate': self.add_read_token_role_on_create,
            'authenticateByDefault': self.authenticate_by_default,
            'linkOnly': self.link_only,
            'firstBrokerLoginFlowAlias': self.first_broker_login_flow_alias,
            'postBrokerLoginFlowAlias': self.post_broker_login_flow_alias,
            'config': self.config or {},
        }


class IdentityProviderMapper(db.Model):
    """
    Identity Provider Mapper - Maps claims/attributes from external IdP to user attributes.
    """
    __tablename__ = 'identity_provider_mappers'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Parent IdP
    identity_provider_id = Column(String(36), db.ForeignKey('identity_providers.id', ondelete='CASCADE'), 
                                 nullable=False, index=True)
    
    # Mapper name and type
    name = Column(String(255), nullable=False)
    identity_provider_mapper = Column(String(255), nullable=False)  # e.g., 'oidc-user-attribute-idp-mapper'
    
    # Configuration (JSON)
    config = Column(JSON, default=dict)
    
    # Relationship
    identity_provider = relationship('IdentityProvider', back_populates='mappers')
    
    def __repr__(self):
        return f'<IdentityProviderMapper {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'identityProviderAlias': self.identity_provider.alias if self.identity_provider else None,
            'identityProviderMapper': self.identity_provider_mapper,
            'config': self.config or {},
        }


class FederatedIdentity(db.Model):
    """
    Federated Identity - Links a user to an external identity provider account.
    """
    __tablename__ = 'federated_identities'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # User
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Identity provider
    identity_provider = Column(String(255), nullable=False, index=True)  # alias
    realm_id = Column(String(36), nullable=False, index=True)
    
    # External user info
    federated_user_id = Column(String(255), nullable=False)  # ID from external provider
    federated_username = Column(String(255), nullable=True)
    
    # Token (if stored)
    token = Column(Text, nullable=True)
    
    # Relationship
    user = relationship('User', back_populates='federated_identities')
    
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'identity_provider', 'federated_user_id', 
                           name='uq_federated_identity'),
        db.Index('ix_federated_identity_user', 'user_id', 'identity_provider'),
    )
    
    def __repr__(self):
        return f'<FederatedIdentity {self.identity_provider}:{self.federated_user_id}>'
    
    @classmethod
    def find_by_federated_identity(cls, realm_id, provider_alias, federated_user_id):
        """Find by external identity"""
        return cls.query.filter_by(
            realm_id=realm_id,
            identity_provider=provider_alias,
            federated_user_id=federated_user_id
        ).first()
    
    def to_dict(self):
        return {
            'identityProvider': self.identity_provider,
            'userId': self.federated_user_id,
            'userName': self.federated_username,
        }
