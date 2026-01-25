# -*- encoding: utf-8 -*-
"""
RijanAuth - Authentication Model
Authentication flows and required actions
"""

from sqlalchemy import Column, String, Boolean, Integer, Text, JSON
from sqlalchemy.orm import relationship
from apps.models.base import RealmScopedModel, generate_uuid
from apps import db


class AuthenticationFlow(RealmScopedModel):
    """
    Authentication Flow - Defines the sequence of authentication steps.
    Mirrors Keycloak's authentication flow model.
    """
    __tablename__ = 'authentication_flows'
    
    # Flow alias (unique name)
    alias = Column(String(255), nullable=False, index=True)
    
    # Description
    description = Column(Text, nullable=True)
    
    # Provider ID (e.g., 'basic-flow', 'form-flow', 'client-flow')
    provider_id = Column(String(50), default='basic-flow')
    
    # Top level flow flag
    top_level = Column(Boolean, default=False)
    
    # Built-in flow (cannot be deleted)
    built_in = Column(Boolean, default=False)
    
    # Relationships
    realm = relationship('Realm', back_populates='authentication_flows')
    executions = relationship('AuthenticationExecution', back_populates='flow', 
                             cascade='all, delete-orphan', lazy='dynamic',
                             order_by='AuthenticationExecution.priority')
    
    # Unique constraint
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'alias', name='uq_auth_flow_alias'),
    )
    
    def __repr__(self):
        return f'<AuthenticationFlow {self.alias}>'
    
    @classmethod
    def find_by_alias(cls, realm_id, alias):
        """Find a flow by alias"""
        return cls.query.filter_by(realm_id=realm_id, alias=alias).first()
    
    @classmethod
    def get_browser_flow(cls, realm_id):
        """Get the browser authentication flow"""
        return cls.find_by_alias(realm_id, 'browser')
    
    @classmethod
    def get_direct_grant_flow(cls, realm_id):
        """Get the direct grant (password) flow"""
        return cls.find_by_alias(realm_id, 'direct grant')
    
    def to_dict(self):
        return {
            'id': self.id,
            'alias': self.alias,
            'description': self.description,
            'providerId': self.provider_id,
            'topLevel': self.top_level,
            'builtIn': self.built_in,
            'authenticationExecutions': [e.to_dict() for e in self.executions]
        }


class AuthenticationExecution(db.Model):
    """
    Authentication Execution - A step in an authentication flow.
    """
    __tablename__ = 'authentication_executions'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Parent flow
    flow_id = Column(String(36), db.ForeignKey('authentication_flows.id', ondelete='CASCADE'), 
                    nullable=False, index=True)
    
    # Realm (denormalized for easier queries)
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Authenticator (e.g., 'auth-username-password-form', 'auth-otp-form')
    authenticator = Column(String(255), nullable=True)
    
    # Sub-flow reference (if this execution is a sub-flow)
    flow_alias = Column(String(255), nullable=True)
    
    # Requirement: DISABLED, ALTERNATIVE, REQUIRED, CONDITIONAL
    requirement = Column(String(50), default='DISABLED')
    
    # Priority (order in the flow)
    priority = Column(Integer, default=0)
    
    # Authenticator config ID
    authenticator_config_id = Column(String(36), nullable=True)
    
    # Authenticator flow flag (if this points to another flow)
    authenticator_flow = Column(Boolean, default=False)
    
    # Relationship
    flow = relationship('AuthenticationFlow', back_populates='executions')
    
    def __repr__(self):
        return f'<AuthenticationExecution {self.authenticator or self.flow_alias}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'requirement': self.requirement,
            'priority': self.priority,
            'authenticator': self.authenticator,
            'flowAlias': self.flow_alias if self.authenticator_flow else None,
            'authenticatorFlow': self.authenticator_flow,
            'authenticatorConfig': self.authenticator_config_id,
        }


class AuthenticatorConfig(db.Model):
    """
    Authenticator Config - Configuration for an authenticator.
    """
    __tablename__ = 'authenticator_configs'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Realm
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Alias
    alias = Column(String(255), nullable=True)
    
    # Configuration (JSON)
    config = Column(JSON, default=dict)
    
    def __repr__(self):
        return f'<AuthenticatorConfig {self.alias}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'alias': self.alias,
            'config': self.config or {},
        }


class RequiredAction(db.Model):
    """
    Required Action - Actions required of a user (e.g., update password, verify email).
    """
    __tablename__ = 'required_actions'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Realm
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Action alias (e.g., 'VERIFY_EMAIL', 'UPDATE_PASSWORD', 'CONFIGURE_TOTP')
    alias = Column(String(255), nullable=False)
    
    # Display name
    name = Column(String(255), nullable=True)
    
    # Provider ID
    provider_id = Column(String(255), nullable=False)
    
    # Enabled
    enabled = Column(Boolean, default=True)
    
    # Default action (automatically added to new users)
    default_action = Column(Boolean, default=False)
    
    # Priority
    priority = Column(Integer, default=0)
    
    # Configuration (JSON)
    config = Column(JSON, default=dict)
    
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'alias', name='uq_required_action_alias'),
    )
    
    def __repr__(self):
        return f'<RequiredAction {self.alias}>'
    
    @classmethod
    def get_default_actions(cls, realm_id):
        """Get all default required actions for a realm"""
        return cls.query.filter_by(
            realm_id=realm_id,
            enabled=True,
            default_action=True
        ).order_by(cls.priority).all()
    
    def to_dict(self):
        return {
            'alias': self.alias,
            'name': self.name,
            'providerId': self.provider_id,
            'enabled': self.enabled,
            'defaultAction': self.default_action,
            'priority': self.priority,
            'config': self.config or {},
        }
