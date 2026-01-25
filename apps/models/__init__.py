# -*- encoding: utf-8 -*-
"""
RijanAuth - Models Package
Keycloak-compatible data models for identity and access management
"""

from apps.models.realm import Realm, RealmAttribute
from apps.models.user import User, UserAttribute, Credential
from apps.models.role import Role, RoleMapping
from apps.models.group import Group, GroupMembership, GroupRoleMapping
from apps.models.client import Client, ClientScope, ClientScopeMapping, ProtocolMapper
from apps.models.session import UserSession, AuthenticatedClientSession
from apps.models.identity_provider import IdentityProvider, IdentityProviderMapper, FederatedIdentity
from apps.models.authentication import AuthenticationFlow, AuthenticationExecution, RequiredAction
from apps.models.event import Event, AdminEvent
from apps.models.federation import (
    UserFederationProvider, UserFederationMapper, UserFederationLink, FederationSyncLog
)

__all__ = [
    # Realm
    'Realm', 'RealmAttribute',
    # User
    'User', 'UserAttribute', 'Credential',
    # Role
    'Role', 'RoleMapping',
    # Group
    'Group', 'GroupMembership', 'GroupRoleMapping',
    # Client
    'Client', 'ClientScope', 'ClientScopeMapping', 'ProtocolMapper',
    # Session
    'UserSession', 'AuthenticatedClientSession',
    # Identity Provider
    'IdentityProvider', 'IdentityProviderMapper', 'FederatedIdentity',
    # Authentication
    'AuthenticationFlow', 'AuthenticationExecution', 'RequiredAction',
    # Event
    'Event', 'AdminEvent',
    # User Federation
    'UserFederationProvider', 'UserFederationMapper', 'UserFederationLink', 'FederationSyncLog',
]
