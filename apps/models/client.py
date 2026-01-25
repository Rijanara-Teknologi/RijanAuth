# -*- encoding: utf-8 -*-
"""
RijanAuth - Client Model
OAuth 2.0 / OpenID Connect client applications
"""

from sqlalchemy import Column, String, Boolean, Integer, Text, JSON
from sqlalchemy.orm import relationship
from apps.models.base import RealmScopedModel, generate_uuid
from apps import db


class Client(RealmScopedModel):
    """
    Client - An OAuth 2.0 / OpenID Connect client application.
    Mirrors Keycloak's client model with full OIDC support.
    """
    __tablename__ = 'clients'
    
    # Client Identifier (OAuth client_id)
    client_id = Column(String(255), nullable=False, index=True)
    
    # Display name
    name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    
    # Client secret for confidential clients
    secret = Column(String(255), nullable=True)
    
    # Client type
    public_client = Column(Boolean, default=False)  # True for public clients (no secret)
    bearer_only = Column(Boolean, default=False)  # True for bearer-only clients
    consent_required = Column(Boolean, default=False)
    
    # Standard flow enabled (Authorization Code Flow)
    standard_flow_enabled = Column(Boolean, default=True)
    
    # Implicit flow enabled
    implicit_flow_enabled = Column(Boolean, default=False)
    
    # Direct access grants (Resource Owner Password Credentials)
    direct_access_grants_enabled = Column(Boolean, default=False)
    
    # Service accounts (Client Credentials Flow)
    service_accounts_enabled = Column(Boolean, default=False)
    
    # OAuth 2.0 Device Authorization Grant
    oauth2_device_authorization_grant_enabled = Column(Boolean, default=False)
    
    # Protocol: openid-connect, saml
    protocol = Column(String(50), default='openid-connect')
    
    # URLs
    root_url = Column(String(1024), nullable=True)
    base_url = Column(String(1024), nullable=True)
    admin_url = Column(String(1024), nullable=True)
    
    # Redirect URIs (JSON array)
    redirect_uris = Column(JSON, default=list)
    
    # Web origins for CORS (JSON array)
    web_origins = Column(JSON, default=list)
    
    # Enabled
    enabled = Column(Boolean, default=True)
    
    # Always display in consent screen
    always_display_in_console = Column(Boolean, default=False)
    
    # Client authentication method
    client_authenticator_type = Column(String(50), default='client-secret')
    
    # Token settings
    access_token_lifespan = Column(Integer, nullable=True)  # Override realm default
    
    # Frontchannel/Backchannel logout
    frontchannel_logout = Column(Boolean, default=False)
    backchannel_logout_url = Column(String(1024), nullable=True)
    backchannel_logout_session_required = Column(Boolean, default=True)
    backchannel_logout_revoke_offline_tokens = Column(Boolean, default=False)
    
    # Full scope allowed (inherits all realm roles)
    full_scope_allowed = Column(Boolean, default=True)
    
    # Node re-registration timeout (for clustered clients)
    node_re_registration_timeout = Column(Integer, default=-1)
    
    # Registration access token
    registration_access_token = Column(String(255), nullable=True)
    
    # Surrogate auth required (for impersonation)
    surrogate_auth_required = Column(Boolean, default=False)
    
    # Default client scopes (JSON array of scope IDs)
    default_client_scopes = Column(JSON, default=list)
    
    # Optional client scopes (JSON array of scope IDs)  
    optional_client_scopes = Column(JSON, default=list)
    
    # Attributes (JSON object)
    attributes = Column(JSON, default=dict)
    
    # Relationships
    realm = relationship('Realm', back_populates='clients')
    roles = relationship('Role', back_populates='client', cascade='all, delete-orphan', lazy='dynamic')
    scopes = relationship('ClientScopeMapping', back_populates='client', cascade='all, delete-orphan', lazy='dynamic')
    protocol_mappers = relationship('ProtocolMapper', back_populates='client', cascade='all, delete-orphan', lazy='dynamic')
    
    # Unique constraint: client_id unique within realm
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'client_id', name='uq_client_client_id'),
    )
    
    def __repr__(self):
        return f'<Client {self.client_id}>'
    
    @classmethod
    def find_by_client_id(cls, realm_id, client_id):
        """Find a client by its client_id within a realm"""
        return cls.query.filter_by(realm_id=realm_id, client_id=client_id).first()
    
    def validate_redirect_uri(self, redirect_uri):
        """Validate a redirect URI against allowed URIs"""
        if not self.redirect_uris:
            return False
        
        for pattern in self.redirect_uris:
            if pattern == redirect_uri:
                return True
            # Handle wildcard patterns
            if pattern.endswith('*'):
                if redirect_uri.startswith(pattern[:-1]):
                    return True
        return False
    
    def validate_secret(self, secret):
        """Validate the client secret"""
        if self.public_client:
            return True  # Public clients don't need secret validation
        return self.secret == secret
    
    def to_dict(self):
        """Serialize client to dictionary"""
        return {
            'id': self.id,
            'clientId': self.client_id,
            'name': self.name,
            'description': self.description,
            'rootUrl': self.root_url,
            'baseUrl': self.base_url,
            'adminUrl': self.admin_url,
            'surrogateAuthRequired': self.surrogate_auth_required,
            'enabled': self.enabled,
            'alwaysDisplayInConsole': self.always_display_in_console,
            'clientAuthenticatorType': self.client_authenticator_type,
            'redirectUris': self.redirect_uris or [],
            'webOrigins': self.web_origins or [],
            'bearerOnly': self.bearer_only,
            'consentRequired': self.consent_required,
            'standardFlowEnabled': self.standard_flow_enabled,
            'implicitFlowEnabled': self.implicit_flow_enabled,
            'directAccessGrantsEnabled': self.direct_access_grants_enabled,
            'serviceAccountsEnabled': self.service_accounts_enabled,
            'publicClient': self.public_client,
            'frontchannelLogout': self.frontchannel_logout,
            'protocol': self.protocol,
            'attributes': self.attributes or {},
            'fullScopeAllowed': self.full_scope_allowed,
            'nodeReRegistrationTimeout': self.node_re_registration_timeout,
            'defaultClientScopes': self.default_client_scopes or [],
            'optionalClientScopes': self.optional_client_scopes or [],
        }


class ClientScope(RealmScopedModel):
    """
    Client Scope - Defines a set of protocol mappers and role scope mappings.
    Can be assigned to clients as default or optional scopes.
    """
    __tablename__ = 'client_scopes'
    
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    protocol = Column(String(50), default='openid-connect')
    
    # Scope attributes (JSON)
    attributes = Column(JSON, default=dict)
    
    # Relationships
    protocol_mappers = relationship('ProtocolMapper', back_populates='client_scope', cascade='all, delete-orphan', lazy='dynamic')
    
    # Unique constraint
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'name', name='uq_client_scope_name'),
    )
    
    def __repr__(self):
        return f'<ClientScope {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'protocol': self.protocol,
            'attributes': self.attributes or {},
        }


class ClientScopeMapping(db.Model):
    """
    Mapping between clients and client scopes.
    """
    __tablename__ = 'client_scope_mappings'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    client_id = Column(String(36), db.ForeignKey('clients.id', ondelete='CASCADE'), nullable=False, index=True)
    scope_id = Column(String(36), db.ForeignKey('client_scopes.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Whether this is a default scope (always included) or optional (must be requested)
    default_scope = Column(Boolean, default=True)
    
    # Relationships
    client = relationship('Client', back_populates='scopes')
    scope = relationship('ClientScope')
    
    __table_args__ = (
        db.UniqueConstraint('client_id', 'scope_id', name='uq_client_scope_mapping'),
    )


class ProtocolMapper(db.Model):
    """
    Protocol Mapper - Defines how claims are added to tokens.
    Can be attached to a client or client scope.
    
    Mapper Types:
    - oidc-usermodel-attribute-mapper: Maps user attributes to token claims
    - oidc-hardcoded-claim-mapper: Adds hardcoded values to tokens
    - oidc-usermodel-realm-role-mapper: Maps realm roles to token claims
    - oidc-usermodel-client-role-mapper: Maps client roles to token claims
    - oidc-group-membership-mapper: Maps group memberships to token claims
    - oidc-audience-mapper: Adds audience claims
    - oidc-full-name-mapper: Maps full name to token
    """
    __tablename__ = 'protocol_mappers'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Name and protocol
    name = Column(String(255), nullable=False)
    protocol = Column(String(50), default='openid-connect')
    
    # Mapper type (e.g., 'oidc-usermodel-attribute-mapper', 'oidc-hardcoded-claim-mapper')
    protocol_mapper = Column(String(255), nullable=False)
    
    # Parent - either client or client_scope
    client_id = Column(String(36), db.ForeignKey('clients.id', ondelete='CASCADE'), nullable=True, index=True)
    client_scope_id = Column(String(36), db.ForeignKey('client_scopes.id', ondelete='CASCADE'), nullable=True, index=True)
    
    # Configuration (JSON object)
    # Common config keys:
    # - claim.name: Name of the claim in the token
    # - claim.value: Hardcoded value (for hardcoded mapper)
    # - user.attribute: User attribute to map (for attribute mapper)
    # - access.token.claim: "true"/"false" - include in access token
    # - id.token.claim: "true"/"false" - include in ID token
    # - userinfo.token.claim: "true"/"false" - include in userinfo response
    # - jsonType.label: Data type (String, int, boolean, JSON)
    # - multivalued: "true"/"false" - is this a multi-valued claim
    config = Column(JSON, default=dict)
    
    # Priority for ordering (lower = processed first)
    priority = Column(Integer, default=0, nullable=False)
    
    # Consent text (shown when consent is required)
    consent_text = Column(String(255), nullable=True)
    
    # Relationships
    client = relationship('Client', back_populates='protocol_mappers')
    client_scope = relationship('ClientScope', back_populates='protocol_mappers')
    
    # Protected claims that cannot be overridden
    PROTECTED_CLAIMS = {'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'auth_time', 'nonce', 'acr', 'azp', 'typ'}
    
    # Valid mapper types
    MAPPER_TYPES = {
        'oidc-usermodel-attribute-mapper': 'User Attribute',
        'oidc-hardcoded-claim-mapper': 'Hardcoded Claim',
        'oidc-usermodel-realm-role-mapper': 'User Realm Role',
        'oidc-usermodel-client-role-mapper': 'User Client Role',
        'oidc-group-membership-mapper': 'Group Membership',
        'oidc-audience-mapper': 'Audience',
        'oidc-full-name-mapper': 'Full Name',
        'oidc-address-mapper': 'Address',
    }
    
    def __repr__(self):
        return f'<ProtocolMapper {self.name} ({self.protocol_mapper})>'
    
    @classmethod
    def find_by_client(cls, client_id):
        """Get all mappers for a client"""
        return cls.query.filter_by(client_id=client_id).order_by(cls.priority).all()
    
    @classmethod
    def find_by_client_scope(cls, client_scope_id):
        """Get all mappers for a client scope"""
        return cls.query.filter_by(client_scope_id=client_scope_id).order_by(cls.priority).all()
    
    def applies_to_token_type(self, token_type: str) -> bool:
        """Check if this mapper should apply to the given token type"""
        config = self.config or {}
        
        if token_type == 'access':
            return config.get('access.token.claim', 'true') == 'true'
        elif token_type == 'id':
            return config.get('id.token.claim', 'true') == 'true'
        elif token_type == 'userinfo':
            return config.get('userinfo.token.claim', 'true') == 'true'
        
        return True
    
    def get_claim_name(self) -> str:
        """Get the claim name from config"""
        return self.config.get('claim.name', '')
    
    def is_claim_protected(self) -> bool:
        """Check if this mapper tries to override a protected claim"""
        claim_name = self.get_claim_name()
        return claim_name in self.PROTECTED_CLAIMS
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'protocol': self.protocol,
            'protocolMapper': self.protocol_mapper,
            'protocolMapperLabel': self.MAPPER_TYPES.get(self.protocol_mapper, self.protocol_mapper),
            'consentRequired': False,
            'consentText': self.consent_text,
            'config': self.config or {},
            'priority': self.priority,
            'clientId': self.client_id,
            'clientScopeId': self.client_scope_id,
        }
