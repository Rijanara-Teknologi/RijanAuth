# -*- encoding: utf-8 -*-
"""
RijanAuth - Realm Model
Multi-tenancy isolation: all entities belong to a realm
"""

from sqlalchemy import Column, String, Boolean, Integer, Text, JSON
from sqlalchemy.orm import relationship
from apps.models.base import BaseModel, generate_uuid
from apps import db


class Realm(BaseModel):
    """
    Realm - The root of multi-tenancy in RijanAuth.
    Each realm is completely isolated with its own users, clients, roles, etc.
    Mirrors Keycloak's realm functionality.
    """
    __tablename__ = 'realms'
    
    # Basic Info
    name = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    display_name_html = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    
    # SSL Settings
    ssl_required = Column(String(50), default='external')  # 'all', 'external', 'none'
    
    # Registration & Login Settings
    registration_allowed = Column(Boolean, default=False)
    registration_email_as_username = Column(Boolean, default=False)
    remember_me = Column(Boolean, default=False)
    verify_email = Column(Boolean, default=False)
    login_with_email_allowed = Column(Boolean, default=True)
    duplicate_emails_allowed = Column(Boolean, default=False)
    reset_password_allowed = Column(Boolean, default=False)
    edit_username_allowed = Column(Boolean, default=False)
    
    # Brute Force Protection
    brute_force_protected = Column(Boolean, default=False)
    permanent_lockout = Column(Boolean, default=False)
    max_failure_wait_seconds = Column(Integer, default=900)  # 15 minutes
    minimum_quick_login_wait_seconds = Column(Integer, default=60)
    wait_increment_seconds = Column(Integer, default=60)
    quick_login_check_milli_seconds = Column(Integer, default=1000)
    max_delta_time_seconds = Column(Integer, default=43200)  # 12 hours
    failure_factor = Column(Integer, default=30)
    max_login_failures = Column(Integer, default=30)  # Alias for failure_factor
    max_temporary_lockouts = Column(Integer, default=0)
    
    # Token Settings
    default_signature_algorithm = Column(String(50), default='RS256')
    access_token_lifespan = Column(Integer, default=300)  # 5 minutes
    access_token_lifespan_for_implicit_flow = Column(Integer, default=900)  # 15 minutes
    sso_session_idle_timeout = Column(Integer, default=1800)  # 30 minutes
    sso_session_max_lifespan = Column(Integer, default=36000)  # 10 hours
    offline_session_idle_timeout = Column(Integer, default=2592000)  # 30 days
    offline_session_max_lifespan_enabled = Column(Boolean, default=False)
    offline_session_max_lifespan = Column(Integer, default=5184000)  # 60 days
    access_code_lifespan = Column(Integer, default=60)  # 1 minute
    access_code_lifespan_user_action = Column(Integer, default=300)  # 5 minutes
    access_code_lifespan_login = Column(Integer, default=1800)  # 30 minutes
    action_token_generated_by_admin_lifespan = Column(Integer, default=43200)  # 12 hours
    action_token_generated_by_user_lifespan = Column(Integer, default=300)  # 5 minutes
    
    # Refresh Token Settings
    refresh_token_max_reuse = Column(Integer, default=0)
    revoke_refresh_token = Column(Boolean, default=False)
    
    # OTP/TOTP Settings
    otp_policy_type = Column(String(50), default='totp')
    otp_policy_algorithm = Column(String(50), default='HmacSHA1')
    otp_policy_initial_counter = Column(Integer, default=0)
    otp_policy_digits = Column(Integer, default=6)
    otp_policy_look_ahead_window = Column(Integer, default=1)
    otp_policy_period = Column(Integer, default=30)
    
    # WebAuthn Settings
    webauthn_policy_rp_entity_name = Column(String(255), default='keycloak')
    webauthn_policy_rp_id = Column(String(255), nullable=True)
    webauthn_policy_signature_algorithms = Column(JSON, default=list)
    webauthn_policy_attestation_conveyance_preference = Column(String(50), default='not specified')
    webauthn_policy_authenticator_attachment = Column(String(50), default='not specified')
    webauthn_policy_require_resident_key = Column(String(50), default='not specified')
    webauthn_policy_user_verification_requirement = Column(String(50), default='not specified')
    webauthn_policy_create_timeout = Column(Integer, default=0)
    webauthn_policy_avoid_same_authenticator_register = Column(Boolean, default=False)
    
    # SMTP Settings
    smtp_server = Column(String(255), nullable=True)
    smtp_port = Column(String(10), nullable=True)
    smtp_from = Column(String(255), nullable=True)
    smtp_from_display_name = Column(String(255), nullable=True)
    smtp_reply_to = Column(String(255), nullable=True)
    smtp_reply_to_display_name = Column(String(255), nullable=True)
    smtp_ssl = Column(Boolean, default=False)
    smtp_starttls = Column(Boolean, default=False)
    smtp_auth = Column(Boolean, default=False)
    smtp_user = Column(String(255), nullable=True)
    smtp_password = Column(String(255), nullable=True)
    
    # Theme Settings
    login_theme = Column(String(255), nullable=True)
    account_theme = Column(String(255), nullable=True)
    admin_theme = Column(String(255), nullable=True)
    email_theme = Column(String(255), nullable=True)
    
    # Internationalization
    internationalization_enabled = Column(Boolean, default=False)
    supported_locales = Column(JSON, default=list)
    default_locale = Column(String(50), nullable=True)
    
    # Events
    events_enabled = Column(Boolean, default=True)
    events_expiration = Column(Integer, default=0)
    events_listeners = Column(JSON, default=list)
    enabled_event_types = Column(JSON, default=list)
    admin_events_enabled = Column(Boolean, default=True)
    admin_events_details_enabled = Column(Boolean, default=False)
    
    # Browser Security Headers
    browser_security_headers = Column(JSON, nullable=True)
    
    # Password Policy
    password_policy = Column(Text, nullable=True)
    
    # Authentication Flow References
    browser_flow_id = Column(String(36), nullable=True)
    registration_flow_id = Column(String(36), nullable=True)
    direct_grant_flow_id = Column(String(36), nullable=True)
    reset_credentials_flow_id = Column(String(36), nullable=True)
    client_authentication_flow_id = Column(String(36), nullable=True)
    docker_authentication_flow_id = Column(String(36), nullable=True)
    
    # Default Roles
    default_role_id = Column(String(36), nullable=True)
    
    # Relationships
    attributes = relationship('RealmAttribute', back_populates='realm', cascade='all, delete-orphan', lazy='dynamic')
    users = relationship('User', back_populates='realm', cascade='all, delete-orphan', lazy='dynamic')
    clients = relationship('Client', back_populates='realm', cascade='all, delete-orphan', lazy='dynamic')
    roles = relationship('Role', back_populates='realm', cascade='all, delete-orphan', lazy='dynamic')
    groups = relationship('Group', back_populates='realm', cascade='all, delete-orphan', lazy='dynamic')
    identity_providers = relationship('IdentityProvider', back_populates='realm', cascade='all, delete-orphan', lazy='dynamic')
    authentication_flows = relationship('AuthenticationFlow', back_populates='realm', cascade='all, delete-orphan', lazy='dynamic')
    
    def __repr__(self):
        return f'<Realm {self.name}>'
    
    @classmethod
    def find_by_name(cls, name):
        """Find a realm by its name"""
        return cls.query.filter_by(name=name).first()
    
    @classmethod
    def get_master_realm(cls):
        """Get the master realm"""
        return cls.find_by_name('master')
    
    @classmethod
    def create_master_realm(cls):
        """Create the master realm if it doesn't exist"""
        master = cls.get_master_realm()
        if master is None:
            master = cls(
                name='master',
                display_name='Master Realm',
                enabled=True,
                registration_allowed=False,
                reset_password_allowed=True,
                verify_email=False,
                login_with_email_allowed=True,
                brute_force_protected=True
            )
            master.save()
        return master
    
    def to_dict(self):
        """Serialize realm to dictionary"""
        return {
            'id': self.id,
            'realm': self.name,
            'displayName': self.display_name,
            'displayNameHtml': self.display_name_html,
            'enabled': self.enabled,
            'sslRequired': self.ssl_required,
            'registrationAllowed': self.registration_allowed,
            'registrationEmailAsUsername': self.registration_email_as_username,
            'rememberMe': self.remember_me,
            'verifyEmail': self.verify_email,
            'loginWithEmailAllowed': self.login_with_email_allowed,
            'duplicateEmailsAllowed': self.duplicate_emails_allowed,
            'resetPasswordAllowed': self.reset_password_allowed,
            'editUsernameAllowed': self.edit_username_allowed,
            'bruteForceProtected': self.brute_force_protected,
            'accessTokenLifespan': self.access_token_lifespan,
            'ssoSessionIdleTimeout': self.sso_session_idle_timeout,
            'ssoSessionMaxLifespan': self.sso_session_max_lifespan,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'updatedAt': self.updated_at.isoformat() if self.updated_at else None,
        }


class RealmAttribute(db.Model):
    """
    Key-value attributes for realms.
    Allows storing custom realm configuration.
    """
    __tablename__ = 'realm_attributes'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    value = Column(Text, nullable=True)
    
    # Relationship
    realm = relationship('Realm', back_populates='attributes')
    
    # Unique constraint on realm + name
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'name', name='uq_realm_attribute'),
    )
    
    def __repr__(self):
        return f'<RealmAttribute {self.name}={self.value}>'
