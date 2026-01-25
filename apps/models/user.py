# -*- encoding: utf-8 -*-
"""
RijanAuth - User Model
User accounts with Keycloak-compatible attributes and credentials
"""

from datetime import datetime
from sqlalchemy import Column, String, Boolean, Integer, Text, DateTime, LargeBinary, JSON
from sqlalchemy.orm import relationship
from apps.models.base import RealmScopedModel, generate_uuid
from apps import db


class User(RealmScopedModel):
    """
    User - An authenticated user within a realm.
    Mirrors Keycloak's user model with all standard attributes.
    """
    __tablename__ = 'users'
    
    # Basic Info
    username = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=True, index=True)
    email_verified = Column(Boolean, default=False)
    first_name = Column(String(255), nullable=True)
    last_name = Column(String(255), nullable=True)
    
    # Status
    enabled = Column(Boolean, default=True, nullable=False)
    
    # TOTP/MFA
    totp_enabled = Column(Boolean, default=False)
    
    # Timestamps
    email_constraint = Column(String(255), nullable=True)
    
    # Federation
    federation_link = Column(String(36), nullable=True)
    service_account_client_link = Column(String(36), nullable=True)
    
    # Required Actions (JSON array of action names)
    required_actions = Column(JSON, default=list)
    
    # Locale preference
    locale = Column(String(50), nullable=True)
    
    # Relationships
    realm = relationship('Realm', back_populates='users')
    attributes = relationship('UserAttribute', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')
    credentials = relationship('Credential', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')
    role_mappings = relationship('RoleMapping', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')
    group_memberships = relationship('GroupMembership', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')
    sessions = relationship('UserSession', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')
    federated_identities = relationship('FederatedIdentity', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')
    
    # Unique constraint: username unique within realm
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'username', name='uq_user_username'),
        db.Index('ix_user_email_realm', 'realm_id', 'email'),
    )
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def full_name(self):
        """Get user's full name"""
        parts = [self.first_name, self.last_name]
        return ' '.join(p for p in parts if p) or self.username
    
    @classmethod
    def find_by_id(cls, user_id):
        """Find user by ID"""
        return cls.query.get(user_id)
    
    @classmethod
    def find_by_username(cls, realm_id, username):
        """Find user by username within a realm"""
        return cls.query.filter_by(realm_id=realm_id, username=username).first()
    
    @classmethod
    def find_by_email(cls, realm_id, email):
        """Find user by email within a realm"""
        return cls.query.filter_by(realm_id=realm_id, email=email).first()
    
    @classmethod
    def find_by_username_or_email(cls, realm_id, identifier):
        """Find user by username or email"""
        return cls.query.filter(
            cls.realm_id == realm_id,
            db.or_(cls.username == identifier, cls.email == identifier)
        ).first()
    
    def get_attribute(self, name):
        """Get a single attribute value"""
        attr = self.attributes.filter_by(name=name).first()
        return attr.value if attr else None
    
    def set_attribute(self, name, value):
        """Set an attribute value"""
        attr = self.attributes.filter_by(name=name).first()
        if attr:
            attr.value = value
        else:
            attr = UserAttribute(user_id=self.id, name=name, value=value)
            db.session.add(attr)
        db.session.commit()
    
    def get_password_credential(self):
        """Get the user's password credential"""
        return self.credentials.filter_by(type='password').first()
    
    def has_role(self, role_name, client_id=None):
        """Check if user has a specific role"""
        from apps.models.role import Role
        query = self.role_mappings.join(Role)
        if client_id:
            query = query.filter(Role.client_id == client_id, Role.name == role_name)
        else:
            query = query.filter(Role.client_id.is_(None), Role.name == role_name)
        return query.first() is not None
    
    def to_dict(self, include_attributes=False):
        """Serialize user to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'emailVerified': self.email_verified,
            'firstName': self.first_name,
            'lastName': self.last_name,
            'enabled': self.enabled,
            'totp': self.totp_enabled,
            'createdTimestamp': int(self.created_at.timestamp() * 1000) if self.created_at else None,
            'requiredActions': self.required_actions or [],
        }
        if include_attributes:
            data['attributes'] = {
                attr.name: [attr.value] for attr in self.attributes
            }
        return data


class UserAttribute(db.Model):
    """
    Key-value attributes for users.
    Supports multi-valued attributes (multiple rows with same name).
    """
    __tablename__ = 'user_attributes'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    value = Column(Text, nullable=True)
    
    # Relationship
    user = relationship('User', back_populates='attributes')
    
    # Index for efficient lookups
    __table_args__ = (
        db.Index('ix_user_attr_name_value', 'name', 'value', mysql_length={'value': 255}),
    )
    
    def __repr__(self):
        return f'<UserAttribute {self.name}={self.value}>'


class Credential(db.Model):
    """
    User credentials (passwords, OTP secrets, etc.)
    Supports multiple credential types like Keycloak.
    """
    __tablename__ = 'credentials'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Credential type: 'password', 'otp', 'webauthn', etc.
    type = Column(String(50), nullable=False)
    
    # For password: the hashed password
    # For OTP: the secret key
    secret_data = Column(Text, nullable=True)
    
    # Additional credential data (JSON)
    # For password: algorithm, iterations, salt
    # For OTP: algorithm, digits, counter, period
    credential_data = Column(JSON, nullable=True)
    
    # User-friendly label for the credential
    user_label = Column(String(255), nullable=True)
    
    # Priority for ordering
    priority = Column(Integer, default=10)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    user = relationship('User', back_populates='credentials')
    
    def __repr__(self):
        return f'<Credential {self.type} for user {self.user_id}>'
    
    @classmethod
    def create_password(cls, user_id, hashed_password, algorithm='bcrypt', iterations=None):
        """Create a password credential"""
        credential_data = {'algorithm': algorithm}
        if iterations:
            credential_data['iterations'] = iterations
        
        return cls(
            user_id=user_id,
            type='password',
            secret_data=hashed_password,
            credential_data=credential_data
        )
    
    @classmethod
    def create_otp(cls, user_id, secret, algorithm='HmacSHA1', digits=6, period=30):
        """Create an OTP credential"""
        return cls(
            user_id=user_id,
            type='otp',
            secret_data=secret,
            credential_data={
                'algorithm': algorithm,
                'digits': digits,
                'period': period,
                'type': 'totp'
            }
        )
