# -*- encoding: utf-8 -*-
"""
RijanAuth - Session Model
User sessions and authenticated client sessions
"""

from datetime import datetime
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from apps.models.base import generate_uuid
from apps import db


class UserSession(db.Model):
    """
    User Session - Represents an authenticated user session.
    Tracks SSO sessions across multiple clients.
    """
    __tablename__ = 'user_sessions'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Realm and user
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Session info
    login_username = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    auth_method = Column(String(50), nullable=True)  # e.g., 'password', 'otp', 'social'
    
    # Remember me flag
    remember_me = Column(Boolean, default=False)
    
    # Session state
    state = Column(String(50), default='ACTIVE')  # ACTIVE, LOGGED_OUT, EXPIRED
    
    # Broker session ID (for federated login)
    broker_session_id = Column(String(255), nullable=True)
    broker_user_id = Column(String(255), nullable=True)
    
    # Timestamps
    started = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_session_refresh = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Notes (JSON) - for storing arbitrary session data
    notes = Column(JSON, default=dict)
    
    # Relationships
    user = relationship('User', back_populates='sessions')
    authenticated_clients = relationship('AuthenticatedClientSession', back_populates='user_session', 
                                        cascade='all, delete-orphan', lazy='dynamic')
    
    __table_args__ = (
        db.Index('ix_user_session_realm_user', 'realm_id', 'user_id'),
    )
    
    def __repr__(self):
        return f'<UserSession {self.id} for user {self.user_id}>'
    
    @classmethod
    def find_active_sessions(cls, realm_id, user_id):
        """Find all active sessions for a user"""
        return cls.query.filter_by(
            realm_id=realm_id,
            user_id=user_id,
            state='ACTIVE'
        ).all()
    
    @classmethod
    def find_by_realm(cls, realm_id):
        """Find all active sessions in a realm"""
        return cls.query.filter_by(realm_id=realm_id, state='ACTIVE').all()
    
    def refresh(self):
        """Refresh the session timestamp"""
        self.last_session_refresh = datetime.utcnow()
        db.session.commit()
    
    def logout(self):
        """Mark session as logged out"""
        self.state = 'LOGGED_OUT'
        db.session.commit()
    
    def is_expired(self, idle_timeout, max_lifespan):
        """Check if session is expired based on realm settings"""
        now = datetime.utcnow()
        
        # Check idle timeout
        idle_delta = (now - self.last_session_refresh).total_seconds()
        if idle_delta > idle_timeout:
            return True
        
        # Check max lifespan
        lifespan_delta = (now - self.started).total_seconds()
        if lifespan_delta > max_lifespan:
            return True
        
        return False
    
    def to_dict(self):
        """Serialize session to dictionary"""
        return {
            'id': self.id,
            'username': self.login_username,
            'userId': self.user_id,
            'ipAddress': self.ip_address,
            'start': int(self.started.timestamp() * 1000) if self.started else None,
            'lastAccess': int(self.last_session_refresh.timestamp() * 1000) if self.last_session_refresh else None,
            'rememberMe': self.remember_me,
            'clients': {
                cs.client_id: cs.client.client_id if cs.client else cs.client_id 
                for cs in self.authenticated_clients
            }
        }


class AuthenticatedClientSession(db.Model):
    """
    Authenticated Client Session - Tracks which clients a user has authenticated to
    within a user session.
    """
    __tablename__ = 'authenticated_client_sessions'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Parent session
    user_session_id = Column(String(36), db.ForeignKey('user_sessions.id', ondelete='CASCADE'), 
                            nullable=False, index=True)
    
    # Client
    client_id = Column(String(36), db.ForeignKey('clients.id', ondelete='CASCADE'), 
                      nullable=False, index=True)
    
    # Redirect URI used
    redirect_uri = Column(String(1024), nullable=True)
    
    # Action (e.g., 'AUTHENTICATE', 'CONSENT')
    action = Column(String(50), nullable=True)
    
    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Notes
    notes = Column(JSON, default=dict)
    
    # Relationships
    user_session = relationship('UserSession', back_populates='authenticated_clients')
    client = relationship('Client')
    
    __table_args__ = (
        db.UniqueConstraint('user_session_id', 'client_id', name='uq_client_session'),
    )
    
    def __repr__(self):
        return f'<AuthenticatedClientSession {self.client_id}>'


class RefreshToken(db.Model):
    """
    Refresh Token - Stored refresh tokens for token refresh flow.
    """
    __tablename__ = 'refresh_tokens'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Token value (hashed)
    token = Column(String(255), unique=True, nullable=False, index=True)
    
    # Associated entities
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    client_id = Column(String(36), db.ForeignKey('clients.id', ondelete='CASCADE'), nullable=False, index=True)
    user_session_id = Column(String(36), db.ForeignKey('user_sessions.id', ondelete='CASCADE'), nullable=True)
    
    # Scope
    scope = Column(Text, nullable=True)
    
    # Offline token flag
    offline = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    
    # Revocation
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f'<RefreshToken {self.id}>'
    
    def is_expired(self):
        """Check if token is expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def revoke(self):
        """Revoke this refresh token"""
        self.revoked = True
        self.revoked_at = datetime.utcnow()
        db.session.commit()


class AuthorizationCode(db.Model):
    """
    Authorization Code - Short-lived codes for OAuth authorization code flow.
    """
    __tablename__ = 'authorization_codes'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # The authorization code
    code = Column(String(255), unique=True, nullable=False, index=True)
    
    # Associated entities
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    client_id = Column(String(36), db.ForeignKey('clients.id', ondelete='CASCADE'), nullable=False, index=True)
    user_session_id = Column(String(36), db.ForeignKey('user_sessions.id', ondelete='CASCADE'), nullable=True)
    
    # Redirect URI (must match on token exchange)
    redirect_uri = Column(String(1024), nullable=False)
    
    # Scope requested
    scope = Column(Text, nullable=True)
    
    # PKCE
    code_challenge = Column(String(255), nullable=True)
    code_challenge_method = Column(String(10), nullable=True)  # 'S256' or 'plain'
    
    # Nonce for OIDC
    nonce = Column(String(255), nullable=True)
    
    # State
    state = Column(String(255), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    # Used flag (codes are single-use)
    used = Column(Boolean, default=False)
    
    def __repr__(self):
        return f'<AuthorizationCode {self.id}>'
    
    def is_expired(self):
        """Check if code is expired"""
        return datetime.utcnow() > self.expires_at
    
    def mark_used(self):
        """Mark code as used"""
        self.used = True
        db.session.commit()
