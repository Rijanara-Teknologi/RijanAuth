# -*- encoding: utf-8 -*-
"""
RijanAuth - Seeding Configuration
Environment-based configuration for database seeding
"""

import os
import secrets


class SeedingConfig:
    """Configuration for database seeding"""
    
    # Admin user configuration
    ADMIN_USERNAME = os.getenv('RIJANAUTH_ADMIN_USER', 'admin')
    ADMIN_EMAIL = os.getenv('RIJANAUTH_ADMIN_EMAIL', 'admin@localhost')
    ADMIN_PASSWORD = os.getenv('RIJANAUTH_ADMIN_PASSWORD', None)  # None = auto-generate
    
    # Master realm configuration
    MASTER_REALM_NAME = os.getenv('RIJANAUTH_MASTER_REALM_NAME', 'master')
    
    # Skip seeding (for testing/migrations)
    SKIP_INITIAL_SEED = os.getenv('RIJANAUTH_SKIP_INITIAL_SEED', 'false').lower() == 'true'
    
    # Token lifespans (in seconds)
    ACCESS_TOKEN_LIFESPAN = 300  # 5 minutes
    REFRESH_TOKEN_LIFESPAN = 1800  # 30 minutes
    SSO_SESSION_IDLE = 1800  # 30 minutes
    SSO_SESSION_MAX = 28800  # 8 hours
    
    # Security settings
    SETUP_TOKEN_VALIDITY_HOURS = 24
    INITIAL_PASSWORD_LENGTH = 32
    
    # Event retention (in days)
    ADMIN_EVENTS_RETENTION_DAYS = 180
    LOGIN_EVENTS_RETENTION_DAYS = 90
    
    @classmethod
    def generate_secure_password(cls, length=None):
        """Generate a cryptographically secure password"""
        if length is None:
            length = cls.INITIAL_PASSWORD_LENGTH
        # Use secrets module for cryptographic security
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @classmethod
    def generate_setup_token(cls):
        """Generate a secure setup token"""
        return secrets.token_urlsafe(48)
