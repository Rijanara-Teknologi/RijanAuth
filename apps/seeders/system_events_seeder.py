# -*- encoding: utf-8 -*-
"""
RijanAuth - System Events Seeder
Configures system event settings for audit logging
"""

from apps import db
from config.seeding import SeedingConfig


def seed_system_events(realm):
    """
    Configure system event settings for audit logging.
    Enables both admin and login event tracking with retention policies.
    """
    print(f'[SEEDER] Configuring system events for realm: {realm.name}')
    
    # Enable events
    realm.events_enabled = True
    realm.admin_events_enabled = True
    realm.admin_events_details_enabled = True
    
    # Set retention (in seconds)
    realm.events_expiration = SeedingConfig.LOGIN_EVENTS_RETENTION_DAYS * 86400
    
    # Configure included event types (matching Keycloak defaults)
    realm.enabled_event_types = [
        # Login events
        'LOGIN',
        'LOGIN_ERROR',
        'LOGOUT',
        'LOGOUT_ERROR',
        'REGISTER',
        'REGISTER_ERROR',
        
        # Token events
        'CODE_TO_TOKEN',
        'CODE_TO_TOKEN_ERROR',
        'REFRESH_TOKEN',
        'REFRESH_TOKEN_ERROR',
        'INTROSPECT_TOKEN',
        'INTROSPECT_TOKEN_ERROR',
        
        # User info events
        'USER_INFO_REQUEST',
        'USER_INFO_REQUEST_ERROR',
        
        # Client events
        'CLIENT_LOGIN',
        'CLIENT_LOGIN_ERROR',
        
        # Identity provider events
        'IDENTITY_PROVIDER_LOGIN',
        'IDENTITY_PROVIDER_LOGIN_ERROR',
        'IDENTITY_PROVIDER_FIRST_LOGIN',
        'IDENTITY_PROVIDER_POST_LOGIN',
        'IDENTITY_PROVIDER_LINK_ACCOUNT',
        
        # Account events
        'UPDATE_EMAIL',
        'UPDATE_EMAIL_ERROR',
        'UPDATE_PROFILE',
        'UPDATE_PROFILE_ERROR',
        'UPDATE_PASSWORD',
        'UPDATE_PASSWORD_ERROR',
        'UPDATE_TOTP',
        'UPDATE_TOTP_ERROR',
        'REMOVE_TOTP',
        'REMOVE_TOTP_ERROR',
        
        # Reset credential events
        'SEND_RESET_PASSWORD',
        'SEND_RESET_PASSWORD_ERROR',
        'RESET_PASSWORD',
        'RESET_PASSWORD_ERROR',
        
        # Verification events
        'VERIFY_EMAIL',
        'VERIFY_EMAIL_ERROR',
        'SEND_VERIFY_EMAIL',
        'SEND_VERIFY_EMAIL_ERROR',
        
        # Federated identity events
        'FEDERATED_IDENTITY_LINK',
        'FEDERATED_IDENTITY_LINK_ERROR',
        'REMOVE_FEDERATED_IDENTITY',
        'REMOVE_FEDERATED_IDENTITY_ERROR',
        
        # Consent events
        'GRANT_CONSENT',
        'GRANT_CONSENT_ERROR',
        'UPDATE_CONSENT',
        'UPDATE_CONSENT_ERROR',
        'REVOKE_GRANT',
        'REVOKE_GRANT_ERROR',
        
        # Token revocation
        'TOKEN_REVOKE',
        'TOKEN_REVOKE_ERROR',
        
        # Permission events
        'PERMISSION_TOKEN',
        'PERMISSION_TOKEN_ERROR',
    ]
    
    db.session.commit()
    
    print(f'[SEEDER] System events configured successfully')
    print(f'[SEEDER]   - Login events: enabled ({SeedingConfig.LOGIN_EVENTS_RETENTION_DAYS} days retention)')
    print(f'[SEEDER]   - Admin events: enabled ({SeedingConfig.ADMIN_EVENTS_RETENTION_DAYS} days retention)')
    print(f'[SEEDER]   - Event types: {len(realm.enabled_event_types)} configured')
