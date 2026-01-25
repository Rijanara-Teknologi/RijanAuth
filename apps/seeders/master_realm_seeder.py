# -*- encoding: utf-8 -*-
"""
RijanAuth - Master Realm Seeder
Creates the foundational "master" realm for managing all other realms
"""

from datetime import datetime
from apps import db
from apps.models.realm import Realm
from config.seeding import SeedingConfig


def seed_master_realm():
    """
    Create the master realm with all Keycloak-compatible settings.
    The master realm is used for administering RijanAuth itself.
    """
    print(f'[SEEDER] Creating master realm: {SeedingConfig.MASTER_REALM_NAME}')
    
    # Check if master realm already exists
    existing = Realm.find_by_name(SeedingConfig.MASTER_REALM_NAME)
    if existing:
        print(f'[SEEDER] Master realm already exists, skipping...')
        return existing
    
    # Create master realm with Keycloak-compatible defaults
    master_realm = Realm(
        name=SeedingConfig.MASTER_REALM_NAME,
        display_name='Master',
        display_name_html='<div class="kc-logo-text"><span>RijanAuth</span></div>',
        enabled=True,
        
        # Registration settings
        registration_allowed=False,
        registration_email_as_username=False,
        
        # Login settings
        remember_me=True,
        verify_email=False,
        reset_password_allowed=True,
        edit_username_allowed=False,
        login_with_email_allowed=True,
        duplicate_emails_allowed=False,
        
        # Brute force protection
        brute_force_protected=True,
        max_failure_wait_seconds=900,  # 15 minutes
        minimum_quick_login_wait_seconds=60,
        wait_increment_seconds=60,
        quick_login_check_milli_seconds=1000,
        max_delta_time_seconds=43200,  # 12 hours
        max_login_failures=30,
        
        # SSL/TLS requirements
        ssl_required='external',
        
        # Token lifespans
        access_token_lifespan=SeedingConfig.ACCESS_TOKEN_LIFESPAN,
        access_token_lifespan_for_implicit_flow=900,  # 15 minutes
        
        # SSO Session settings
        sso_session_idle_timeout=SeedingConfig.SSO_SESSION_IDLE,
        sso_session_max_lifespan=SeedingConfig.SSO_SESSION_MAX,
        
        # Offline session settings
        offline_session_idle_timeout=2592000,  # 30 days
        offline_session_max_lifespan_enabled=False,
        
        # Access code settings
        access_code_lifespan=60,
        access_code_lifespan_user_action=300,
        access_code_lifespan_login=1800,
        
        # Action token settings
        action_token_generated_by_admin_lifespan=43200,  # 12 hours
        action_token_generated_by_user_lifespan=300,  # 5 minutes
        
        # Refresh token settings
        refresh_token_max_reuse=0,
        revoke_refresh_token=False,
        
        # User authentication settings
        otp_policy_type='totp',
        otp_policy_algorithm='HmacSHA1',
        otp_policy_initial_counter=0,
        otp_policy_digits=6,
        otp_policy_look_ahead_window=1,
        otp_policy_period=30,
        
        # Password policy (will be parsed by policy engine)
        password_policy='hashIterations(27500)',
        
        # Browser headers
        browser_security_headers={
            'contentSecurityPolicyReportOnly': '',
            'xContentTypeOptions': 'nosniff',
            'xRobotsTag': 'none',
            'xFrameOptions': 'SAMEORIGIN',
            'contentSecurityPolicy': "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
            'xXSSProtection': '1; mode=block',
            'strictTransportSecurity': 'max-age=31536000; includeSubDomains'
        },
        
        # SMTP settings (empty by default, configure via UI)
        smtp_server=None,
        smtp_port=None,
        smtp_from=None,
        smtp_from_display_name='RijanAuth',
        smtp_ssl=False,
        smtp_starttls=True,
        smtp_auth=False,
        smtp_user=None,
        smtp_password=None,
        
        # Events settings
        events_enabled=True,
        events_expiration=SeedingConfig.LOGIN_EVENTS_RETENTION_DAYS * 86400,
        admin_events_enabled=True,
        admin_events_details_enabled=True,
        
        # Internationalization
        internationalization_enabled=False,
        supported_locales=['en'],
        default_locale='en',
    )
    
    db.session.add(master_realm)
    db.session.commit()
    
    print(f'[SEEDER] Master realm created successfully')
    print(f'[SEEDER]   - Brute force protection: enabled')
    print(f'[SEEDER]   - Max login failures: 30')
    print(f'[SEEDER]   - SSO session max: {SeedingConfig.SSO_SESSION_MAX // 3600} hours')
    
    return master_realm
