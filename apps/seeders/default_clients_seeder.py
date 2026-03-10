# -*- encoding: utf-8 -*-
"""
RijanAuth - Default Clients Seeder
Creates essential system clients for administration and account management
"""

import secrets
from apps import db
from apps.models.client import Client, ClientScope
from apps.models.base import generate_uuid


def seed_default_clients(realm):
    """
    Create essential system clients required for administration
    and account management.
    """
    print(f'[SEEDER] Creating default clients for realm: {realm.name}')
    
    # Check if clients already exist
    existing = Client.find_by_client_id(realm.id, 'admin-cli')
    if existing:
        print(f'[SEEDER] Default clients already exist, skipping...')
        return
    
    # 1. Admin CLI client
    admin_cli = create_admin_cli_client(realm)
    
    # 2. Account console client
    account_console = create_account_console_client(realm)
    
    # 3. Security admin console
    security_admin = create_security_admin_console_client(realm)
    
    # 4. Broker client for identity brokering
    broker = create_broker_client(realm)
    
    # Internal RijanAuth service client
    internal = create_internal_service_client(realm)
    
    db.session.commit()
    
    print(f'[SEEDER] Default clients created successfully')
    print(f'[SEEDER]   - admin-cli (public)')
    print(f'[SEEDER]   - account-console (public)')
    print(f'[SEEDER]   - security-admin-console (public)')
    print(f'[SEEDER]   - broker (confidential)')
    print(f'[SEEDER]   - rijanauth-internal (bearer-only)')


def create_admin_cli_client(realm):
    """Create the admin CLI client for command-line administration"""
    client = Client(
        realm_id=realm.id,
        client_id='admin-cli',
        name='Admin CLI',
        description='Command-line administration client',
        protocol='openid-connect',
        
        # Access type: public
        public_client=True,
        bearer_only=False,
        
        # Enabled
        enabled=True,
        
        # Flows
        standard_flow_enabled=False,
        implicit_flow_enabled=False,
        direct_access_grants_enabled=True,
        service_accounts_enabled=False,
        
        # No redirects needed for CLI
        redirect_uris=[],
        web_origins=[],
        
        # Full scope allowed
        full_scope_allowed=True,
    )
    db.session.add(client)
    db.session.flush()
    return client


def create_account_console_client(realm):
    """Create the account console client for user self-service"""
    client = Client(
        realm_id=realm.id,
        client_id='account-console',
        name='Account Console',
        description='User account management console',
        protocol='openid-connect',
        
        # Access type: public
        public_client=True,
        bearer_only=False,
        
        # Enabled
        enabled=True,
        
        # Flows
        standard_flow_enabled=True,
        implicit_flow_enabled=False,
        direct_access_grants_enabled=False,
        service_accounts_enabled=False,
        
        # Redirect URIs
        root_url='/realms/master/account/',
        base_url='/realms/master/account/',
        redirect_uris=['/realms/*/account/*'],
        web_origins=['+'],  # Allow from same origin
        
        # Full scope
        full_scope_allowed=True,
    )
    db.session.add(client)
    db.session.flush()
    return client


def create_security_admin_console_client(realm):
    """Create the security admin console client"""
    client = Client(
        realm_id=realm.id,
        client_id='security-admin-console',
        name='Security Admin Console',
        description='Administration console for RijanAuth',
        protocol='openid-connect',
        
        # Access type: public
        public_client=True,
        bearer_only=False,
        
        # Enabled
        enabled=True,
        
        # Flows
        standard_flow_enabled=True,
        implicit_flow_enabled=False,
        direct_access_grants_enabled=False,
        service_accounts_enabled=False,
        
        # Redirect URIs
        root_url='/admin/',
        base_url='/admin/master/console/',
        redirect_uris=['/admin/*'],
        web_origins=['+'],
        
        # Full scope
        full_scope_allowed=True,
    )
    db.session.add(client)
    db.session.flush()
    return client


def create_broker_client(realm):
    """Create the broker client for identity brokering"""
    client = Client(
        realm_id=realm.id,
        client_id='broker',
        name='Broker',
        description='Identity brokering client',
        protocol='openid-connect',
        
        # Access type: confidential
        public_client=False,
        bearer_only=False,
        secret=secrets.token_urlsafe(32),
        
        # Enabled
        enabled=True,
        
        # Flows
        standard_flow_enabled=False,
        implicit_flow_enabled=False,
        direct_access_grants_enabled=False,
        service_accounts_enabled=False,
        
        # No redirects
        redirect_uris=[],
        web_origins=[],
        
        # Full scope
        full_scope_allowed=True,
    )
    db.session.add(client)
    db.session.flush()
    return client


def create_internal_service_client(realm):
    """Create the internal RijanAuth service client"""
    client = Client(
        realm_id=realm.id,
        client_id='rijanauth-internal',
        name='RijanAuth Internal',
        description='Internal service client for RijanAuth operations',
        protocol='openid-connect',
        
        # Access type: bearer-only
        public_client=False,
        bearer_only=True,
        secret=secrets.token_urlsafe(32),
        
        # Enabled
        enabled=True,
        
        # Flows - service accounts
        standard_flow_enabled=False,
        implicit_flow_enabled=False,
        direct_access_grants_enabled=False,
        service_accounts_enabled=True,
        
        # No redirects
        redirect_uris=[],
        web_origins=[],
        
        # Full scope
        full_scope_allowed=True,
    )
    db.session.add(client)
    db.session.flush()
    return client
