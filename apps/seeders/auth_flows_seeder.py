# -*- encoding: utf-8 -*-
"""
RijanAuth - Authentication Flow Seeder
Creates default authentication flows with all required executions
"""

from apps import db
from apps.models.authentication import AuthenticationFlow, AuthenticationExecution, AuthenticatorConfig


def seed_authentication_flows(realm):
    """
    Create all standard Keycloak authentication flows.
    These define how users authenticate to the system.
    """
    print(f'[SEEDER] Creating authentication flows for realm: {realm.name}')
    
    # Check if flows already exist
    existing = AuthenticationFlow.query.filter_by(realm_id=realm.id, alias='browser').first()
    if existing:
        print(f'[SEEDER] Authentication flows already exist, skipping...')
        return
    
    # 1. Browser flow (main login flow)
    browser_flow = create_browser_flow(realm)
    
    # 2. Registration flow
    registration_flow = create_registration_flow(realm)
    
    # 3. Reset credentials flow
    reset_flow = create_reset_credentials_flow(realm)
    
    # 4. Direct grant flow (Resource Owner Password Credentials)
    direct_grant_flow = create_direct_grant_flow(realm)
    
    # 5. Client authentication flow
    client_auth_flow = create_client_auth_flow(realm)
    
    # 6. First broker login flow
    first_broker_flow = create_first_broker_login_flow(realm)
    
    # Set browser flow as default for realm
    realm.browser_flow_id = browser_flow.id
    realm.registration_flow_id = registration_flow.id
    realm.reset_credentials_flow_id = reset_flow.id
    realm.direct_grant_flow_id = direct_grant_flow.id
    realm.client_authentication_flow_id = client_auth_flow.id
    
    db.session.commit()
    
    print(f'[SEEDER] Authentication flows created successfully')
    print(f'[SEEDER]   - Browser flow: {browser_flow.alias}')
    print(f'[SEEDER]   - Registration flow: {registration_flow.alias}')
    print(f'[SEEDER]   - Reset credentials flow: {reset_flow.alias}')
    print(f'[SEEDER]   - Direct grant flow: {direct_grant_flow.alias}')
    print(f'[SEEDER]   - Client auth flow: {client_auth_flow.alias}')


def create_browser_flow(realm):
    """Create the browser authentication flow"""
    flow = AuthenticationFlow(
        realm_id=realm.id,
        alias='browser',
        description='Browser-based authentication',
        provider_id='basic-flow',
        top_level=True,
        built_in=True
    )
    db.session.add(flow)
    db.session.flush()
    
    # Execution 1: Cookie authentication (checks existing session)
    cookie_exec = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='auth-cookie',
        requirement='ALTERNATIVE',
        priority=10,
        authenticator_flow=False
    )
    db.session.add(cookie_exec)
    
    # Execution 2: Identity provider redirector
    idp_exec = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='identity-provider-redirector',
        requirement='ALTERNATIVE',
        priority=20,
        authenticator_flow=False
    )
    db.session.add(idp_exec)
    
    # Execution 3: Username/password form (sub-flow)
    forms_subflow = AuthenticationFlow(
        realm_id=realm.id,
        alias='browser-forms',
        description='Username, password, OTP',
        provider_id='basic-flow',
        top_level=False,
        built_in=True
    )
    db.session.add(forms_subflow)
    db.session.flush()
    
    forms_exec = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        flow_alias='browser-forms',
        requirement='ALTERNATIVE',
        priority=30,
        authenticator_flow=True
    )
    db.session.add(forms_exec)
    
    # Sub-execution: Username/password
    username_pass = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=forms_subflow.id,
        authenticator='auth-username-password-form',
        requirement='REQUIRED',
        priority=10,
        authenticator_flow=False
    )
    db.session.add(username_pass)
    
    # Sub-execution: OTP (optional)
    otp_exec = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=forms_subflow.id,
        authenticator='auth-otp-form',
        requirement='OPTIONAL',
        priority=20,
        authenticator_flow=False
    )
    db.session.add(otp_exec)
    
    return flow


def create_registration_flow(realm):
    """Create the registration flow"""
    flow = AuthenticationFlow(
        realm_id=realm.id,
        alias='registration',
        description='Registration flow',
        provider_id='basic-flow',
        top_level=True,
        built_in=True
    )
    db.session.add(flow)
    db.session.flush()
    
    # Registration form
    reg_form = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='registration-page-form',
        requirement='REQUIRED',
        priority=10,
        authenticator_flow=False
    )
    db.session.add(reg_form)
    
    return flow


def create_reset_credentials_flow(realm):
    """Create the reset credentials flow"""
    flow = AuthenticationFlow(
        realm_id=realm.id,
        alias='reset-credentials',
        description='Reset credentials',
        provider_id='basic-flow',
        top_level=True,
        built_in=True
    )
    db.session.add(flow)
    db.session.flush()
    
    # Choose user execution
    choose_user = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='reset-credentials-choose-user',
        requirement='REQUIRED',
        priority=10,
        authenticator_flow=False
    )
    db.session.add(choose_user)
    
    # Send reset email
    send_email = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='reset-credential-email',
        requirement='REQUIRED',
        priority=20,
        authenticator_flow=False
    )
    db.session.add(send_email)
    
    # Reset password
    reset_pass = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='reset-password',
        requirement='REQUIRED',
        priority=30,
        authenticator_flow=False
    )
    db.session.add(reset_pass)
    
    return flow


def create_direct_grant_flow(realm):
    """Create the direct grant (ROPC) flow"""
    flow = AuthenticationFlow(
        realm_id=realm.id,
        alias='direct-grant',
        description='Direct access grants',
        provider_id='basic-flow',
        top_level=True,
        built_in=True
    )
    db.session.add(flow)
    db.session.flush()
    
    # Validate username
    validate_user = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='direct-grant-validate-username',
        requirement='REQUIRED',
        priority=10,
        authenticator_flow=False
    )
    db.session.add(validate_user)
    
    # Validate password
    validate_pass = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='direct-grant-validate-password',
        requirement='REQUIRED',
        priority=20,
        authenticator_flow=False
    )
    db.session.add(validate_pass)
    
    # Validate OTP (optional)
    validate_otp = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='direct-grant-validate-otp',
        requirement='OPTIONAL',
        priority=30,
        authenticator_flow=False
    )
    db.session.add(validate_otp)
    
    return flow


def create_client_auth_flow(realm):
    """Create the client authentication flow"""
    flow = AuthenticationFlow(
        realm_id=realm.id,
        alias='clients',
        description='Client authentication',
        provider_id='client-flow',
        top_level=True,
        built_in=True
    )
    db.session.add(flow)
    db.session.flush()
    
    # Client secret
    client_secret = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='client-secret',
        requirement='ALTERNATIVE',
        priority=10,
        authenticator_flow=False
    )
    db.session.add(client_secret)
    
    # Client JWT
    client_jwt = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='client-jwt',
        requirement='ALTERNATIVE',
        priority=20,
        authenticator_flow=False
    )
    db.session.add(client_jwt)
    
    return flow


def create_first_broker_login_flow(realm):
    """Create the first broker login flow (for identity federation)"""
    flow = AuthenticationFlow(
        realm_id=realm.id,
        alias='first-broker-login',
        description='Actions taken after first broker login',
        provider_id='basic-flow',
        top_level=True,
        built_in=True
    )
    db.session.add(flow)
    db.session.flush()
    
    # Review profile
    review_profile = AuthenticationExecution(
        realm_id=realm.id,
        flow_id=flow.id,
        authenticator='idp-review-profile',
        requirement='REQUIRED',
        priority=10,
        authenticator_flow=False
    )
    db.session.add(review_profile)
    
    return flow
