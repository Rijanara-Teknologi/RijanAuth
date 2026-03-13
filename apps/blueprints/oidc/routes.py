# -*- encoding: utf-8 -*-
"""
RijanAuth - OIDC Routes
OpenID Connect 1.0 Protocol Implementation
"""

import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse, parse_qs

from flask import (
    request, jsonify, redirect, url_for, render_template,
    current_app, session, make_response
)
from flask_login import current_user, login_user

from apps.blueprints.oidc import oidc_bp
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.client import Client
from apps.models.session import AuthorizationCode, RefreshToken, UserSession, AuthenticatedClientSession
from apps.utils.crypto import generate_token, create_jwt, decode_jwt
from apps import db


# =============================================================================
# OpenID Connect Discovery
# =============================================================================

@oidc_bp.route('/<realm_name>/.well-known/openid-configuration', methods=['GET'])
def openid_configuration(realm_name):
    """
    OpenID Connect Discovery Endpoint
    Returns the OpenID Provider Configuration
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    base_url = request.url_root.rstrip('/')
    realm_url = f"{base_url}/auth/realms/{realm_name}"
    
    config = {
        "issuer": realm_url,
        "authorization_endpoint": f"{realm_url}/protocol/openid-connect/auth",
        "token_endpoint": f"{realm_url}/protocol/openid-connect/token",
        "userinfo_endpoint": f"{realm_url}/protocol/openid-connect/userinfo",
        "end_session_endpoint": f"{realm_url}/protocol/openid-connect/logout",
        "jwks_uri": f"{realm_url}/protocol/openid-connect/certs",
        "introspection_endpoint": f"{realm_url}/protocol/openid-connect/token/introspect",
        "revocation_endpoint": f"{realm_url}/protocol/openid-connect/revoke",
        
        # Supported features
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token"
        ],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "password",
            "client_credentials"
        ],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time",
            "name", "given_name", "family_name", "preferred_username",
            "email", "email_verified", "locale", "picture"
        ],
        "scopes_supported": [
            "openid", "profile", "email", "address", "phone",
            "offline_access", "roles"
        ],
        "code_challenge_methods_supported": ["plain", "S256"]
    }
    
    return jsonify(config)


# =============================================================================
# Authorization Endpoint
# =============================================================================

@oidc_bp.route('/<realm_name>/protocol/openid-connect/auth', methods=['GET', 'POST'])
def authorize(realm_name):
    """
    OAuth 2.0 / OIDC Authorization Endpoint
    Handles authorization requests and user authentication
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'invalid_request', 'error_description': 'Realm not found'}), 400
    
    # Get authorization parameters
    client_id = request.args.get('client_id') or request.form.get('client_id')
    redirect_uri = request.args.get('redirect_uri') or request.form.get('redirect_uri')
    response_type = request.args.get('response_type', 'code') or request.form.get('response_type', 'code')
    scope = request.args.get('scope', 'openid') or request.form.get('scope', 'openid')
    state = request.args.get('state') or request.form.get('state')
    nonce = request.args.get('nonce') or request.form.get('nonce')
    code_challenge = request.args.get('code_challenge') or request.form.get('code_challenge')
    code_challenge_method = request.args.get('code_challenge_method', 'plain') or request.form.get('code_challenge_method', 'plain')
    
    # Validate required parameters
    if not client_id:
        return jsonify({'error': 'invalid_request', 'error_description': 'client_id is required'}), 400
    
    if not redirect_uri:
        return jsonify({'error': 'invalid_request', 'error_description': 'redirect_uri is required'}), 400
    
    # Find client
    client = Client.find_by_client_id(realm.id, client_id)
    if not client:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client not found'}), 400
    
    if not client.enabled:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client is disabled'}), 400
    
    # Validate redirect URI
    if not _validate_redirect_uri(client, redirect_uri):
        return jsonify({'error': 'invalid_request', 'error_description': 'Invalid redirect_uri'}), 400
    
    # If user is already authenticated, generate authorization code
    if current_user.is_authenticated and current_user.realm_id == realm.id:
        return _generate_auth_response(
            realm, client, current_user, redirect_uri, response_type,
            scope, state, nonce, code_challenge, code_challenge_method
        )
    
    # Handle POST (login form submission)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            user = User.find_by_username(realm.id, username)
            if not user:
                user = User.find_by_email(realm.id, username)
            
            if user and user.verify_password(password) and user.enabled:
                login_user(user, remember=True)
                return _generate_auth_response(
                    realm, client, user, redirect_uri, response_type,
                    scope, state, nonce, code_challenge, code_challenge_method
                )
            
            # Invalid credentials
            return render_template(
                'oidc/login.html',
                realm=realm,
                client=client,
                error='Invalid username or password',
                **request.args
            )
    
    # Show login form
    return render_template(
        'oidc/login.html',
        realm=realm,
        client=client,
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method
    )


def _validate_redirect_uri(client, redirect_uri):
    """Validate that the redirect URI is allowed for the client"""
    if not client.redirect_uris:
        return True  # Allow any if not configured
    
    allowed_uris = client.redirect_uris if isinstance(client.redirect_uris, list) else []
    
    # Check exact match or wildcard
    for allowed in allowed_uris:
        if allowed == redirect_uri:
            return True
        if allowed.endswith('*') and redirect_uri.startswith(allowed[:-1]):
            return True
    
    return len(allowed_uris) == 0  # Allow if no restrictions


def _generate_auth_response(realm, client, user, redirect_uri, response_type,
                            scope, state, nonce, code_challenge, code_challenge_method):
    """Generate authorization response based on response_type"""
    params = {}
    
    if state:
        params['state'] = state
    
    # Create or retrieve user session (SSO session)
    user_session = _get_or_create_user_session(realm, user)
    
    # Create authenticated client session to track this client
    _create_authenticated_client_session(user_session, client, redirect_uri)
    
    if 'code' in response_type:
        # Generate authorization code
        code = generate_token(32)
        
        auth_code = AuthorizationCode(
            code=code,
            realm_id=realm.id,
            client_id=client.id,
            user_id=user.id,
            user_session_id=user_session.id,  # Link to user session
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=datetime.utcnow() + timedelta(seconds=realm.access_code_lifespan)
        )
        db.session.add(auth_code)
        db.session.commit()
        
        params['code'] = code
    
    if 'token' in response_type:
        # Generate access token (implicit flow)
        access_token = _generate_access_token(realm, client, user, scope)
        params['access_token'] = access_token
        params['token_type'] = 'Bearer'
        params['expires_in'] = realm.access_token_lifespan
    
    if 'id_token' in response_type:
        # Generate ID token
        id_token = _generate_id_token(realm, client, user, nonce, scope)
        params['id_token'] = id_token
    
    # Build redirect URL
    separator = '#' if 'token' in response_type or 'id_token' in response_type else '?'
    redirect_url = f"{redirect_uri}{separator}{urlencode(params)}"
    
    return redirect(redirect_url)


def _get_or_create_user_session(realm, user):
    """Get existing active user session or create a new one"""
    # Check for existing active session
    existing_sessions = UserSession.find_active_sessions(realm.id, user.id)
    
    if existing_sessions:
        # Use the most recent active session
        user_session = existing_sessions[0]
        user_session.last_session_refresh = datetime.utcnow()
        db.session.commit()
        return user_session
    
    # Create new user session
    user_session = UserSession(
        realm_id=realm.id,
        user_id=user.id,
        login_username=user.username,
        ip_address=request.remote_addr,
        auth_method='password',
        remember_me=False,
        state='ACTIVE',
        started=datetime.utcnow(),
        last_session_refresh=datetime.utcnow()
    )
    db.session.add(user_session)
    db.session.commit()
    
    current_app.logger.info(f"Created SSO session for user {user.username}", extra={
        'user_id': user.id,
        'session_id': user_session.id,
        'realm_id': realm.id
    })
    
    return user_session


def _create_authenticated_client_session(user_session, client, redirect_uri):
    """Create or update authenticated client session"""
    # Check if client session already exists
    existing = AuthenticatedClientSession.query.filter_by(
        user_session_id=user_session.id,
        client_id=client.id
    ).first()
    
    if existing:
        # Update timestamp
        existing.timestamp = datetime.utcnow()
        existing.redirect_uri = redirect_uri
        db.session.commit()
        return existing
    
    # Create new authenticated client session
    client_session = AuthenticatedClientSession(
        user_session_id=user_session.id,
        client_id=client.id,
        redirect_uri=redirect_uri,
        action='AUTHENTICATE',
        timestamp=datetime.utcnow()
    )
    db.session.add(client_session)
    db.session.commit()
    
    return client_session


# =============================================================================
# Token Endpoint
# =============================================================================

@oidc_bp.route('/<realm_name>/protocol/openid-connect/token', methods=['POST'])
def token(realm_name):
    """
    OAuth 2.0 Token Endpoint
    Exchanges authorization codes for tokens, refreshes tokens, etc.
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'invalid_request', 'error_description': 'Realm not found'}), 400
    
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        return _handle_authorization_code_grant(realm)
    elif grant_type == 'refresh_token':
        return _handle_refresh_token_grant(realm)
    elif grant_type == 'password':
        return _handle_password_grant(realm)
    elif grant_type == 'client_credentials':
        return _handle_client_credentials_grant(realm)
    else:
        return jsonify({
            'error': 'unsupported_grant_type',
            'error_description': f'Grant type {grant_type} is not supported'
        }), 400


def _authenticate_client(realm):
    """Authenticate client from request"""
    # Try Basic auth first
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        try:
            credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
            client_id, client_secret = credentials.split(':', 1)
        except:
            return None, None
    else:
        # Try form parameters
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    
    if not client_id:
        return None, None
    
    client = Client.find_by_client_id(realm.id, client_id)
    if not client:
        return None, None
    
    # Public clients don't need secret verification
    if client.public_client:
        return client, True
    
    # Verify secret for confidential clients
    if client.secret == client_secret:
        return client, True
    
    return client, False


def _handle_authorization_code_grant(realm):
    """Handle authorization_code grant type"""
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    code_verifier = request.form.get('code_verifier')
    
    client, authenticated = _authenticate_client(realm)
    if not client:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    if not authenticated and not client.public_client:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    # Find and validate authorization code
    auth_code = AuthorizationCode.query.filter_by(code=code, client_id=client.id).first()
    if not auth_code:
        return jsonify({'error': 'invalid_grant', 'error_description': 'Invalid authorization code'}), 400
    
    if auth_code.is_expired():
        db.session.delete(auth_code)
        db.session.commit()
        return jsonify({'error': 'invalid_grant', 'error_description': 'Authorization code expired'}), 400
    
    if auth_code.used:
        return jsonify({'error': 'invalid_grant', 'error_description': 'Authorization code already used'}), 400
    
    if auth_code.redirect_uri != redirect_uri:
        return jsonify({'error': 'invalid_grant', 'error_description': 'redirect_uri mismatch'}), 400
    
    # Validate PKCE if code_challenge was provided
    if auth_code.code_challenge:
        if not code_verifier:
            return jsonify({'error': 'invalid_grant', 'error_description': 'code_verifier required'}), 400
        
        if auth_code.code_challenge_method == 'S256':
            computed = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip('=')
        else:
            computed = code_verifier
        
        if computed != auth_code.code_challenge:
            return jsonify({'error': 'invalid_grant', 'error_description': 'Invalid code_verifier'}), 400
    
    # Mark code as used
    auth_code.used = True
    db.session.commit()
    
    # Get user
    user = User.find_by_id(auth_code.user_id)
    if not user:
        return jsonify({'error': 'invalid_grant', 'error_description': 'User not found'}), 400
    
    # Refresh the user session if exists
    user_session_id = auth_code.user_session_id
    if user_session_id:
        user_session = UserSession.query.get(user_session_id)
        if user_session and user_session.state == 'ACTIVE':
            user_session.last_session_refresh = datetime.utcnow()
            db.session.commit()
    
    # Generate tokens
    scope = auth_code.scope or 'openid'
    access_token = _generate_access_token(realm, client, user, scope)
    refresh_token = _generate_refresh_token(realm, client, user, scope, user_session_id)
    
    response_data = {
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': realm.access_token_lifespan,
        'refresh_token': refresh_token,
        'refresh_expires_in': realm.sso_session_idle_timeout,
        'scope': scope
    }
    
    # Add session state for session management
    if user_session_id:
        response_data['session_state'] = user_session_id
    
    # Add ID token for openid scope
    if 'openid' in scope:
        response_data['id_token'] = _generate_id_token(realm, client, user, auth_code.nonce, scope)
    
    return jsonify(response_data)


def _handle_refresh_token_grant(realm):
    """Handle refresh_token grant type"""
    refresh_token_value = request.form.get('refresh_token')
    
    client, authenticated = _authenticate_client(realm)
    if not client:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    if not authenticated and not client.public_client:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    # Find refresh token
    refresh_token = RefreshToken.query.filter_by(token=refresh_token_value).first()
    if not refresh_token:
        return jsonify({'error': 'invalid_grant', 'error_description': 'Invalid refresh token'}), 400
    
    if refresh_token.is_expired():
        return jsonify({'error': 'invalid_grant', 'error_description': 'Refresh token expired'}), 400
    
    if refresh_token.revoked:
        return jsonify({'error': 'invalid_grant', 'error_description': 'Refresh token revoked'}), 400
    
    # Get user
    user = User.find_by_id(refresh_token.user_id)
    if not user or not user.enabled:
        return jsonify({'error': 'invalid_grant', 'error_description': 'User not found or disabled'}), 400
    
    # Refresh the user session if exists
    user_session_id = refresh_token.user_session_id
    if user_session_id:
        user_session = UserSession.query.get(user_session_id)
        if user_session and user_session.state == 'ACTIVE':
            user_session.last_session_refresh = datetime.utcnow()
            db.session.commit()
    
    # Generate new tokens
    scope = refresh_token.scope or 'openid'
    new_access_token = _generate_access_token(realm, client, user, scope)
    new_refresh_token = _generate_refresh_token(realm, client, user, scope, user_session_id)
    
    # Revoke old refresh token (optional - can be configurable)
    if realm.revoke_refresh_token:
        refresh_token.revoke()
    
    response_data = {
        'access_token': new_access_token,
        'token_type': 'Bearer',
        'expires_in': realm.access_token_lifespan,
        'refresh_token': new_refresh_token,
        'refresh_expires_in': realm.sso_session_idle_timeout,
        'scope': scope
    }
    
    if 'openid' in scope:
        response_data['id_token'] = _generate_id_token(realm, client, user, None, scope)
    
    return jsonify(response_data)


def _handle_password_grant(realm):
    """Handle password grant type (Resource Owner Password Credentials)"""
    username = request.form.get('username')
    password = request.form.get('password')
    scope = request.form.get('scope', 'openid')
    
    client, authenticated = _authenticate_client(realm)
    if not client:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    if not authenticated and not client.public_client:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    # Check if direct access grants enabled
    if not client.direct_access_grants_enabled:
        return jsonify({'error': 'unauthorized_client', 'error_description': 'Direct access grants not allowed'}), 400
    
    # Authenticate user - try local first
    user = User.find_by_username(realm.id, username)
    if not user:
        user = User.find_by_email(realm.id, username)
    
    user_authenticated = False
    
    if user:
        # Check if federated user
        if user.federation_link:
            # Try federation authentication
            try:
                from apps.services.federation import FederationService
                fed_user = FederationService.authenticate_federated(realm.id, username, password)
                if fed_user and fed_user.id == user.id:
                    user_authenticated = True
            except Exception as e:
                current_app.logger.error(f"Federation auth error in OIDC: {str(e)}")
        else:
            # Local user - verify password
            user_authenticated = user.verify_password(password)
    
    # If local auth failed, try federation providers (may create new user)
    if not user_authenticated:
        try:
            from apps.services.federation import FederationService
            fed_user = FederationService.authenticate_federated(realm.id, username, password)
            if fed_user:
                user = fed_user
                user_authenticated = True
        except Exception as e:
            current_app.logger.error(f"Federation auth error in OIDC: {str(e)}")
    
    if not user_authenticated or not user:
        return jsonify({'error': 'invalid_grant', 'error_description': 'Invalid username or password'}), 400
    
    if not user.enabled:
        return jsonify({'error': 'invalid_grant', 'error_description': 'User account is disabled'}), 400
    
    # Create user session for password grant
    user_session = _get_or_create_user_session(realm, user)
    
    # Create authenticated client session
    _create_authenticated_client_session(user_session, client, None)
    
    # Generate tokens
    access_token = _generate_access_token(realm, client, user, scope)
    refresh_token = _generate_refresh_token(realm, client, user, scope, user_session.id)
    
    response_data = {
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': realm.access_token_lifespan,
        'refresh_token': refresh_token,
        'refresh_expires_in': realm.sso_session_idle_timeout,
        'scope': scope,
        'session_state': user_session.id
    }
    
    if 'openid' in scope:
        response_data['id_token'] = _generate_id_token(realm, client, user, None, scope)
    
    return jsonify(response_data)


def _handle_client_credentials_grant(realm):
    """Handle client_credentials grant type"""
    scope = request.form.get('scope', '')
    
    client, authenticated = _authenticate_client(realm)
    if not client or not authenticated:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    if client.public_client:
        return jsonify({'error': 'unauthorized_client', 'error_description': 'Public clients cannot use client_credentials grant'}), 400
    
    if not client.service_accounts_enabled:
        return jsonify({'error': 'unauthorized_client', 'error_description': 'Service accounts not enabled for this client'}), 400
    
    # Generate access token for service account
    access_token = _generate_client_access_token(realm, client, scope)
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': realm.access_token_lifespan,
        'scope': scope
    })


# =============================================================================
# Token Generation Helpers
# =============================================================================

def _apply_standard_oidc_claims_fallback(payload, user, scope):
    """
    Ensure standard OIDC claims are present for the requested scopes.
    Called after protocol mappers run so that any claim already added by a
    mapper is never overwritten.
    """
    scope_list = scope.split() if scope else []
    if 'profile' in scope_list:
        if 'preferred_username' not in payload:
            payload['preferred_username'] = user.username
        if 'name' not in payload:
            full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
            if full_name:
                payload['name'] = full_name
        if 'given_name' not in payload and user.first_name:
            payload['given_name'] = user.first_name
        if 'family_name' not in payload and user.last_name:
            payload['family_name'] = user.last_name
    if 'email' in scope_list:
        if 'email' not in payload and user.email:
            payload['email'] = user.email
        if 'email_verified' not in payload:
            payload['email_verified'] = bool(user.email_verified)
    return payload


def _generate_access_token(realm, client, user, scope):
    """Generate JWT access token with protocol mapper processing"""
    from apps.services.mapper_service import MapperService
    
    base_url = request.url_root.rstrip('/')
    issuer = f"{base_url}/auth/realms/{realm.name}"
    
    now = datetime.utcnow()
    
    # Build base token with protected claims
    payload = {
        'exp': now + timedelta(seconds=realm.access_token_lifespan),
        'iat': now,
        'auth_time': int(now.timestamp()),
        'jti': generate_token(16),
        'iss': issuer,
        'aud': client.client_id,
        'sub': user.id,
        'typ': 'Bearer',
        'azp': client.client_id,
        'scope': scope,
    }
    
    # Apply protocol mappers to add custom claims
    try:
        payload = MapperService.apply_mappers(payload, user, client, 'access', scope)
    except Exception as e:
        current_app.logger.error(f"Error applying mappers to access token: {str(e)}")

    # Fallback: add standard OIDC claims for requested scopes when no mapper added them
    payload = _apply_standard_oidc_claims_fallback(payload, user, scope)

    return create_jwt(payload, current_app.config.get('SECRET_KEY', 'secret'))


def _generate_refresh_token(realm, client, user, scope, user_session_id=None):
    """Generate and store refresh token"""
    token_value = generate_token(64)
    
    refresh_token = RefreshToken(
        token=token_value,
        realm_id=realm.id,
        client_id=client.id,
        user_id=user.id,
        user_session_id=user_session_id,
        scope=scope,
        expires_at=datetime.utcnow() + timedelta(seconds=realm.sso_session_idle_timeout)
    )
    db.session.add(refresh_token)
    db.session.commit()
    
    return token_value


def _generate_id_token(realm, client, user, nonce, scope='openid'):
    """Generate OIDC ID Token with protocol mapper processing"""
    from apps.services.mapper_service import MapperService
    
    base_url = request.url_root.rstrip('/')
    issuer = f"{base_url}/auth/realms/{realm.name}"
    
    now = datetime.utcnow()
    
    # Build base token with protected claims
    payload = {
        'exp': now + timedelta(seconds=realm.access_token_lifespan),
        'iat': now,
        'auth_time': int(now.timestamp()),
        'jti': generate_token(16),
        'iss': issuer,
        'aud': client.client_id,
        'sub': user.id,
        'typ': 'ID',
        'azp': client.client_id,
    }
    
    if nonce:
        payload['nonce'] = nonce
    
    # Apply protocol mappers to add custom claims
    try:
        payload = MapperService.apply_mappers(payload, user, client, 'id', scope)
    except Exception as e:
        current_app.logger.error(f"Error applying mappers to ID token: {str(e)}")

    # Fallback: add standard OIDC claims for requested scopes when no mapper added them
    payload = _apply_standard_oidc_claims_fallback(payload, user, scope)

    return create_jwt(payload, current_app.config.get('SECRET_KEY', 'secret'))


def _generate_client_access_token(realm, client, scope):
    """Generate access token for client credentials grant"""
    base_url = request.url_root.rstrip('/')
    issuer = f"{base_url}/auth/realms/{realm.name}"
    
    now = datetime.utcnow()
    payload = {
        'exp': now + timedelta(seconds=realm.access_token_lifespan),
        'iat': now,
        'jti': generate_token(16),
        'iss': issuer,
        'aud': client.client_id,
        'sub': client.id,
        'typ': 'Bearer',
        'azp': client.client_id,
        'scope': scope,
        'clientId': client.client_id
    }
    
    return create_jwt(payload, current_app.config.get('SECRET_KEY', 'secret'))


# =============================================================================
# UserInfo Endpoint
# =============================================================================

@oidc_bp.route('/<realm_name>/protocol/openid-connect/userinfo', methods=['GET', 'POST'])
def userinfo(realm_name):
    """
    OIDC UserInfo Endpoint
    Returns claims about the authenticated user.
    Response must match the claims in the decoded JWT access token (excluding protected claims).
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'invalid_request', 'error_description': 'Realm not found'}), 400
    
    # Get access token from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'invalid_token', 'error_description': 'Bearer token required'}), 401
    
    access_token = auth_header[7:]
    
    # Decode and validate token
    try:
        token_payload = decode_jwt(access_token, current_app.config.get('SECRET_KEY', 'secret'))
    except Exception as e:
        return jsonify({'error': 'invalid_token', 'error_description': str(e)}), 401
    
    # Validate token expiration
    exp = token_payload.get('exp')
    if exp:
        if datetime.utcnow().timestamp() > exp:
            return jsonify({'error': 'invalid_token', 'error_description': 'Token expired'}), 401
    
    # Validate realm
    iss = token_payload.get('iss', '')
    if realm_name not in iss:
        return jsonify({'error': 'invalid_token', 'error_description': 'Token realm mismatch'}), 401
    
    # Get user to verify token is valid
    user_id = token_payload.get('sub')
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({'error': 'invalid_token', 'error_description': 'User not found'}), 401

    # Get scope and client from token to drive mapper selection
    scope = token_payload.get('scope', 'openid')
    client_id = token_payload.get('azp')
    token_client = Client.find_by_client_id(realm.id, client_id) if client_id else None

    # Build userinfo using protocol mappers (token_type='userinfo')
    from apps.services.mapper_service import MapperService
    userinfo_data = {'sub': str(user.id)}
    if token_client:
        try:
            userinfo_data = MapperService.apply_mappers(
                userinfo_data, user, token_client, 'userinfo', scope
            )
        except Exception as e:
            current_app.logger.error(f"Error applying mappers to userinfo: {str(e)}")

    # Fallback: add standard OIDC claims for requested scopes when no mapper added them
    userinfo_data = _apply_standard_oidc_claims_fallback(userinfo_data, user, scope)

    return jsonify(userinfo_data)


# =============================================================================
# Logout Endpoint
# =============================================================================

@oidc_bp.route('/<realm_name>/protocol/openid-connect/logout', methods=['GET', 'POST'])
def logout(realm_name):
    """
    OIDC Logout Endpoint
    Ends the user session
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'invalid_request', 'error_description': 'Realm not found'}), 400
    
    # Get parameters
    id_token_hint = request.args.get('id_token_hint') or request.form.get('id_token_hint')
    post_logout_redirect_uri = request.args.get('post_logout_redirect_uri') or request.form.get('post_logout_redirect_uri')
    state = request.args.get('state') or request.form.get('state')
    
    # Clear session
    from flask_login import logout_user
    logout_user()
    session.clear()
    
    # Redirect if post_logout_redirect_uri provided
    if post_logout_redirect_uri:
        redirect_url = post_logout_redirect_uri
        if state:
            separator = '&' if '?' in redirect_url else '?'
            redirect_url = f"{redirect_url}{separator}state={state}"
        return redirect(redirect_url)
    
    return jsonify({'status': 'logged_out'})


# =============================================================================
# JWKS Endpoint
# =============================================================================

@oidc_bp.route('/<realm_name>/protocol/openid-connect/certs', methods=['GET'])
def certs(realm_name):
    """
    JWKS Endpoint
    Returns the JSON Web Key Set for token verification
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'invalid_request', 'error_description': 'Realm not found'}), 400
    
    # For HS256, we don't expose the key
    # This is a placeholder for when RS256 is implemented
    jwks = {
        "keys": [
            {
                "kty": "oct",
                "use": "sig",
                "alg": "HS256",
                "kid": "rijanauth-default-key"
            }
        ]
    }
    
    return jsonify(jwks)


# =============================================================================
# Token Introspection Endpoint
# =============================================================================

@oidc_bp.route('/<realm_name>/protocol/openid-connect/token/introspect', methods=['POST'])
def introspect(realm_name):
    """
    Token Introspection Endpoint (RFC 7662)
    Allows resource servers to validate tokens
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'invalid_request', 'error_description': 'Realm not found'}), 400
    
    # Authenticate client
    client, authenticated = _authenticate_client(realm)
    if not client or not authenticated:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    token = request.form.get('token')
    token_type_hint = request.form.get('token_type_hint', 'access_token')
    
    if not token:
        return jsonify({'active': False})
    
    try:
        payload = decode_jwt(token, current_app.config.get('SECRET_KEY', 'secret'))
        
        return jsonify({
            'active': True,
            'scope': payload.get('scope', ''),
            'client_id': payload.get('azp'),
            'username': payload.get('preferred_username'),
            'token_type': payload.get('typ', 'Bearer'),
            'exp': int(payload.get('exp').timestamp()) if hasattr(payload.get('exp'), 'timestamp') else payload.get('exp'),
            'iat': int(payload.get('iat').timestamp()) if hasattr(payload.get('iat'), 'timestamp') else payload.get('iat'),
            'sub': payload.get('sub'),
            'aud': payload.get('aud'),
            'iss': payload.get('iss')
        })
    except Exception:
        return jsonify({'active': False})


# =============================================================================
# Token Revocation Endpoint
# =============================================================================

@oidc_bp.route('/<realm_name>/protocol/openid-connect/revoke', methods=['POST'])
def revoke(realm_name):
    """
    Token Revocation Endpoint (RFC 7009)
    Revokes access or refresh tokens
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'invalid_request', 'error_description': 'Realm not found'}), 400
    
    # Authenticate client
    client, authenticated = _authenticate_client(realm)
    if not client or not authenticated:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication failed'}), 401
    
    token = request.form.get('token')
    token_type_hint = request.form.get('token_type_hint')
    
    if not token:
        return '', 200
    
    # Try to revoke as refresh token
    refresh_token = RefreshToken.query.filter_by(token=token).first()
    if refresh_token:
        refresh_token.revoke()
    
    return '', 200
