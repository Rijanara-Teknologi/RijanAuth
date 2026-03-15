"""
Tests for the OIDC logout endpoint.

Covers:
- Simple GET logout (browser flow) returns {"status": "logged_out"}
- POST logout with Authorization: Bearer <access_token> invalidates the
  UserSession and revokes associated RefreshTokens in the database.
- POST logout with id_token_hint invalidates the session.
- Logout of an already-logged-out session is handled gracefully.
"""
import pytest
import jwt as pyjwt
from datetime import datetime, timedelta

from apps import db
from apps.models.session import UserSession, RefreshToken
from apps.utils.crypto import create_jwt, generate_token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_tokens(client, realm_name, client_id, username, password):
    """Obtain tokens via password grant and return the parsed JSON."""
    resp = client.post(
        f'/auth/realms/{realm_name}/protocol/openid-connect/token',
        data={
            'grant_type': 'password',
            'client_id': client_id,
            'username': username,
            'password': password,
            'scope': 'openid',
        },
    )
    return resp


def _make_access_token(app, realm_name, user_id, session_id=None, secret=None):
    """Manually craft a JWT access token for testing."""
    secret = secret or app.config.get('SECRET_KEY', 'secret')
    base_url = 'http://localhost'
    now = datetime.utcnow()
    payload = {
        'exp': now + timedelta(seconds=300),
        'iat': now,
        'jti': generate_token(16),
        'iss': f'{base_url}/auth/realms/{realm_name}',
        'aud': 'test-client',
        'sub': user_id,
        'typ': 'Bearer',
        'azp': 'test-client',
        'scope': 'openid',
    }
    if session_id:
        payload['session_state'] = session_id
    return create_jwt(payload, secret)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLogoutEndpoint:

    def test_logout_no_token_returns_logged_out(self, client, test_realm):
        """Simple GET without a token should return {'status': 'logged_out'}."""
        resp = client.get(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/logout'
        )
        assert resp.status_code == 200
        assert resp.get_json() == {'status': 'logged_out'}

    def test_logout_with_bearer_token_invalidates_session(
        self, app, client, test_realm, test_user, test_client
    ):
        """Bearer token logout must mark the UserSession as LOGGED_OUT."""
        with app.app_context():
            # Create an active UserSession
            us = UserSession(
                realm_id=test_realm.id,
                user_id=test_user.id,
                login_username=test_user.username,
                ip_address='127.0.0.1',
                state='ACTIVE',
            )
            db.session.add(us)
            db.session.commit()
            session_id = us.id

        access_token = _make_access_token(
            app,
            test_realm.name,
            test_user.id,
            session_id=session_id,
        )

        resp = client.post(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/logout',
            headers={'Authorization': f'Bearer {access_token}'},
        )

        assert resp.status_code == 200
        assert resp.get_json() == {'status': 'logged_out'}

        with app.app_context():
            refreshed = UserSession.query.get(session_id)
            assert refreshed is not None
            assert refreshed.state == 'LOGGED_OUT'

    def test_logout_with_bearer_token_revokes_refresh_tokens(
        self, app, client, test_realm, test_user, test_client
    ):
        """Bearer token logout must revoke all refresh tokens for the session."""
        with app.app_context():
            us = UserSession(
                realm_id=test_realm.id,
                user_id=test_user.id,
                login_username=test_user.username,
                ip_address='127.0.0.1',
                state='ACTIVE',
            )
            db.session.add(us)
            db.session.flush()

            rt = RefreshToken(
                token=generate_token(64),
                realm_id=test_realm.id,
                user_id=test_user.id,
                client_id=test_client.id,
                user_session_id=us.id,
                scope='openid',
                expires_at=datetime.utcnow() + timedelta(hours=1),
            )
            db.session.add(rt)
            db.session.commit()

            session_id = us.id
            token_id = rt.id

        access_token = _make_access_token(
            app,
            test_realm.name,
            test_user.id,
            session_id=session_id,
        )

        resp = client.post(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/logout',
            headers={'Authorization': f'Bearer {access_token}'},
        )

        assert resp.status_code == 200

        with app.app_context():
            revoked_rt = RefreshToken.query.get(token_id)
            assert revoked_rt is not None
            assert revoked_rt.revoked is True

    def test_logout_with_id_token_hint_invalidates_session(
        self, app, client, test_realm, test_user
    ):
        """id_token_hint logout should also invalidate the UserSession."""
        with app.app_context():
            us = UserSession(
                realm_id=test_realm.id,
                user_id=test_user.id,
                login_username=test_user.username,
                ip_address='127.0.0.1',
                state='ACTIVE',
            )
            db.session.add(us)
            db.session.commit()
            session_id = us.id

        id_token = _make_access_token(
            app,
            test_realm.name,
            test_user.id,
            session_id=session_id,
        )

        resp = client.get(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/logout'
            f'?id_token_hint={id_token}'
        )

        assert resp.status_code == 200

        with app.app_context():
            refreshed = UserSession.query.get(session_id)
            assert refreshed is not None
            assert refreshed.state == 'LOGGED_OUT'

    def test_logout_with_post_logout_redirect_uri(self, client, test_realm):
        """When post_logout_redirect_uri is provided the response should redirect."""
        redirect_uri = 'http://myapp.local/after-logout'
        resp = client.get(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/logout'
            f'?post_logout_redirect_uri={redirect_uri}'
        )
        assert resp.status_code == 302
        assert redirect_uri in resp.headers.get('Location', '')

    def test_logout_with_post_logout_redirect_uri_and_state(self, client, test_realm):
        """State parameter should be appended to the redirect URI."""
        redirect_uri = 'http://myapp.local/after-logout'
        state = 'xyz-state-123'
        resp = client.get(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/logout'
            f'?post_logout_redirect_uri={redirect_uri}&state={state}'
        )
        assert resp.status_code == 302
        location = resp.headers.get('Location', '')
        assert redirect_uri in location
        assert state in location

    def test_logout_invalid_realm(self, client):
        """Non-existent realm should return 400."""
        resp = client.get(
            '/auth/realms/nonexistent-realm/protocol/openid-connect/logout'
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data.get('error') == 'invalid_request'

    def test_logout_already_logged_out_session_graceful(
        self, app, client, test_realm, test_user
    ):
        """Logging out an already-LOGGED_OUT session should not raise an error."""
        with app.app_context():
            us = UserSession(
                realm_id=test_realm.id,
                user_id=test_user.id,
                login_username=test_user.username,
                ip_address='127.0.0.1',
                state='LOGGED_OUT',
            )
            db.session.add(us)
            db.session.commit()
            session_id = us.id

        access_token = _make_access_token(
            app,
            test_realm.name,
            test_user.id,
            session_id=session_id,
        )

        resp = client.post(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/logout',
            headers={'Authorization': f'Bearer {access_token}'},
        )

        assert resp.status_code == 200
        assert resp.get_json() == {'status': 'logged_out'}
