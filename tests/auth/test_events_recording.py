"""
Tests verifying that login, login-error, and logout activities are
recorded as Event rows in the database.
"""
import pytest
from apps.models.event import Event
from apps.models.realm import Realm
from apps.models.client import Client


@pytest.fixture
def events_test_client(app, test_realm):
    """OIDC client with direct_access_grants enabled for password-grant tests."""
    with app.app_context():
        from apps import db
        oidc_client = Client.query.filter_by(
            client_id='events-test-client', realm_id=test_realm.id
        ).first()
        if not oidc_client:
            oidc_client = Client(
                realm_id=test_realm.id,
                client_id='events-test-client',
                name='Events Test Client',
                enabled=True,
                public_client=True,
                direct_access_grants_enabled=True,
                client_authenticator_type='client-secret',
                protocol='openid-connect',
                redirect_uris='["http://localhost:8080/callback"]'
            )
            db.session.add(oidc_client)
            db.session.commit()
        yield oidc_client


# ---------------------------------------------------------------------------
# Admin-console login (apps/blueprints/auth/routes.py)
# ---------------------------------------------------------------------------

class TestAdminLoginEvents:
    """Admin-console login records events against the master realm."""

    def test_successful_login_records_login_event(self, client, admin_user, app):
        with app.app_context():
            master = Realm.query.filter_by(name='master').first()
            before = Event.get_events(master.id, event_types=['LOGIN'])

        client.post('/auth/login', data={
            'username': admin_user.username,
            'password': 'testadmin123!'
        }, follow_redirects=False)

        with app.app_context():
            after = Event.get_events(master.id, event_types=['LOGIN'])
        assert len(after) == len(before) + 1
        assert after[0].type == 'LOGIN'
        assert after[0].user_id == admin_user.id

    def test_failed_login_records_login_error_event(self, client, admin_user, app):
        with app.app_context():
            master = Realm.query.filter_by(name='master').first()
            before = Event.get_events(master.id, event_types=['LOGIN_ERROR'])

        client.post('/auth/login', data={
            'username': admin_user.username,
            'password': 'wrongpassword!'
        }, follow_redirects=False)

        with app.app_context():
            after = Event.get_events(master.id, event_types=['LOGIN_ERROR'])
        assert len(after) == len(before) + 1
        assert after[0].type == 'LOGIN_ERROR'
        assert after[0].error == 'invalid_user_credentials'

    def test_logout_records_logout_event(self, client, admin_user, app):
        # Log in first
        client.post('/auth/login', data={
            'username': admin_user.username,
            'password': 'testadmin123!'
        }, follow_redirects=False)

        with app.app_context():
            master = Realm.query.filter_by(name='master').first()
            before = Event.get_events(master.id, event_types=['LOGOUT'])

        client.get('/auth/logout', follow_redirects=False)

        with app.app_context():
            after = Event.get_events(master.id, event_types=['LOGOUT'])
        assert len(after) == len(before) + 1
        assert after[0].type == 'LOGOUT'

    def test_no_event_when_events_disabled(self, client, admin_user, app):
        """When events_enabled=False on the realm, no login events are recorded."""
        from unittest.mock import patch

        with app.app_context():
            master = Realm.query.filter_by(name='master').first()
            master_id = master.id
            before_count = len(Event.get_events(master_id, event_types=['LOGIN']))

        # Patch find_by_name to return the realm with events_enabled=False so
        # the route handler sees the disabled flag regardless of session state.
        original_find = Realm.find_by_name

        def find_with_events_disabled(name):
            realm = original_find(name)
            if realm:
                realm.events_enabled = False
            return realm

        with patch.object(Realm, 'find_by_name', side_effect=find_with_events_disabled):
            client.post('/auth/login', data={
                'username': admin_user.username,
                'password': 'testadmin123!'
            }, follow_redirects=False)

        with app.app_context():
            after_count = len(Event.get_events(master_id, event_types=['LOGIN']))

        assert after_count == before_count, (
            "A LOGIN event was recorded despite events_enabled=False"
        )


# ---------------------------------------------------------------------------
# OIDC password grant (apps/blueprints/oidc/routes.py → _handle_password_grant)
# ---------------------------------------------------------------------------

class TestOIDCPasswordGrantEvents:
    """Password-grant token requests record events against the realm."""

    def test_successful_password_grant_records_login_event(
        self, client, test_realm, test_user, events_test_client, app
    ):
        with app.app_context():
            before = Event.get_events(test_realm.id, event_types=['LOGIN'])

        client.post(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/token',
            data={
                'grant_type': 'password',
                'client_id': events_test_client.client_id,
                'username': test_user.username,
                'password': 'testpassword123!',
                'scope': 'openid',
            }
        )

        with app.app_context():
            after = Event.get_events(test_realm.id, event_types=['LOGIN'])
        assert len(after) == len(before) + 1
        assert after[0].type == 'LOGIN'
        assert after[0].user_id == test_user.id

    def test_failed_password_grant_records_login_error_event(
        self, client, test_realm, test_user, events_test_client, app
    ):
        with app.app_context():
            before = Event.get_events(test_realm.id, event_types=['LOGIN_ERROR'])

        client.post(
            f'/auth/realms/{test_realm.name}/protocol/openid-connect/token',
            data={
                'grant_type': 'password',
                'client_id': events_test_client.client_id,
                'username': test_user.username,
                'password': 'wrongpassword',
                'scope': 'openid',
            }
        )

        with app.app_context():
            after = Event.get_events(test_realm.id, event_types=['LOGIN_ERROR'])
        assert len(after) == len(before) + 1
        assert after[0].type == 'LOGIN_ERROR'
        assert after[0].error == 'invalid_user_credentials'
