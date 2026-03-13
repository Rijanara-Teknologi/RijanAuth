"""
Tests for session sign-out functionality on the Sessions admin page.

Verifies that:
- POST /<realm>/sessions/<session_id>/signout marks a session as LOGGED_OUT
- POST /<realm>/sessions/signout-all marks ALL active sessions as LOGGED_OUT
- Cross-realm sessions cannot be signed out via another realm's URL
"""
import pytest
from apps import db
from apps.models.session import UserSession
from apps.models.user import User
from apps.models.realm import Realm
from apps.services.realm_service import RealmService


def _login_admin(client_fixture):
    client_fixture.post('/auth/login', data={
        'username': 'admin',
        'password': 'testadmin123!',
    }, follow_redirects=True)


def _make_session(realm_id, user_id, state='ACTIVE'):
    s = UserSession(realm_id=realm_id, user_id=user_id, state=state, login_username='testuser')
    db.session.add(s)
    db.session.commit()
    return s.id


class TestSessionSignout:
    def test_signout_single_redirects(self, client, app):
        """POST to signout endpoint must redirect back to sessions list."""
        with app.app_context():
            realm = RealmService.create_realm('signout-realm1', 'Signout Realm 1')
            realm_name = realm.name
            user = User(realm_id=realm.id, username='signout_user1', email='so1@example.com')
            db.session.add(user)
            db.session.flush()
            sid = _make_session(realm.id, user.id)

        try:
            _login_admin(client)
            response = client.post(
                f'/admin/{realm_name}/sessions/{sid}/signout',
                follow_redirects=False,
            )
            assert response.status_code == 302
            assert f'/admin/{realm_name}/sessions' in response.headers.get('Location', '')
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_signout_single_marks_logged_out(self, client, app):
        """After signing out a single session its state must be LOGGED_OUT."""
        with app.app_context():
            realm = RealmService.create_realm('signout-realm2', 'Signout Realm 2')
            realm_name = realm.name
            user = User(realm_id=realm.id, username='signout_user2', email='so2@example.com')
            db.session.add(user)
            db.session.flush()
            sid = _make_session(realm.id, user.id)

        try:
            _login_admin(client)
            client.post(f'/admin/{realm_name}/sessions/{sid}/signout', follow_redirects=True)
            with app.app_context():
                s = UserSession.query.get(sid)
                assert s is not None
                assert s.state == 'LOGGED_OUT', f"Expected LOGGED_OUT, got {s.state}"
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_signout_all_marks_all_logged_out(self, client, app):
        """Sign out all must mark every active session in the realm as LOGGED_OUT."""
        with app.app_context():
            realm = RealmService.create_realm('signout-realm3', 'Signout Realm 3')
            realm_name = realm.name
            user = User(realm_id=realm.id, username='signout_user3', email='so3@example.com')
            db.session.add(user)
            db.session.flush()
            sid1 = _make_session(realm.id, user.id)
            sid2 = _make_session(realm.id, user.id)

        try:
            _login_admin(client)
            response = client.post(
                f'/admin/{realm_name}/sessions/signout-all',
                follow_redirects=False,
            )
            assert response.status_code == 302
            with app.app_context():
                for sid in (sid1, sid2):
                    s = UserSession.query.get(sid)
                    assert s is not None
                    assert s.state == 'LOGGED_OUT', f"Session {sid} expected LOGGED_OUT, got {s.state}"
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_signout_cross_realm_rejected(self, client, app):
        """Signing out a session that belongs to a different realm must fail gracefully."""
        with app.app_context():
            realm_a = RealmService.create_realm('signout-realm-a', 'Signout Realm A')
            realm_b = RealmService.create_realm('signout-realm-b', 'Signout Realm B')
            realm_a_name = realm_a.name
            realm_b_name = realm_b.name
            user = User(realm_id=realm_b.id, username='cross_realm_user', email='cr@example.com')
            db.session.add(user)
            db.session.flush()
            sid = _make_session(realm_b.id, user.id)

        try:
            _login_admin(client)
            # Try to sign out realm_b's session via realm_a's URL
            client.post(
                f'/admin/{realm_a_name}/sessions/{sid}/signout',
                follow_redirects=True,
            )
            with app.app_context():
                s = UserSession.query.get(sid)
                assert s is not None
                assert s.state == 'ACTIVE', "Session from another realm must NOT be signed out"
        finally:
            with app.app_context():
                for name in (realm_a_name, realm_b_name):
                    r = Realm.find_by_name(name)
                    if r:
                        db.session.delete(r)
                        db.session.commit()
