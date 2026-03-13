"""
Tests for delete buttons on users list and client scopes list pages.

Verifies that:
- DELETE routes exist and return the correct status codes
- Users are actually removed from the database after deletion
- Client scopes (and their mappers) are removed after deletion
"""
import pytest
from apps import db
from apps.models.user import User, Credential
from apps.models.client import ClientScope, ProtocolMapper
from apps.models.realm import Realm
from apps.services.realm_service import RealmService
from apps.services.client_service import ClientService
from apps.utils.crypto import hash_password


def _login_admin(client_fixture):
    """Helper: log in as the master-realm admin.
    The password 'testadmin123!' is set by the test session fixture in conftest.py.
    """
    client_fixture.post('/auth/login', data={
        'username': 'admin',
        'password': 'testadmin123!',
    }, follow_redirects=True)


# ============================================================
# User delete
# ============================================================

class TestUserDelete:
    def test_delete_user_redirects(self, client, app):
        """POST /<realm>/users/<id>/delete must redirect (not 405/404)."""
        with app.app_context():
            realm = RealmService.create_realm('del-user-realm1', 'Del User 1')
            realm_name = realm.name
            user = User(realm_id=realm.id, username='to_delete_1', email='del1@example.com')
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        try:
            _login_admin(client)
            response = client.post(
                f'/admin/{realm_name}/users/{user_id}/delete',
                follow_redirects=False,
            )
            assert response.status_code == 302, (
                f"Expected 302 redirect, got {response.status_code}"
            )
            assert f'/admin/{realm_name}/users' in response.headers.get('Location', '')
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_delete_user_removes_from_db(self, client, app):
        """After deletion the user must no longer exist in the database."""
        with app.app_context():
            realm = RealmService.create_realm('del-user-realm2', 'Del User 2')
            realm_name = realm.name
            user = User(realm_id=realm.id, username='to_delete_2', email='del2@example.com')
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        try:
            _login_admin(client)
            client.post(
                f'/admin/{realm_name}/users/{user_id}/delete',
                follow_redirects=True,
            )
            with app.app_context():
                assert User.find_by_id(user_id) is None, \
                    "User should have been deleted from the database"
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_delete_user_wrong_realm_is_rejected(self, client, app):
        """Deleting a user that belongs to a different realm must fail gracefully."""
        with app.app_context():
            realm_a = RealmService.create_realm('del-realm-a', 'Del Realm A')
            realm_b = RealmService.create_realm('del-realm-b', 'Del Realm B')
            realm_a_name = realm_a.name
            realm_b_name = realm_b.name
            user = User(realm_id=realm_b.id, username='realm_b_user', email='rb@example.com')
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        try:
            _login_admin(client)
            # Try to delete realm_b's user via realm_a's URL
            response = client.post(
                f'/admin/{realm_a_name}/users/{user_id}/delete',
                follow_redirects=True,
            )
            # The user must still exist
            with app.app_context():
                assert User.find_by_id(user_id) is not None, \
                    "User from another realm must NOT be deleted"
        finally:
            with app.app_context():
                for name in (realm_a_name, realm_b_name):
                    r = Realm.find_by_name(name)
                    if r:
                        db.session.delete(r)
                        db.session.commit()


# ============================================================
# Client scope delete
# ============================================================

class TestClientScopeDelete:
    def test_delete_scope_redirects(self, client, app):
        """POST /<realm>/client-scopes/<id>/delete must redirect (not 405/404)."""
        with app.app_context():
            realm = RealmService.create_realm('del-scope-realm1', 'Del Scope 1')
            realm_name = realm.name
            scope = ClientScope(realm_id=realm.id, name='test-scope-1', protocol='openid-connect')
            db.session.add(scope)
            db.session.commit()
            scope_id = scope.id

        try:
            _login_admin(client)
            response = client.post(
                f'/admin/{realm_name}/client-scopes/{scope_id}/delete',
                follow_redirects=False,
            )
            assert response.status_code == 302, (
                f"Expected 302 redirect, got {response.status_code}"
            )
            assert f'/admin/{realm_name}/client-scopes' in response.headers.get('Location', '')
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_delete_scope_removes_from_db(self, client, app):
        """After deletion the client scope must no longer exist in the database."""
        with app.app_context():
            realm = RealmService.create_realm('del-scope-realm2', 'Del Scope 2')
            realm_name = realm.name
            scope = ClientScope(realm_id=realm.id, name='test-scope-2', protocol='openid-connect')
            db.session.add(scope)
            db.session.commit()
            scope_id = scope.id

        try:
            _login_admin(client)
            client.post(
                f'/admin/{realm_name}/client-scopes/{scope_id}/delete',
                follow_redirects=True,
            )
            with app.app_context():
                assert ClientScope.query.get(scope_id) is None, \
                    "ClientScope should have been deleted from the database"
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_delete_scope_also_removes_mappers(self, client, app):
        """Deleting a scope must cascade-delete its protocol mappers."""
        with app.app_context():
            realm = RealmService.create_realm('del-scope-realm3', 'Del Scope 3')
            realm_name = realm.name
            scope = ClientScope(realm_id=realm.id, name='test-scope-3', protocol='openid-connect')
            db.session.add(scope)
            db.session.flush()
            mapper = ProtocolMapper(
                name='test-mapper',
                protocol='openid-connect',
                protocol_mapper='oidc-usermodel-attribute-mapper',
                client_scope_id=scope.id,
                config={},
            )
            db.session.add(mapper)
            db.session.commit()
            scope_id = scope.id
            mapper_id = mapper.id

        try:
            _login_admin(client)
            client.post(
                f'/admin/{realm_name}/client-scopes/{scope_id}/delete',
                follow_redirects=True,
            )
            with app.app_context():
                assert ClientScope.query.get(scope_id) is None
                assert ProtocolMapper.query.get(mapper_id) is None, \
                    "ProtocolMapper should have been cascade-deleted with the scope"
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()
