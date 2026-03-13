"""
Regression tests for client settings save (405 Method Not Allowed fix).

Before this fix, POSTing to /<realm_name>/clients/<client_id> returned 405
because the route only accepted GET. The checkboxes for capability settings
also lacked `name` attributes so their values were never submitted.
"""
import pytest
from apps import db
from apps.models.client import Client
from apps.services.realm_service import RealmService
from apps.services.client_service import ClientService


def _login_admin(client_fixture):
    """Helper: log in as the master-realm admin.
    The password 'testadmin123!' is set by the test session fixture in conftest.py.
    """
    client_fixture.post('/auth/login', data={
        'username': 'admin',
        'password': 'testadmin123!',
    }, follow_redirects=True)


def test_client_detail_get_returns_200(client, app):
    """GET on the client detail page must succeed."""
    with app.app_context():
        realm = RealmService.create_realm('csgtest-realm-get', 'CSG Get')
        realm_name = realm.name
        oidc = ClientService.create_client(realm_id=realm.id, client_id='csg-get-client')
        client_internal_id = oidc.id

    try:
        _login_admin(client)
        response = client.get(f'/admin/{realm_name}/clients/{client_internal_id}')
        assert response.status_code == 200
    finally:
        with app.app_context():
            from apps.models.realm import Realm as RealmModel
            r = RealmModel.find_by_name(realm_name)
            if r:
                db.session.delete(r)
                db.session.commit()


def test_client_settings_post_no_longer_returns_405(client, app):
    """
    POSTing to the client detail URL must NOT return 405 Method Not Allowed.
    This is the core regression: before the fix the route only allowed GET.
    """
    with app.app_context():
        realm = RealmService.create_realm('csgtest-realm-post', 'CSG Post')
        realm_name = realm.name
        oidc = ClientService.create_client(realm_id=realm.id, client_id='csg-post-client')
        client_internal_id = oidc.id

    try:
        _login_admin(client)
        response = client.post(
            f'/admin/{realm_name}/clients/{client_internal_id}',
            data={
                'name': 'Updated Name',
                'description': 'Updated description',
                'root_url': '',
                'redirect_uris': 'http://localhost/callback',
                # standard_flow_enabled checkbox is included (checked = present in form)
                'standard_flow_enabled': 'on',
            },
            follow_redirects=False,
        )
        # Must redirect (302) on success, NOT return 405
        assert response.status_code != 405, "405 Method Not Allowed - route is missing POST handler"
        assert response.status_code in (200, 302)
    finally:
        with app.app_context():
            from apps.models.realm import Realm as RealmModel
            r = RealmModel.find_by_name(realm_name)
            if r:
                db.session.delete(r)
                db.session.commit()


def test_client_settings_saved_correctly(client, app):
    """
    After a successful POST, the updated field values must be persisted to the DB.
    Also verifies that capability checkboxes with `name` attributes are
    correctly toggled on/off.
    """
    with app.app_context():
        realm = RealmService.create_realm('csgtest-realm-save', 'CSG Save')
        realm_name = realm.name
        # Create client with standard_flow_enabled=True, direct_access_grants_enabled=False
        oidc = ClientService.create_client(
            realm_id=realm.id,
            client_id='csg-save-client',
            name='Original Name',
            standard_flow_enabled=True,
            direct_access_grants_enabled=False,
        )
        client_internal_id = oidc.id

    try:
        _login_admin(client)
        response = client.post(
            f'/admin/{realm_name}/clients/{client_internal_id}',
            data={
                'name': 'New Name',
                'description': 'New desc',
                'root_url': 'https://example.com',
                'redirect_uris': 'https://example.com/cb\nhttps://example.com/cb2',
                # standard_flow_enabled NOT included (unchecked)
                # direct_access_grants_enabled IS included (checked)
                'direct_access_grants_enabled': 'on',
            },
            follow_redirects=False,
        )
        assert response.status_code == 302, f"Expected redirect after save, got {response.status_code}"

        with app.app_context():
            updated = Client.find_by_id(client_internal_id)
            assert updated.name == 'New Name'
            assert updated.description == 'New desc'
            assert updated.root_url == 'https://example.com'
            assert 'https://example.com/cb' in updated.redirect_uris
            assert 'https://example.com/cb2' in updated.redirect_uris
            # standard_flow_enabled was NOT submitted → should be False
            assert updated.standard_flow_enabled is False
            # direct_access_grants_enabled WAS submitted → should be True
            assert updated.direct_access_grants_enabled is True
    finally:
        with app.app_context():
            from apps.models.realm import Realm as RealmModel
            r = RealmModel.find_by_name(realm_name)
            if r:
                db.session.delete(r)
                db.session.commit()
