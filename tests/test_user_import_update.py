"""Tests for user import endpoint and custom-attribute update endpoint."""

import io
import pytest
from apps import db
from apps.models.user import User
from apps.models.role import Role
from apps.models.group import Group
from apps.services.user_service import UserService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username='admin', password='testadmin123!'):
    """Log the test client in as admin."""
    client.post('/auth/login', data={'username': username, 'password': password},
                follow_redirects=False)


# ---------------------------------------------------------------------------
# Update user – custom attributes
# ---------------------------------------------------------------------------

class TestUpdateUserAttributes:
    def test_update_standard_fields(self, app, client, admin_user, test_realm, test_user):
        """PUT /api/<realm>/users/<id> updates first/last name and email."""
        # Extract scalar values before any request (requests close the scoped session)
        realm_name = test_realm.name
        user_id = test_user.id
        _login(client)
        url = f'/admin/api/{realm_name}/users/{user_id}'

        resp = client.put(url, json={
            'firstName': 'UpdatedFirst',
            'lastName': 'UpdatedLast',
            'email': 'updated@example.com',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['firstName'] == 'UpdatedFirst'
        assert data['lastName'] == 'UpdatedLast'
        assert data['email'] == 'updated@example.com'

    def test_update_custom_attributes(self, app, client, admin_user, test_realm, test_user):
        """PUT /api/<realm>/users/<id> with 'attributes' stores custom key-value pairs."""
        realm_name = test_realm.name
        user_id = test_user.id
        _login(client)
        url = f'/admin/api/{realm_name}/users/{user_id}'

        resp = client.put(url, json={
            'attributes': {
                'phone': '+62811123456',
                'department': 'Engineering',
                'tags': ['admin', 'staff'],
            }
        })
        assert resp.status_code == 200
        data = resp.get_json()
        attrs = data.get('attributes', {})
        assert attrs.get('phone') == ['+62811123456']
        assert attrs.get('department') == ['Engineering']
        assert set(attrs.get('tags', [])) == {'admin', 'staff'}

    def test_update_attributes_invalid_type(self, app, client, admin_user, test_realm, test_user):
        """PUT with attributes as a non-object returns 400."""
        realm_name = test_realm.name
        user_id = test_user.id
        _login(client)
        url = f'/admin/api/{realm_name}/users/{user_id}'
        resp = client.put(url, json={'attributes': 'not-a-dict'})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Import users
# ---------------------------------------------------------------------------

class TestImportUsers:
    def _import_url(self, realm_name):
        return f'/admin/api/{realm_name}/users/import'

    def test_import_csv_multipart(self, app, client, admin_user, test_realm):
        """Import via multipart file upload creates users."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'username,email,password,name\n'
            'importuser1,import1@example.com,pass123,Alice Smith\n'
            'importuser2,import2@example.com,pass456,Bob\n'
        )
        data = {'file': (io.BytesIO(csv_content.encode()), 'users.csv')}
        url = self._import_url(realm_name)

        resp = client.post(url, data=data, content_type='multipart/form-data')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 2
        assert result['skipped'] == 0

        with app.app_context():
            u1 = User.find_by_username(realm_id, 'importuser1')
            assert u1 is not None
            assert u1.first_name == 'Alice'
            assert u1.last_name == 'Smith'
            u2 = User.find_by_username(realm_id, 'importuser2')
            assert u2 is not None
            assert u2.first_name == 'Bob'

    def test_import_csv_raw(self, app, client, admin_user, test_realm):
        """Import via raw CSV body creates users."""
        realm_name = test_realm.name
        url = self._import_url(realm_name)
        _login(client)

        csv_content = (
            'username,email,password,first_name,last_name\n'
            'rawuser1,rawuser1@example.com,secret,Charlie,Brown\n'
        )
        resp = client.post(url, data=csv_content.encode(), content_type='text/csv')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

    def test_import_updates_existing_user(self, app, client, admin_user, test_realm, test_user):
        """Import updates a user whose username already exists instead of reporting an error."""
        realm_name = test_realm.name
        url = self._import_url(realm_name)
        realm_id = test_realm.id
        existing_username = test_user.username
        _login(client)

        csv_content = (
            f'username,first_name,last_name,email\n'
            f'{existing_username},UpdatedFirst,UpdatedLast,updated@example.com\n'
        )
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'update.csv')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['updated'] == 1
        assert result['imported'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == []

        with app.app_context():
            u = User.find_by_username(realm_id, existing_username)
            assert u is not None
            assert u.first_name == 'UpdatedFirst'
            assert u.last_name == 'UpdatedLast'
            assert u.email == 'updated@example.com'

    def test_import_existing_user_preserves_id_and_username(self, app, client, admin_user, test_realm, test_user):
        """Import never changes id or username for an existing user."""
        realm_name = test_realm.name
        url = self._import_url(realm_name)
        realm_id = test_realm.id
        existing_username = test_user.username
        original_id = test_user.id
        _login(client)

        csv_content = (
            f'username,first_name,last_name\n'
            f'{existing_username},NewFirst,NewLast\n'
        )
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'id_check.csv')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['updated'] == 1

        with app.app_context():
            u = User.find_by_username(realm_id, existing_username)
            assert u.id == original_id
            assert u.username == existing_username

    def test_import_skips_missing_username(self, app, client, admin_user, test_realm):
        """Row with no username is reported as an error."""
        realm_name = test_realm.name
        url = self._import_url(realm_name)
        _login(client)
        csv_content = 'username,email\n,noname@example.com\n'
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'bad.csv')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['skipped'] == 1

    def test_import_custom_attribute_columns(self, app, client, admin_user, test_realm):
        """Extra CSV columns become user attributes."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'username,email,password,phone,department\n'
            'attruser1,attr1@example.com,pass,+621234,Engineering\n'
        )
        url = self._import_url(realm_name)
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'attrs.csv')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

        with app.app_context():
            u = User.find_by_username(realm_id, 'attruser1')
            assert u is not None
            phone = u.get_attribute('phone')
            assert phone == '+621234'

    def test_import_no_file_returns_400(self, app, client, admin_user, test_realm):
        """Request with no CSV content returns 400."""
        url = self._import_url(test_realm.name)
        _login(client)
        resp = client.post(url, json={'not': 'a-csv'})
        assert resp.status_code == 400

    def test_import_assigns_valid_roles(self, app, client, admin_user, test_realm):
        """Import assigns realm roles that exist; skips role names that don't exist."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        with app.app_context():
            role = Role.query.filter_by(realm_id=realm_id, name='import-test-role', client_id=None).first()
            if not role:
                role = Role(realm_id=realm_id, name='import-test-role')
                db.session.add(role)
                db.session.commit()

        csv_content = (
            'username,email,password,roles\n'
            'roleuser1,roleuser1@example.com,pass123,import-test-role;nonexistent-role\n'
        )
        url = self._import_url(realm_name)
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'roles.csv')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

        with app.app_context():
            u = User.find_by_username(realm_id, 'roleuser1')
            assert u is not None
            user_roles = UserService.get_user_roles(u)
            role_names = [r.name for r in user_roles]
            assert 'import-test-role' in role_names
            assert 'nonexistent-role' not in role_names

    def test_import_assigns_valid_groups(self, app, client, admin_user, test_realm):
        """Import adds users to groups that exist; skips group names that don't exist."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        with app.app_context():
            grp = Group.query.filter_by(realm_id=realm_id, name='import-test-group').first()
            if not grp:
                grp = Group(realm_id=realm_id, name='import-test-group', path='/import-test-group')
                db.session.add(grp)
                db.session.commit()

        csv_content = (
            'username,email,password,groups\n'
            'groupuser1,groupuser1@example.com,pass123,import-test-group;nonexistent-group\n'
        )
        url = self._import_url(realm_name)
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'groups.csv')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

        with app.app_context():
            u = User.find_by_username(realm_id, 'groupuser1')
            assert u is not None
            user_groups = UserService.get_user_groups(u)
            group_names = [g.name for g in user_groups]
            assert 'import-test-group' in group_names
            assert 'nonexistent-group' not in group_names

    def test_import_roles_groups_not_treated_as_attributes(self, app, client, admin_user, test_realm):
        """The roles and groups columns must not be stored as custom user attributes."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'username,email,password,roles,groups\n'
            'attrcheck1,attrcheck1@example.com,pass123,somerole,somegroup\n'
        )
        url = self._import_url(realm_name)
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'attrcheck.csv')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200
        resp.get_json()  # consume the response

        with app.app_context():
            u = User.find_by_username(realm_id, 'attrcheck1')
            assert u is not None
            assert u.get_attribute('roles') is None
            assert u.get_attribute('groups') is None

