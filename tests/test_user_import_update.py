"""Tests for user import endpoint and custom-attribute update endpoint."""

import io
import pytest
from apps import db
from apps.models.user import User


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
        url = self._import_url(test_realm.name)
        _login(client)

        csv_content = (
            'username,email,password,first_name,last_name\n'
            'rawuser1,rawuser1@example.com,secret,Charlie,Brown\n'
        )
        resp = client.post(url, data=csv_content.encode(), content_type='text/csv')
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

    def test_import_skips_duplicate(self, app, client, admin_user, test_realm, test_user):
        """Import skips users whose username already exists."""
        url = self._import_url(test_realm.name)
        existing_username = test_user.username
        _login(client)

        csv_content = f'username,email,password\n{existing_username},dup@example.com,pass\n'
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'dup.csv')},
                           content_type='multipart/form-data')
        result = resp.get_json()
        assert result['skipped'] == 1
        assert result['imported'] == 0
        assert len(result['errors']) == 1

    def test_import_skips_missing_username(self, app, client, admin_user, test_realm):
        """Row with no username is reported as an error."""
        url = self._import_url(test_realm.name)
        _login(client)
        csv_content = 'username,email\n,noname@example.com\n'
        resp = client.post(url, data={'file': (io.BytesIO(csv_content.encode()), 'bad.csv')},
                           content_type='multipart/form-data')
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
        assert resp.get_json()['imported'] == 1

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


