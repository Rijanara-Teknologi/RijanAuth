"""Tests for the UI-side user import routes.

Covers:
* GET  /<realm>/users/import-template  – CSV template download
* POST /api/<realm>/users/import       – already tested in test_user_import_update.py;
  here we add a smoke-test that confirms the same endpoint is reachable from the
  context of the users-list page (same session / login flow used by the UI).
"""

import io
import pytest
from apps.models.user import User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username='admin', password='testadmin123!'):
    client.post('/auth/login', data={'username': username, 'password': password},
                follow_redirects=False)


# ---------------------------------------------------------------------------
# CSV template download
# ---------------------------------------------------------------------------

class TestDownloadImportTemplate:
    def test_template_requires_login(self, client, test_realm):
        """Unauthenticated request redirects to login."""
        url = f'/admin/{test_realm.name}/users/import-template'
        resp = client.get(url)
        assert resp.status_code in (302, 401)

    def test_template_returns_csv(self, client, admin_user, test_realm):
        """Authenticated request returns a CSV file."""
        _login(client)
        url = f'/admin/{test_realm.name}/users/import-template'
        resp = client.get(url)
        assert resp.status_code == 200
        assert 'text/csv' in resp.content_type
        assert b'username' in resp.data

    def test_template_has_required_columns(self, client, admin_user, test_realm):
        """Template CSV header contains at minimum the 'username' column."""
        _login(client)
        url = f'/admin/{test_realm.name}/users/import-template'
        resp = client.get(url)
        header_line = resp.data.decode('utf-8').splitlines()[0]
        assert 'username' in header_line

    def test_template_is_attachment(self, client, admin_user, test_realm):
        """Response includes Content-Disposition attachment header."""
        _login(client)
        url = f'/admin/{test_realm.name}/users/import-template'
        resp = client.get(url)
        cd = resp.headers.get('Content-Disposition', '')
        assert 'attachment' in cd
        assert '.csv' in cd


# ---------------------------------------------------------------------------
# UI import – uses the same API endpoint as the direct API tests but exercised
# exactly as the browser would call it (multipart POST from the modal form).
# ---------------------------------------------------------------------------

class TestUIImportUsers:
    def _import_url(self, realm_name):
        return f'/admin/api/{realm_name}/users/import'

    def test_ui_import_single_user(self, app, client, admin_user, test_realm):
        """Multipart POST (as issued by the modal) imports a user successfully."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'username,email,password,first_name,last_name\n'
            'ui_import_user1,ui1@example.com,pass1,Jane,Doe\n'
        )
        data = {'file': (io.BytesIO(csv_content.encode()), 'import.csv')}
        resp = client.post(
            self._import_url(realm_name),
            data=data,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1
        assert result['skipped'] == 0

        with app.app_context():
            u = User.find_by_username(realm_id, 'ui_import_user1')
            assert u is not None
            assert u.first_name == 'Jane'
            assert u.last_name == 'Doe'

    def test_ui_import_multiple_users(self, app, client, admin_user, test_realm):
        """Importing multiple rows via a single file upload works correctly.

        Uses the ``name`` column (full name) intentionally – the API splits it
        into first_name / last_name automatically.  Both ``name`` and the
        separate ``first_name`` / ``last_name`` columns are valid CSV formats.
        """
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'username,email,password,name\n'
            'ui_bulk_a,bulka@example.com,pass,Alpha User\n'
            'ui_bulk_b,bulkb@example.com,pass,Beta User\n'
        )
        data = {'file': (io.BytesIO(csv_content.encode()), 'bulk.csv')}
        resp = client.post(
            self._import_url(realm_name),
            data=data,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 2
        assert result['skipped'] == 0

    def test_ui_import_updates_duplicate(self, app, client, admin_user, test_realm, test_user):
        """Import via the UI updates existing users instead of reporting them as errors."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        existing_username = test_user.username  # capture before session closes
        _login(client)

        csv_content = f'username,first_name,last_name\n{existing_username},UIFirst,UILast\n'
        data = {'file': (io.BytesIO(csv_content.encode()), 'dup.csv')}
        resp = client.post(
            self._import_url(realm_name),
            data=data,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['updated'] == 1
        assert result['imported'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == []

        with app.app_context():
            u = User.find_by_username(realm_id, existing_username)
            assert u.first_name == 'UIFirst'
            assert u.last_name == 'UILast'

    def test_ui_import_no_file_returns_400(self, client, admin_user, test_realm):
        """Missing file in the multipart request returns 400."""
        _login(client)
        resp = client.post(
            self._import_url(test_realm.name),
            data={},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 400

    def test_ui_import_requires_login(self, client, test_realm):
        """Unauthenticated import request is rejected."""
        csv_content = 'username\nanon_user\n'
        data = {'file': (io.BytesIO(csv_content.encode()), 'anon.csv')}
        resp = client.post(
            self._import_url(test_realm.name),
            data=data,
            content_type='multipart/form-data',
        )
        assert resp.status_code in (302, 401)
