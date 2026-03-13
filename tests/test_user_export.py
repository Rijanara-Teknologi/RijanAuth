"""Tests for user export endpoint."""

import csv
import io
import pytest
from apps.models.user import User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username='admin', password='testadmin123!'):
    """Log the test client in as admin."""
    client.post('/auth/login', data={'username': username, 'password': password},
                follow_redirects=False)


# ---------------------------------------------------------------------------
# Export users
# ---------------------------------------------------------------------------

class TestExportUsers:
    def _export_url(self, realm_name):
        return f'/admin/api/{realm_name}/users/export'

    def test_export_returns_csv(self, app, client, admin_user, test_realm, test_user):
        """GET /api/<realm>/users/export returns a CSV file."""
        realm_name = test_realm.name
        _login(client)

        resp = client.get(self._export_url(realm_name))
        assert resp.status_code == 200
        assert 'text/csv' in resp.content_type
        assert 'attachment' in resp.headers.get('Content-Disposition', '')
        assert f'users_export_{realm_name}.csv' in resp.headers['Content-Disposition']

    def test_export_csv_headers(self, app, client, admin_user, test_realm, test_user):
        """Exported CSV contains the expected columns (id, username, email, first_name, last_name)."""
        realm_name = test_realm.name
        _login(client)

        resp = client.get(self._export_url(realm_name))
        assert resp.status_code == 200

        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        assert reader.fieldnames == ['id', 'username', 'email', 'first_name', 'last_name']

    def test_export_csv_no_password_column(self, app, client, admin_user, test_realm, test_user):
        """Exported CSV must NOT contain a password column."""
        realm_name = test_realm.name
        _login(client)

        resp = client.get(self._export_url(realm_name))
        assert resp.status_code == 200

        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        assert 'password' not in (reader.fieldnames or [])

    def test_export_csv_contains_user_data(self, app, client, admin_user, test_realm, test_user):
        """Exported CSV rows include the test user's data with a valid UUID id."""
        realm_name = test_realm.name
        user_id = test_user.id
        username = test_user.username
        _login(client)

        resp = client.get(self._export_url(realm_name))
        assert resp.status_code == 200

        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        rows = list(reader)
        usernames = [r['username'] for r in rows]
        assert username in usernames

        user_row = next(r for r in rows if r['username'] == username)
        # id must be the UUID of the user
        assert user_row['id'] == str(user_id)

    def test_export_requires_login(self, app, client, test_realm):
        """Export endpoint redirects unauthenticated users."""
        realm_name = test_realm.name
        resp = client.get(self._export_url(realm_name))
        # Should redirect to login
        assert resp.status_code in (302, 401)

    def test_export_unknown_realm_returns_404(self, app, client, admin_user):
        """Export for a non-existent realm returns 404."""
        _login(client)
        resp = client.get(self._export_url('nonexistent-realm-xyz'))
        assert resp.status_code == 404
