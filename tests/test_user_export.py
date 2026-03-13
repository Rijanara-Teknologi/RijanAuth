"""Tests for user export endpoint."""

import csv
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
        """Exported CSV contains the expected columns (id, username, email, first_name, last_name, roles, groups)."""
        realm_name = test_realm.name
        _login(client)

        resp = client.get(self._export_url(realm_name))
        assert resp.status_code == 200

        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        assert reader.fieldnames == ['id', 'username', 'email', 'first_name', 'last_name', 'roles', 'groups']

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

    def test_export_includes_roles_and_groups(self, app, client, admin_user, test_realm):
        """Exported CSV includes semicolon-separated role and group names for each user."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        with app.app_context():
            user = User.query.filter_by(username='export_rg_user', realm_id=realm_id).first()
            if not user:
                user = User(realm_id=realm_id, username='export_rg_user', enabled=True)
                db.session.add(user)
                db.session.flush()

            role_a = Role.query.filter_by(realm_id=realm_id, name='export-role-a', client_id=None).first()
            if not role_a:
                role_a = Role(realm_id=realm_id, name='export-role-a')
                db.session.add(role_a)
            role_b = Role.query.filter_by(realm_id=realm_id, name='export-role-b', client_id=None).first()
            if not role_b:
                role_b = Role(realm_id=realm_id, name='export-role-b')
                db.session.add(role_b)

            grp = Group.query.filter_by(realm_id=realm_id, name='export-grp').first()
            if not grp:
                grp = Group(realm_id=realm_id, name='export-grp', path='/export-grp')
                db.session.add(grp)

            db.session.flush()
            UserService.assign_role(user, role_a)
            UserService.assign_role(user, role_b)
            UserService.join_group(user, grp)
            db.session.commit()

        resp = client.get(self._export_url(realm_name))
        assert resp.status_code == 200

        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        rows = list(reader)
        user_row = next((r for r in rows if r['username'] == 'export_rg_user'), None)
        assert user_row is not None

        exported_roles = set(user_row['roles'].split(';')) if user_row['roles'] else set()
        assert 'export-role-a' in exported_roles
        assert 'export-role-b' in exported_roles

        exported_groups = set(user_row['groups'].split(';')) if user_row['groups'] else set()
        assert 'export-grp' in exported_groups

    def test_export_empty_roles_groups_for_plain_user(self, app, client, admin_user, test_realm, test_user):
        """A user with no roles or groups has empty roles and groups columns."""
        realm_name = test_realm.name
        _login(client)

        resp = client.get(self._export_url(realm_name))
        assert resp.status_code == 200

        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        rows = list(reader)
        user_row = next((r for r in rows if r['username'] == test_user.username), None)
        assert user_row is not None
        assert user_row['roles'] == ''
        assert user_row['groups'] == ''
