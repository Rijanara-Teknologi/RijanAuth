"""Tests for Realm Roles and Realm Groups CSV import/export endpoints."""

import csv
import io
import pytest
from apps import db
from apps.models.role import Role
from apps.models.group import Group


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username='admin', password='testadmin123!'):
    """Log the test client in as admin."""
    client.post('/auth/login', data={'username': username, 'password': password},
                follow_redirects=False)


# ---------------------------------------------------------------------------
# Realm Roles – Export
# ---------------------------------------------------------------------------

class TestExportRoles:
    def _url(self, realm_name):
        return f'/admin/api/{realm_name}/roles/export'

    def test_export_returns_csv(self, app, client, admin_user, test_realm):
        """GET /api/<realm>/roles/export returns a text/csv response."""
        realm_name = test_realm.name
        _login(client)
        resp = client.get(self._url(realm_name))
        assert resp.status_code == 200
        assert 'text/csv' in resp.content_type
        assert 'attachment' in resp.headers.get('Content-Disposition', '')
        assert f'roles_export_{realm_name}.csv' in resp.headers['Content-Disposition']

    def test_export_csv_headers(self, app, client, admin_user, test_realm):
        """Exported roles CSV has name and description columns."""
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        assert reader.fieldnames == ['name', 'description']

    def test_export_includes_existing_roles(self, app, client, admin_user, test_realm):
        """Roles created in the realm appear in the export."""
        realm_id = test_realm.id
        with app.app_context():
            if not Role.find_realm_role(realm_id, 'export_test_role'):
                r = Role(realm_id=realm_id, name='export_test_role',
                         description='For export test', client_id=None,
                         client_role=False, composite=False)
                db.session.add(r)
                db.session.commit()

        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        rows = list(reader)
        names = [r['name'] for r in rows]
        assert 'export_test_role' in names
        row = next(r for r in rows if r['name'] == 'export_test_role')
        assert row['description'] == 'For export test'

    def test_export_requires_login(self, app, client, test_realm):
        """Unauthenticated request is redirected."""
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code in (302, 401)

    def test_export_unknown_realm_returns_404(self, app, client, admin_user):
        """Export for a non-existent realm returns 404."""
        _login(client)
        resp = client.get(self._url('nonexistent-realm-xyz'))
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Realm Roles – Import
# ---------------------------------------------------------------------------

class TestImportRoles:
    def _url(self, realm_name):
        return f'/admin/api/{realm_name}/roles/import'

    def test_import_creates_roles(self, app, client, admin_user, test_realm):
        """Roles in the CSV are created in the realm."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'name,description\n'
            'teacher,Classroom teacher\n'
            'librarian,School librarian\n'
        )
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'roles.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 2
        assert result['skipped'] == 0

        with app.app_context():
            assert Role.find_realm_role(realm_id, 'teacher') is not None
            assert Role.find_realm_role(realm_id, 'librarian') is not None

    def test_import_normalises_role_name(self, app, client, admin_user, test_realm):
        """Role names are lowercased and spaces replaced with underscores."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'name,description\n'
            'Guru Quran,Quran teacher\n'
            'GURU EKSTRAKURIKULER,Extra teacher\n'
        )
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'roles.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 2

        with app.app_context():
            assert Role.find_realm_role(realm_id, 'guru_quran') is not None
            assert Role.find_realm_role(realm_id, 'guru_ekstrakurikuler') is not None
            # Original casing must NOT exist
            assert Role.find_realm_role(realm_id, 'Guru Quran') is None

    def test_import_skips_duplicate(self, app, client, admin_user, test_realm):
        """Roles whose name already exists are skipped."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        # Pre-create the role
        with app.app_context():
            if not Role.find_realm_role(realm_id, 'existing_role'):
                r = Role(realm_id=realm_id, name='existing_role', client_id=None,
                         client_role=False, composite=False)
                db.session.add(r)
                db.session.commit()

        csv_content = 'name,description\nexisting_role,Should be skipped\n'
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'roles.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['skipped'] == 1
        assert result['imported'] == 0
        assert len(result['errors']) == 1

    def test_import_skips_missing_name(self, app, client, admin_user, test_realm):
        """Rows with an empty name are reported as errors."""
        realm_name = test_realm.name
        _login(client)
        csv_content = 'name,description\n,empty name row\n'
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'bad.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['skipped'] == 1

    def test_import_raw_csv(self, app, client, admin_user, test_realm):
        """Import via raw CSV body (Content-Type: text/csv) works."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = 'name,description\nraw_role_import,Raw import test\n'
        resp = client.post(
            self._url(realm_name),
            data=csv_content.encode(),
            content_type='text/csv'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

        with app.app_context():
            assert Role.find_realm_role(realm_id, 'raw_role_import') is not None

    def test_import_no_file_returns_400(self, app, client, admin_user, test_realm):
        """Request with no CSV returns 400."""
        _login(client)
        resp = client.post(self._url(test_realm.name), json={'not': 'csv'})
        assert resp.status_code == 400

    def test_import_requires_login(self, app, client, test_realm):
        """Unauthenticated request is redirected."""
        csv_content = 'name\nadmin\n'
        resp = client.post(
            self._url(test_realm.name),
            data={'file': (io.BytesIO(csv_content.encode()), 'roles.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code in (302, 401)

    def test_import_unknown_realm_returns_404(self, app, client, admin_user):
        """Import for a non-existent realm returns 404."""
        _login(client)
        csv_content = 'name\nadmin\n'
        resp = client.post(
            self._url('nonexistent-realm-xyz'),
            data={'file': (io.BytesIO(csv_content.encode()), 'roles.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Realm Groups – Export
# ---------------------------------------------------------------------------

class TestExportGroups:
    def _url(self, realm_name):
        return f'/admin/api/{realm_name}/groups/export'

    def test_export_returns_csv(self, app, client, admin_user, test_realm):
        """GET /api/<realm>/groups/export returns a text/csv response."""
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        assert 'text/csv' in resp.content_type
        assert 'attachment' in resp.headers.get('Content-Disposition', '')
        assert f'groups_export_{test_realm.name}.csv' in resp.headers['Content-Disposition']

    def test_export_csv_headers(self, app, client, admin_user, test_realm):
        """Exported groups CSV has a name column."""
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        assert reader.fieldnames == ['name']

    def test_export_includes_existing_groups(self, app, client, admin_user, test_realm):
        """Groups created in the realm appear in the export."""
        realm_id = test_realm.id
        with app.app_context():
            if not Group.find_by_path(realm_id, '/export_test_group'):
                g = Group(realm_id=realm_id, name='export_test_group',
                          path='/export_test_group', parent_id=None)
                db.session.add(g)
                db.session.commit()

        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        reader = csv.DictReader(io.StringIO(resp.data.decode('utf-8')))
        names = [r['name'] for r in reader]
        assert 'export_test_group' in names

    def test_export_requires_login(self, app, client, test_realm):
        """Unauthenticated request is redirected."""
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code in (302, 401)

    def test_export_unknown_realm_returns_404(self, app, client, admin_user):
        """Export for a non-existent realm returns 404."""
        _login(client)
        resp = client.get(self._url('nonexistent-realm-xyz'))
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Realm Groups – Import
# ---------------------------------------------------------------------------

class TestImportGroups:
    def _url(self, realm_name):
        return f'/admin/api/{realm_name}/groups/import'

    def test_import_creates_groups(self, app, client, admin_user, test_realm):
        """Groups in the CSV are created in the realm."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = (
            'name\n'
            'PQA dan Asrama\n'
            'sdit 3\n'
        )
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'groups.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 2
        assert result['skipped'] == 0

        with app.app_context():
            assert Group.find_by_path(realm_id, '/PQA dan Asrama') is not None
            assert Group.find_by_path(realm_id, '/sdit 3') is not None

    def test_import_preserves_group_name_casing(self, app, client, admin_user, test_realm):
        """Group names are stored exactly as provided (no normalisation)."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = 'name\nMixed Case Group\n'
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'groups.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

        with app.app_context():
            grp = Group.find_by_path(realm_id, '/Mixed Case Group')
            assert grp is not None
            assert grp.name == 'Mixed Case Group'

    def test_import_skips_duplicate(self, app, client, admin_user, test_realm):
        """Groups whose name already exists are skipped."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        with app.app_context():
            if not Group.find_by_path(realm_id, '/existing_group'):
                g = Group(realm_id=realm_id, name='existing_group',
                          path='/existing_group', parent_id=None)
                db.session.add(g)
                db.session.commit()

        csv_content = 'name\nexisting_group\n'
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'groups.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['skipped'] == 1
        assert result['imported'] == 0
        assert len(result['errors']) == 1

    def test_import_skips_missing_name(self, app, client, admin_user, test_realm):
        """Rows with a whitespace-only name are reported as errors."""
        realm_name = test_realm.name
        _login(client)
        # Use a whitespace-only name; csv.DictReader skips fully-blank rows
        csv_content = 'name\n   \n'
        resp = client.post(
            self._url(realm_name),
            data={'file': (io.BytesIO(csv_content.encode()), 'bad.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['skipped'] == 1

    def test_import_raw_csv(self, app, client, admin_user, test_realm):
        """Import via raw CSV body (Content-Type: text/csv) works."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        _login(client)

        csv_content = 'name\nraw_group_import\n'
        resp = client.post(
            self._url(realm_name),
            data=csv_content.encode(),
            content_type='text/csv'
        )
        assert resp.status_code == 200
        result = resp.get_json()
        assert result['imported'] == 1

        with app.app_context():
            assert Group.find_by_path(realm_id, '/raw_group_import') is not None

    def test_import_no_file_returns_400(self, app, client, admin_user, test_realm):
        """Request with no CSV returns 400."""
        _login(client)
        resp = client.post(self._url(test_realm.name), json={'not': 'csv'})
        assert resp.status_code == 400

    def test_import_requires_login(self, app, client, test_realm):
        """Unauthenticated request is redirected."""
        csv_content = 'name\nsome-group\n'
        resp = client.post(
            self._url(test_realm.name),
            data={'file': (io.BytesIO(csv_content.encode()), 'groups.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code in (302, 401)

    def test_import_unknown_realm_returns_404(self, app, client, admin_user):
        """Import for a non-existent realm returns 404."""
        _login(client)
        csv_content = 'name\nsome-group\n'
        resp = client.post(
            self._url('nonexistent-realm-xyz'),
            data={'file': (io.BytesIO(csv_content.encode()), 'groups.csv')},
            content_type='multipart/form-data'
        )
        assert resp.status_code == 404
