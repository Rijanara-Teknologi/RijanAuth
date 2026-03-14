"""Tests for the synchronous CSV import mechanism.

Validates that:
* Imports are processed synchronously and return results directly.
* Large CSVs are fully processed in a single request.
* Skipped/error rows are reported in the response.
"""

import io
import pytest
from apps import db
from apps.models.user import User
from apps.models.role import Role
from apps.models.group import Group


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username='admin', password='testadmin123!'):
    client.post('/auth/login', data={'username': username, 'password': password},
                follow_redirects=False)


def _build_user_csv(count, prefix='quser'):
    """Return a CSV string with *count* unique users."""
    lines = ['username,email,password,first_name,last_name']
    for i in range(count):
        lines.append(
            f'{prefix}{i},{prefix}{i}@example.com,pass{i},First{i},Last{i}'
        )
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------
# Import lifecycle – synchronous
# ---------------------------------------------------------------------------

class TestImportLifecycle:

    def test_import_returns_200_with_results(self, app, client, admin_user, test_realm):
        """POST /import returns 200 with import results immediately."""
        realm_name = test_realm.name
        _login(client)

        csv_content = _build_user_csv(5, prefix='lifecycle')
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'test.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['total_rows'] == 5
        assert body['imported'] == 5
        assert body['skipped'] == 0

    def test_import_users_result_fields(self, app, client, admin_user, test_realm):
        """Response contains all expected result fields."""
        realm_name = test_realm.name
        _login(client)

        csv_content = _build_user_csv(3, prefix='fields')
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'test.csv')},
            content_type='multipart/form-data',
        )
        body = resp.get_json()
        assert 'total_rows' in body
        assert 'imported' in body
        assert 'updated' in body
        assert 'skipped' in body
        assert 'errors' in body
        assert body['imported'] == 3
        assert body['skipped'] == 0

    def test_import_invalid_realm_returns_404(self, app, client, admin_user):
        """POST /import for a non-existent realm returns 404."""
        _login(client)
        csv_content = _build_user_csv(1)
        resp = client.post(
            '/admin/api/nonexistent-realm-xyz/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'test.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 404

    def test_import_no_file_returns_400(self, client, admin_user, test_realm):
        """Missing file in the multipart request returns 400."""
        _login(client)
        resp = client.post(
            f'/admin/api/{test_realm.name}/users/import',
            data={},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Large import
# ---------------------------------------------------------------------------

class TestLargeImport:

    def test_large_user_import_fully_processed(self, app, client, admin_user, test_realm):
        """A large user import is fully processed synchronously."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        count = 50
        _login(client)

        csv_content = _build_user_csv(count, prefix='bulk')
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'big.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['total_rows'] == count
        assert body['imported'] == count
        assert body['skipped'] == 0

        with app.app_context():
            assert User.find_by_username(realm_id, 'bulk0') is not None
            assert User.find_by_username(realm_id, f'bulk{count - 1}') is not None

    def test_large_role_import_fully_processed(self, app, client, admin_user, test_realm):
        """A large role import is fully processed synchronously."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        count = 25
        _login(client)

        lines = ['name,description']
        for i in range(count):
            lines.append(f'bulk_role_{i},Description {i}')
        csv_content = '\n'.join(lines) + '\n'

        resp = client.post(
            f'/admin/api/{realm_name}/roles/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'roles.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['imported'] == count

        with app.app_context():
            assert Role.find_realm_role(realm_id, 'bulk_role_0') is not None
            assert Role.find_realm_role(realm_id, f'bulk_role_{count - 1}') is not None

    def test_large_group_import_fully_processed(self, app, client, admin_user, test_realm):
        """A large group import is fully processed synchronously."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        count = 25
        _login(client)

        lines = ['name']
        for i in range(count):
            lines.append(f'bulk_group_{i}')
        csv_content = '\n'.join(lines) + '\n'

        resp = client.post(
            f'/admin/api/{realm_name}/groups/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'groups.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['imported'] == count

        with app.app_context():
            assert Group.find_by_path(realm_id, '/bulk_group_0') is not None
            assert Group.find_by_path(realm_id, f'/bulk_group_{count - 1}') is not None


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestImportErrors:

    def test_skipped_rows_reported_in_response(self, app, client, admin_user, test_realm):
        """Rows without required fields increment skipped and add to errors."""
        realm_name = test_realm.name
        _login(client)

        csv_content = (
            'username,email\n'
            ',missing@example.com\n'
            'validuser,valid@example.com\n'
        )
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'errors.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['skipped'] == 1
        assert body['imported'] == 1
        assert len(body['errors']) == 1

