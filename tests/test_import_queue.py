"""Tests for the chunked, asynchronous import queue mechanism.

Validates that:
* Large CSVs are split into chunks and processed in the background.
* Import-job status endpoint returns correct state transitions.
* Multiple concurrent jobs are tracked independently.
* Import-jobs list endpoint returns all jobs for a realm.
"""

import io
import time
import pytest
from apps import db
from apps.models.import_job import ImportJob
from apps.models.user import User
from apps.models.role import Role
from apps.models.group import Group
from apps.services.import_service import CHUNK_SIZE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username='admin', password='testadmin123!'):
    client.post('/auth/login', data={'username': username, 'password': password},
                follow_redirects=False)


def _await_job(client, realm_name, job_id, max_retries=100, delay=0.1):
    """Poll until job reaches a terminal state ('completed' or 'failed')."""
    url = f'/admin/api/{realm_name}/import-jobs/{job_id}'
    for _ in range(max_retries):
        resp = client.get(url)
        assert resp.status_code == 200, f"Status endpoint returned {resp.status_code}"
        data = resp.get_json()
        if data['status'] in ('completed', 'failed'):
            return data
        time.sleep(delay)
    raise AssertionError(
        f"Import job {job_id} did not finish within {max_retries * delay:.1f}s"
    )


def _build_user_csv(count, prefix='quser'):
    """Return a CSV string with *count* unique users."""
    lines = ['username,email,password,first_name,last_name']
    for i in range(count):
        lines.append(
            f'{prefix}{i},{prefix}{i}@example.com,pass{i},First{i},Last{i}'
        )
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------
# Job lifecycle
# ---------------------------------------------------------------------------

class TestImportJobLifecycle:

    def test_import_returns_202_with_job_id(self, app, client, admin_user, test_realm):
        """POST /import returns 202 Accepted with a job_id immediately."""
        realm_name = test_realm.name
        _login(client)

        csv_content = _build_user_csv(5, prefix='lifecycle')
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'test.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 202
        body = resp.get_json()
        assert 'job_id' in body
        assert body['status'] == 'queued'
        assert body['total_rows'] == 5

    def test_import_job_reaches_completed(self, app, client, admin_user, test_realm):
        """Import job transitions from pending/processing → completed."""
        realm_name = test_realm.name
        _login(client)

        csv_content = _build_user_csv(3, prefix='jobstatus')
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'test.csv')},
            content_type='multipart/form-data',
        )
        job_id = resp.get_json()['job_id']
        result = _await_job(client, realm_name, job_id)

        assert result['status'] == 'completed'
        assert result['imported'] == 3
        assert result['skipped'] == 0

    def test_import_job_invalid_realm_returns_404(self, app, client, admin_user):
        """GET /import-jobs/<id> for a non-existent realm returns 404."""
        _login(client)
        resp = client.get('/admin/api/nonexistent-realm-xyz/import-jobs/some-job-id')
        assert resp.status_code == 404

    def test_import_job_unknown_id_returns_404(self, app, client, admin_user, test_realm):
        """GET /import-jobs/<id> with an unknown job id returns 404."""
        realm_name = test_realm.name
        _login(client)
        resp = client.get(f'/admin/api/{realm_name}/import-jobs/00000000-0000-0000-0000-000000000000')
        assert resp.status_code == 404

    def test_import_jobs_list(self, app, client, admin_user, test_realm):
        """GET /import-jobs returns a list of jobs for the realm."""
        realm_name = test_realm.name
        _login(client)

        # Create a job
        csv_content = _build_user_csv(2, prefix='listjob')
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'test.csv')},
            content_type='multipart/form-data',
        )
        job_id = resp.get_json()['job_id']
        _await_job(client, realm_name, job_id)

        list_resp = client.get(f'/admin/api/{realm_name}/import-jobs')
        assert list_resp.status_code == 200
        jobs = list_resp.get_json()
        job_ids = [j['id'] for j in jobs]
        assert job_id in job_ids


# ---------------------------------------------------------------------------
# Chunking behaviour
# ---------------------------------------------------------------------------

class TestImportChunking:

    def test_large_user_import_processed_in_chunks(self, app, client, admin_user, test_realm):
        """A user import larger than CHUNK_SIZE is fully processed."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        # Import 2.5x CHUNK_SIZE to guarantee multiple chunks
        count = CHUNK_SIZE * 2 + CHUNK_SIZE // 2
        _login(client)

        csv_content = _build_user_csv(count, prefix='chunked')
        resp = client.post(
            f'/admin/api/{realm_name}/users/import',
            data={'file': (io.BytesIO(csv_content.encode()), 'big.csv')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 202
        assert resp.get_json()['total_rows'] == count

        job_id = resp.get_json()['job_id']
        result = _await_job(client, realm_name, job_id, max_retries=200, delay=0.1)

        assert result['status'] == 'completed'
        assert result['processed_rows'] == count
        assert result['imported'] == count

        # Spot-check a few users in the DB
        with app.app_context():
            assert User.find_by_username(realm_id, 'chunked0') is not None
            assert User.find_by_username(realm_id, f'chunked{count - 1}') is not None

    def test_large_role_import_processed(self, app, client, admin_user, test_realm):
        """A role import larger than CHUNK_SIZE is fully processed."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        count = CHUNK_SIZE + 5
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
        assert resp.status_code == 202
        job_id = resp.get_json()['job_id']
        result = _await_job(client, realm_name, job_id, max_retries=200, delay=0.1)

        assert result['status'] == 'completed'
        assert result['imported'] == count

        with app.app_context():
            assert Role.find_realm_role(realm_id, 'bulk_role_0') is not None
            assert Role.find_realm_role(realm_id, f'bulk_role_{count - 1}') is not None

    def test_large_group_import_processed(self, app, client, admin_user, test_realm):
        """A group import larger than CHUNK_SIZE is fully processed."""
        realm_name = test_realm.name
        realm_id = test_realm.id
        count = CHUNK_SIZE + 5
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
        assert resp.status_code == 202
        job_id = resp.get_json()['job_id']
        result = _await_job(client, realm_name, job_id, max_retries=200, delay=0.1)

        assert result['status'] == 'completed'
        assert result['imported'] == count

        with app.app_context():
            assert Group.find_by_path(realm_id, '/bulk_group_0') is not None
            assert Group.find_by_path(realm_id, f'/bulk_group_{count - 1}') is not None


# ---------------------------------------------------------------------------
# Error handling in jobs
# ---------------------------------------------------------------------------

class TestImportJobErrors:

    def test_skipped_rows_reported_in_job(self, app, client, admin_user, test_realm):
        """Rows without required fields increment skipped and add to errors in the job."""
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
        assert resp.status_code == 202
        job_id = resp.get_json()['job_id']
        result = _await_job(client, realm_name, job_id)

        assert result['status'] == 'completed'
        assert result['skipped'] == 1
        assert result['imported'] == 1
        assert len(result['errors']) == 1
