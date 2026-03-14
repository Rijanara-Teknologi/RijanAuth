# -*- encoding: utf-8 -*-
"""
RijanAuth - Import Service
Handles chunked, background CSV import for users, roles and groups.

Each import request is split into chunks of CHUNK_SIZE rows.  Each chunk is
processed in a background thread so the HTTP request returns immediately with
a job ID.  The caller can poll
``GET /api/<realm>/import-jobs/<job_id>`` to track progress.
"""

import csv
import io
import threading
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError

CHUNK_SIZE = 20  # rows processed per background chunk


# ============================================================================
# Internal helpers
# ============================================================================

def _process_users_chunk(app, job_id, realm_id, rows, start_row):
    """Process a single chunk of user rows inside an app-context thread."""
    from apps import db
    from apps.models.import_job import ImportJob
    from apps.models.user import User
    from apps.models.role import Role
    from apps.models.group import Group
    from apps.services.user_service import UserService

    FIELD_ALIASES = {'firstname': 'first_name', 'lastname': 'last_name'}
    KNOWN_FIELDS = {'username', 'email', 'password', 'name', 'first_name', 'last_name', 'roles', 'groups'}

    def _resolve(raw, lookup_fn):
        result = []
        for name in [s.strip() for s in raw.split(';') if s.strip()]:
            obj = lookup_fn(name)
            if obj:
                result.append(obj)
        return result

    with app.app_context():
        job = ImportJob.find_by_id(job_id)
        if not job:
            return

        imported = 0
        updated = 0
        skipped = 0
        errors = list(job.errors)

        for i, row in enumerate(rows):
            row_num = start_row + i

            # Normalise keys
            normalised_row = {}
            for k, v in row.items():
                if k is None:
                    continue
                key = k.strip().lower().replace(' ', '_')
                key = FIELD_ALIASES.get(key, key)
                normalised_row[key] = (v or '').strip()

            username = normalised_row.get('username')
            if not username:
                errors.append({'row': row_num, 'error': 'Missing username'})
                skipped += 1
                continue

            # Name resolution
            first_name = normalised_row.get('first_name') or ''
            last_name = normalised_row.get('last_name') or ''
            if not first_name and not last_name:
                full_name = normalised_row.get('name', '')
                if full_name:
                    parts = full_name.split(' ', 1)
                    first_name = parts[0]
                    last_name = parts[1] if len(parts) > 1 else ''

            email = normalised_row.get('email') or None
            password = normalised_row.get('password') or None
            extra_attrs = {k: v for k, v in normalised_row.items() if k not in KNOWN_FIELDS and v}

            roles_raw = normalised_row.get('roles', '')
            roles_to_assign = _resolve(
                roles_raw, lambda name: Role.find_realm_role(realm_id, name)
            ) if roles_raw else []

            groups_raw = normalised_row.get('groups', '')
            groups_to_assign = _resolve(
                groups_raw, lambda name: Group.find_realm_group(realm_id, name)
            ) if groups_raw else []

            existing_user = User.find_by_username(realm_id, username)
            if existing_user:
                try:
                    update_fields = {}
                    if first_name:
                        update_fields['first_name'] = first_name
                    if last_name:
                        update_fields['last_name'] = last_name
                    if email:
                        update_fields['email'] = email
                    if update_fields:
                        UserService.update_user(existing_user, **update_fields)
                    if password:
                        UserService.set_password(existing_user, password)
                    if extra_attrs:
                        UserService.set_attributes(existing_user, {k: [v] for k, v in extra_attrs.items()})
                    for role in roles_to_assign:
                        UserService.assign_role(existing_user, role)
                    for group in groups_to_assign:
                        UserService.join_group(existing_user, group)
                    updated += 1
                except (SQLAlchemyError, ValueError) as exc:
                    db.session.rollback()
                    errors.append({'row': row_num, 'username': username, 'error': str(exc)})
                    skipped += 1
                continue

            try:
                user = UserService.create_user(
                    realm_id=realm_id,
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name or None,
                    last_name=last_name or None,
                )
                if extra_attrs:
                    UserService.set_attributes(user, {k: [v] for k, v in extra_attrs.items()})
                for role in roles_to_assign:
                    UserService.assign_role(user, role)
                for group in groups_to_assign:
                    UserService.join_group(user, group)
                imported += 1
            except (SQLAlchemyError, ValueError) as exc:
                db.session.rollback()
                errors.append({'row': row_num, 'username': username, 'error': str(exc)})
                skipped += 1

        # Persist chunk results back to the job
        job = ImportJob.find_by_id(job_id)
        if job:
            job.imported += imported
            job.updated += updated
            job.skipped += skipped
            job.errors = errors
            job.processed_rows += len(rows)
            db.session.commit()


def _process_roles_chunk(app, job_id, realm_id, rows, start_row):
    """Process a single chunk of role rows inside an app-context thread."""
    from apps import db
    from apps.models.import_job import ImportJob
    from apps.models.role import Role

    with app.app_context():
        job = ImportJob.find_by_id(job_id)
        if not job:
            return

        imported = 0
        skipped = 0
        errors = list(job.errors)

        for i, row in enumerate(rows):
            row_num = start_row + i

            name_raw = (row.get('name') or '').strip()
            if not name_raw:
                errors.append({'row': row_num, 'error': 'Missing name'})
                skipped += 1
                continue

            name = name_raw.lower().replace(' ', '_')
            description = (row.get('description') or '').strip() or None

            if Role.find_realm_role(realm_id, name):
                errors.append({'row': row_num, 'name': name, 'error': 'Role already exists'})
                skipped += 1
                continue

            try:
                role = Role(
                    realm_id=realm_id,
                    name=name,
                    description=description,
                    client_id=None,
                    client_role=False,
                    composite=False,
                )
                db.session.add(role)
                db.session.commit()
                imported += 1
            except SQLAlchemyError as exc:
                db.session.rollback()
                errors.append({'row': row_num, 'name': name, 'error': str(exc)})
                skipped += 1

        job = ImportJob.find_by_id(job_id)
        if job:
            job.imported += imported
            job.skipped += skipped
            job.errors = errors
            job.processed_rows += len(rows)
            db.session.commit()


def _process_groups_chunk(app, job_id, realm_id, rows, start_row):
    """Process a single chunk of group rows inside an app-context thread."""
    from apps import db
    from apps.models.import_job import ImportJob
    from apps.models.group import Group

    with app.app_context():
        job = ImportJob.find_by_id(job_id)
        if not job:
            return

        imported = 0
        skipped = 0
        errors = list(job.errors)

        for i, row in enumerate(rows):
            row_num = start_row + i

            name = (row.get('name') or '').strip()
            if not name:
                errors.append({'row': row_num, 'error': 'Missing name'})
                skipped += 1
                continue

            path = f'/{name}'
            if Group.find_by_path(realm_id, path):
                errors.append({'row': row_num, 'name': name, 'error': 'Group already exists'})
                skipped += 1
                continue

            try:
                group = Group(realm_id=realm_id, name=name, path=path, parent_id=None)
                db.session.add(group)
                db.session.commit()
                imported += 1
            except SQLAlchemyError as exc:
                db.session.rollback()
                errors.append({'row': row_num, 'name': name, 'error': str(exc)})
                skipped += 1

        job = ImportJob.find_by_id(job_id)
        if job:
            job.imported += imported
            job.skipped += skipped
            job.errors = errors
            job.processed_rows += len(rows)
            db.session.commit()


# ============================================================================
# Public API
# ============================================================================

class ImportService:
    """Coordinates chunked background CSV imports."""

    @staticmethod
    def _chunk(lst, size):
        """Yield successive *size*-sized sublists from *lst*."""
        for i in range(0, len(lst), size):
            yield lst[i: i + size]

    @classmethod
    def _run_job(cls, app, job_id, realm_id, job_type, all_rows, chunk_fn):
        """
        Run all chunks sequentially in a single background thread and then
        mark the job as completed (or failed on exception).
        """
        from apps import db
        from apps.models.import_job import ImportJob

        with app.app_context():
            job = ImportJob.find_by_id(job_id)
            if not job:
                return
            job.status = 'processing'
            job.started_at = datetime.utcnow()
            db.session.commit()

        try:
            for chunk_index, chunk in enumerate(cls._chunk(all_rows, CHUNK_SIZE)):
                # row numbers start at 2 (header is row 1)
                start_row = 2 + chunk_index * CHUNK_SIZE
                chunk_fn(app, job_id, realm_id, chunk, start_row)
        except (SQLAlchemyError, ValueError, OSError) as exc:  # noqa: BLE001
            with app.app_context():
                job = ImportJob.find_by_id(job_id)
                if job:
                    errs = list(job.errors)
                    errs.append({'error': f'Unexpected error: {exc}'})
                    job.errors = errs
                    job.status = 'failed'
                    job.finished_at = datetime.utcnow()
                    db.session.commit()
            return

        with app.app_context():
            job = ImportJob.find_by_id(job_id)
            if job:
                job.status = 'completed'
                job.finished_at = datetime.utcnow()
                db.session.commit()

    @classmethod
    def enqueue_users(cls, app, realm_id, csv_raw):
        """
        Parse *csv_raw*, create an ImportJob, and start background processing.

        Returns the new :class:`ImportJob` instance (status=``'pending'``).
        """
        from apps import db
        from apps.models.import_job import ImportJob

        rows = list(csv.DictReader(io.StringIO(csv_raw)))
        job = ImportJob(realm_id=realm_id, job_type='users', total_rows=len(rows))
        db.session.add(job)
        db.session.commit()

        t = threading.Thread(
            target=cls._run_job,
            args=(app, job.id, realm_id, 'users', rows, _process_users_chunk),
            daemon=True,
        )
        t.start()
        return job

    @classmethod
    def enqueue_roles(cls, app, realm_id, csv_raw):
        """Parse *csv_raw*, create an ImportJob, and start background processing."""
        from apps import db
        from apps.models.import_job import ImportJob

        rows = list(csv.DictReader(io.StringIO(csv_raw)))
        job = ImportJob(realm_id=realm_id, job_type='roles', total_rows=len(rows))
        db.session.add(job)
        db.session.commit()

        t = threading.Thread(
            target=cls._run_job,
            args=(app, job.id, realm_id, 'roles', rows, _process_roles_chunk),
            daemon=True,
        )
        t.start()
        return job

    @classmethod
    def enqueue_groups(cls, app, realm_id, csv_raw):
        """Parse *csv_raw*, create an ImportJob, and start background processing."""
        from apps import db
        from apps.models.import_job import ImportJob

        rows = list(csv.DictReader(io.StringIO(csv_raw)))
        job = ImportJob(realm_id=realm_id, job_type='groups', total_rows=len(rows))
        db.session.add(job)
        db.session.commit()

        t = threading.Thread(
            target=cls._run_job,
            args=(app, job.id, realm_id, 'groups', rows, _process_groups_chunk),
            daemon=True,
        )
        t.start()
        return job
