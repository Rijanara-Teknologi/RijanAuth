# -*- encoding: utf-8 -*-
"""
RijanAuth - Import Service
Handles synchronous CSV import for users, roles and groups.

Each import request is processed directly within the HTTP request so the
caller receives a complete result immediately::

    {
        "total_rows": 300,
        "imported":   295,
        "updated":      5,
        "skipped":      0,
        "errors":      []
    }
"""

import csv
import io

from sqlalchemy.exc import SQLAlchemyError


# ============================================================================
# Public API
# ============================================================================

class ImportService:
    """Processes CSV imports synchronously and returns a result dict."""

    @classmethod
    def import_users(cls, realm_id, csv_raw):
        """Parse *csv_raw* and import/update users synchronously.

        Returns a dict with keys ``total_rows``, ``imported``, ``updated``,
        ``skipped``, and ``errors``.
        """
        from apps import db
        from apps.models.user import User
        from apps.models.role import Role
        from apps.models.group import Group
        from apps.services.user_service import UserService

        FIELD_ALIASES = {'firstname': 'first_name', 'lastname': 'last_name'}
        KNOWN_FIELDS = {
            'username', 'email', 'password', 'name',
            'first_name', 'last_name', 'roles', 'groups',
        }

        def _resolve(raw, lookup_fn):
            result = []
            for name in [s.strip() for s in raw.split(';') if s.strip()]:
                obj = lookup_fn(name)
                if obj:
                    result.append(obj)
            return result

        rows = list(csv.DictReader(io.StringIO(csv_raw)))
        total_rows = len(rows)
        imported = 0
        updated = 0
        skipped = 0
        errors = []

        for i, row in enumerate(rows):
            row_num = i + 2  # header is row 1

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
            extra_attrs = {
                k: v for k, v in normalised_row.items()
                if k not in KNOWN_FIELDS and v
            }

            roles_raw = normalised_row.get('roles', '')
            roles_to_assign = (
                _resolve(roles_raw, lambda name: Role.find_realm_role(realm_id, name))
                if roles_raw else []
            )

            groups_raw = normalised_row.get('groups', '')
            groups_to_assign = (
                _resolve(groups_raw, lambda name: Group.find_realm_group(realm_id, name))
                if groups_raw else []
            )

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
                        UserService.set_attributes(
                            existing_user, {k: [v] for k, v in extra_attrs.items()}
                        )
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

        return {
            'total_rows': total_rows,
            'imported': imported,
            'updated': updated,
            'skipped': skipped,
            'errors': errors,
        }

    @classmethod
    def import_roles(cls, realm_id, csv_raw):
        """Parse *csv_raw* and import roles synchronously.

        Returns a dict with keys ``total_rows``, ``imported``, ``skipped``,
        and ``errors``.
        """
        from apps import db
        from apps.models.role import Role

        rows = list(csv.DictReader(io.StringIO(csv_raw)))
        total_rows = len(rows)
        imported = 0
        skipped = 0
        errors = []

        for i, row in enumerate(rows):
            row_num = i + 2

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

        return {
            'total_rows': total_rows,
            'imported': imported,
            'updated': 0,
            'skipped': skipped,
            'errors': errors,
        }

    @classmethod
    def import_groups(cls, realm_id, csv_raw):
        """Parse *csv_raw* and import groups synchronously.

        Returns a dict with keys ``total_rows``, ``imported``, ``skipped``,
        and ``errors``.
        """
        from apps import db
        from apps.models.group import Group

        rows = list(csv.DictReader(io.StringIO(csv_raw)))
        total_rows = len(rows)
        imported = 0
        skipped = 0
        errors = []

        for i, row in enumerate(rows):
            row_num = i + 2

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

        return {
            'total_rows': total_rows,
            'imported': imported,
            'updated': 0,
            'skipped': skipped,
            'errors': errors,
        }
