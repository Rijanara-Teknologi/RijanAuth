# -*- encoding: utf-8 -*-
"""
RijanAuth - Admin API
REST API endpoints for admin console
"""

import csv
import io

from flask import jsonify, request, Response
from flask_login import login_required
from sqlalchemy.exc import SQLAlchemyError
from apps.blueprints.admin import admin_bp
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.client import Client
from apps.models.role import Role
from apps.models.group import Group
from apps.models.import_job import ImportJob
from apps.services.user_service import UserService
from apps.services.client_service import ClientService
from apps.services.import_service import ImportService
from apps.logging import log_action
from apps import db


def _resolve_semicolon_list(raw, lookup_fn):
    """Split a semicolon-separated CSV field and resolve each token via *lookup_fn*.

    Tokens that resolve to ``None`` (i.e. the lookup returned nothing) are
    silently skipped.  Returns a list of resolved objects.
    """
    result = []
    for name in [s.strip() for s in raw.split(';') if s.strip()]:
        obj = lookup_fn(name)
        if obj:
            result.append(obj)
    return result


# =============================================================================
# System API
# =============================================================================

@admin_bp.route('/api/health', methods=['GET'])
def api_health():
    """System health check"""
    return jsonify({
        'status': 'ok', 
        'version': '2.1.1',
        'service': 'RijanAuth'
    })


# =============================================================================
# Realms API
# =============================================================================

@admin_bp.route('/api/realms', methods=['GET'])
@login_required
def api_list_realms():
    """List all realms"""
    realms = Realm.query.all()
    return jsonify([r.to_dict() for r in realms])


@admin_bp.route('/api/realms/<realm_name>', methods=['GET'])
@login_required
def api_get_realm(realm_name):
    """Get realm details"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    return jsonify(realm.to_dict())


# =============================================================================
# Users API
# =============================================================================

@admin_bp.route('/api/<realm_name>/users', methods=['GET'])
@login_required
def api_list_users(realm_name):
    """List users in a realm"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    search = request.args.get('search', '')
    first = request.args.get('first', 0, type=int)
    max_results = request.args.get('max', 20, type=int)
    
    if search:
        users = UserService.search_users(realm.id, search=search, first=first, max_results=max_results)
    else:
        users = User.query.filter_by(realm_id=realm.id).offset(first).limit(max_results).all()
    
    return jsonify([u.to_dict() for u in users])


@admin_bp.route('/api/<realm_name>/users/<user_id>', methods=['GET'])
@login_required
def api_get_user(realm_name, user_id):
    """Get user details"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict(include_attributes=True))


@admin_bp.route('/api/<realm_name>/users', methods=['POST'])
@login_required
@log_action(action="create_user", resource_type="user")
def api_create_user(realm_name):
    """Create a new user"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    if User.find_by_username(realm.id, username):
        return jsonify({'error': 'Username already exists'}), 409
    
    user = UserService.create_user(
        realm_id=realm.id,
        username=username,
        email=data.get('email'),
        first_name=data.get('firstName'),
        last_name=data.get('lastName'),
        enabled=data.get('enabled', True)
    )
    
    # Set password if provided
    if data.get('credentials'):
        for cred in data['credentials']:
            if cred.get('type') == 'password' and cred.get('value'):
                UserService.set_password(user, cred['value'])
    
    return jsonify(user.to_dict()), 201


@admin_bp.route('/api/<realm_name>/users/<user_id>', methods=['PUT'])
@login_required
@log_action(action="update_user", resource_type="user")
def api_update_user(realm_name, user_id):
    """Update a user.

    Standard fields (all optional):
        email, firstName, lastName, enabled, emailVerified

    Custom attributes are supplied under the ``attributes`` key as a
    JSON object whose values may be a string or a list of strings::

        {
            "firstName": "Alice",
            "attributes": {
                "phone": "+62811...",
                "department": ["Engineering"]
            }
        }
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Update standard fields
    if 'email' in data:
        user.email = data['email']
    if 'firstName' in data:
        user.first_name = data['firstName']
    if 'lastName' in data:
        user.last_name = data['lastName']
    if 'enabled' in data:
        user.enabled = data['enabled']
    if 'emailVerified' in data:
        user.email_verified = data['emailVerified']

    # Update custom attributes
    if 'attributes' in data:
        attrs = data['attributes']
        if not isinstance(attrs, dict):
            return jsonify({'error': 'attributes must be a JSON object'}), 400
        # Normalise values to lists of strings
        normalised = {}
        for key, val in attrs.items():
            if isinstance(val, list):
                normalised[key] = [str(v) for v in val]
            else:
                normalised[key] = [str(val)]
        UserService.set_attributes(user, normalised)

    db.session.commit()
    return jsonify(user.to_dict(include_attributes=True))


@admin_bp.route('/api/<realm_name>/users/<user_id>', methods=['DELETE'])
@login_required
@log_action(action="delete_user", resource_type="user")
def api_delete_user(realm_name, user_id):
    """Delete a user"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        return jsonify({'error': 'User not found'}), 404
    
    UserService.delete_user(user)
    return '', 204


@admin_bp.route('/api/<realm_name>/users/<user_id>/reset-password', methods=['PUT'])
@login_required
@log_action(action="reset_password", resource_type="user")
def api_reset_password(realm_name, user_id):
    """Reset user password"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data or not data.get('value'):
        return jsonify({'error': 'Password value is required'}), 400
    
    UserService.set_password(user, data['value'])
    return '', 204


@admin_bp.route('/api/<realm_name>/users/import', methods=['POST'])
@login_required
@log_action(action="import_users", resource_type="user")
def api_import_users(realm_name):
    """Import users from a CSV file.

    The CSV must contain at minimum a ``username`` column.  All other
    columns are optional but recognised:

    * ``email``      – user e-mail address
    * ``password``   – plain-text password (will be hashed on import)
    * ``name``       – full name; split on the first space into
                       first_name / last_name
    * ``first_name`` / ``firstName`` – first name
    * ``last_name``  / ``lastName``  – last name
    * ``roles``      – semicolon-separated realm role names; only roles
                       that exist in the realm are assigned (invalid names
                       are silently skipped)
    * ``groups``     – semicolon-separated group names; only groups
                       that exist in the realm are assigned (invalid names
                       are silently skipped)

    Any additional column is stored as a custom user attribute.

    Upload the file using ``multipart/form-data`` with the field name
    ``file``, or send raw CSV text with ``Content-Type: text/csv``.

    Returns the import result directly::

        {
            "total_rows": 300,
            "imported":   295,
            "updated":      5,
            "skipped":      0,
            "errors":      []
        }
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    # Obtain CSV content from either a file upload or raw body
    if 'file' in request.files:
        file = request.files['file']
        raw = file.read().decode('utf-8-sig')
    elif request.content_type and 'text/csv' in request.content_type:
        raw = request.data.decode('utf-8-sig')
    else:
        return jsonify({'error': 'Provide a CSV file via multipart/form-data (field "file") or raw CSV with Content-Type: text/csv'}), 400

    result = ImportService.import_users(realm.id, raw)
    return jsonify(result), 200


@admin_bp.route('/api/<realm_name>/users/export', methods=['GET'])
@login_required
@log_action(action="export_users", resource_type="user")
def api_export_users(realm_name):
    """Export all users in a realm as a CSV file.

    The exported CSV contains the following columns:

    * ``id``         – user UUID
    * ``username``   – username
    * ``email``      – e-mail address
    * ``first_name`` – first name
    * ``last_name``  – last name
    * ``roles``      – semicolon-separated realm role names
    * ``groups``     – semicolon-separated group names

    Returns a ``text/csv`` response with a
    ``Content-Disposition: attachment`` header.
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    users = User.query.filter_by(realm_id=realm.id).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'username', 'email', 'first_name', 'last_name', 'roles', 'groups'])
    for user in users:
        user_roles = UserService.get_user_roles(user)
        user_groups = UserService.get_user_groups(user)
        roles_str = ';'.join(r.name for r in user_roles)
        groups_str = ';'.join(g.name for g in user_groups)
        writer.writerow([
            user.id,
            user.username,
            user.email or '',
            user.first_name or '',
            user.last_name or '',
            roles_str,
            groups_str,
        ])

    csv_content = output.getvalue()
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=users_export_{realm_name}.csv'}
    )


# =============================================================================
# Import Job Status API
# =============================================================================

@admin_bp.route('/api/<realm_name>/import-jobs/<job_id>', methods=['GET'])
@login_required
def api_get_import_job(realm_name, job_id):
    """Get the status and result of an asynchronous import job.

    Returns a JSON object with the current job state::

        {
            "id": "<uuid>",
            "job_type": "users",
            "status": "completed",
            "total_rows": 300,
            "processed_rows": 300,
            "imported": 295,
            "updated": 5,
            "skipped": 0,
            "errors": [],
            "created_at": "...",
            "started_at": "...",
            "finished_at": "..."
        }

    ``status`` is one of ``pending``, ``processing``, ``completed``, ``failed``.
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    job = ImportJob.find_by_id(job_id)
    if not job or job.realm_id != realm.id:
        return jsonify({'error': 'Import job not found'}), 404

    return jsonify(job.to_dict()), 200


@admin_bp.route('/api/<realm_name>/import-jobs', methods=['GET'])
@login_required
def api_list_import_jobs(realm_name):
    """List all import jobs for a realm (most recent first)."""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    jobs = ImportJob.find_by_realm(realm.id)
    return jsonify([j.to_dict() for j in jobs]), 200


# =============================================================================
# Clients API
# =============================================================================

@admin_bp.route('/api/<realm_name>/clients', methods=['GET'])
@login_required
def api_list_clients(realm_name):
    """List clients in a realm"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    clients = ClientService.get_clients(realm.id)
    return jsonify([c.to_dict() for c in clients])


@admin_bp.route('/api/<realm_name>/clients/<client_id>', methods=['GET'])
@login_required
def api_get_client(realm_name, client_id):
    """Get client details"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    client = Client.find_by_id(client_id)
    if not client or client.realm_id != realm.id:
        return jsonify({'error': 'Client not found'}), 404
    
    return jsonify(client.to_dict())


# =============================================================================
# Roles API
# =============================================================================

@admin_bp.route('/api/<realm_name>/roles', methods=['GET'])
@login_required
def api_list_roles(realm_name):
    """List realm roles"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    roles = Role.get_realm_roles(realm.id)
    return jsonify([r.to_dict() for r in roles])


@admin_bp.route('/api/<realm_name>/roles/export', methods=['GET'])
@login_required
@log_action(action="export_roles", resource_type="role")
def api_export_roles(realm_name):
    """Export all realm roles as a CSV file.

    The exported CSV contains the following columns:

    * ``name``        – role name
    * ``description`` – role description

    Returns a ``text/csv`` response with a
    ``Content-Disposition: attachment`` header.
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    roles = Role.get_realm_roles(realm.id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['name', 'description'])
    for role in roles:
        writer.writerow([role.name, role.description or ''])

    csv_content = output.getvalue()
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=roles_export_{realm_name}.csv'}
    )


@admin_bp.route('/api/<realm_name>/roles/import', methods=['POST'])
@login_required
@log_action(action="import_roles", resource_type="role")
def api_import_roles(realm_name):
    """Import realm roles from a CSV file.

    The CSV must contain at minimum a ``name`` column.  The optional
    ``description`` column is also recognised.

    Role names are automatically normalised: converted to lowercase and
    spaces replaced with underscores (e.g. ``Guru Quran`` → ``guru_quran``).

    Roles whose normalised name already exists in the realm are skipped.

    Upload the file using ``multipart/form-data`` with the field name
    ``file``, or send raw CSV text with ``Content-Type: text/csv``.

    Returns the import result directly::

        {
            "total_rows": 50,
            "imported":   48,
            "updated":     0,
            "skipped":     2,
            "errors":     [...]
        }
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    if 'file' in request.files:
        file = request.files['file']
        raw = file.read().decode('utf-8-sig')
    elif request.content_type and 'text/csv' in request.content_type:
        raw = request.data.decode('utf-8-sig')
    else:
        return jsonify({'error': 'Provide a CSV file via multipart/form-data (field "file") or raw CSV with Content-Type: text/csv'}), 400

    result = ImportService.import_roles(realm.id, raw)
    return jsonify(result), 200


# =============================================================================
# Groups API
# =============================================================================

@admin_bp.route('/api/<realm_name>/groups', methods=['GET'])
@login_required
def api_list_groups(realm_name):
    """List groups in a realm"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    groups = Group.get_top_level_groups(realm.id)
    return jsonify([g.to_dict(include_subgroups=True) for g in groups])


@admin_bp.route('/api/<realm_name>/groups/export', methods=['GET'])
@login_required
@log_action(action="export_groups", resource_type="group")
def api_export_groups(realm_name):
    """Export all top-level realm groups as a CSV file.

    The exported CSV contains the following column:

    * ``name`` – group name

    Returns a ``text/csv`` response with a
    ``Content-Disposition: attachment`` header.
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    groups = Group.get_top_level_groups(realm.id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['name'])
    for group in groups:
        writer.writerow([group.name])

    csv_content = output.getvalue()
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=groups_export_{realm_name}.csv'}
    )


@admin_bp.route('/api/<realm_name>/groups/import', methods=['POST'])
@login_required
@log_action(action="import_groups", resource_type="group")
def api_import_groups(realm_name):
    """Import realm groups from a CSV file.

    The CSV must contain at minimum a ``name`` column.  Group names are
    stored exactly as provided (no formatting is applied).

    Groups whose name already exists as a top-level group in the realm
    are skipped.

    Upload the file using ``multipart/form-data`` with the field name
    ``file``, or send raw CSV text with ``Content-Type: text/csv``.

    Returns the import result directly::

        {
            "total_rows": 50,
            "imported":   48,
            "updated":     0,
            "skipped":     2,
            "errors":     [...]
        }
    """
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404

    if 'file' in request.files:
        file = request.files['file']
        raw = file.read().decode('utf-8-sig')
    elif request.content_type and 'text/csv' in request.content_type:
        raw = request.data.decode('utf-8-sig')
    else:
        return jsonify({'error': 'Provide a CSV file via multipart/form-data (field "file") or raw CSV with Content-Type: text/csv'}), 400

    result = ImportService.import_groups(realm.id, raw)
    return jsonify(result), 200


# =============================================================================
# User Federation API
# =============================================================================

@admin_bp.route('/api/<realm_name>/user-federation', methods=['GET'])
@login_required
def api_list_federation_providers(realm_name):
    """List user federation providers"""
    from apps.models.federation import UserFederationProvider
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    providers = UserFederationProvider.find_by_realm(realm.id)
    return jsonify([p.to_dict() for p in providers])


@admin_bp.route('/api/<realm_name>/user-federation', methods=['POST'])
@login_required
def api_create_federation_provider(realm_name):
    """Create a new federation provider"""
    from apps.services.federation import FederationService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    name = data.get('name')
    provider_type = data.get('providerType')
    config = data.get('config', {})
    
    if not name:
        return jsonify({'error': 'Provider name is required'}), 400
    if not provider_type:
        return jsonify({'error': 'Provider type is required'}), 400
    
    available_types = FederationService.get_available_providers()
    if provider_type not in available_types:
        return jsonify({'error': f'Unknown provider type: {provider_type}'}), 400
    
    try:
        provider = FederationService.create_provider(
            realm_id=realm.id,
            name=name,
            provider_type=provider_type,
            config=config,
            display_name=data.get('displayName', name),
            enabled=data.get('enabled', True),
            priority=data.get('priority', 0),
            import_enabled=data.get('importEnabled', True),
            full_sync_period=data.get('fullSyncPeriod', -1),
            changed_sync_period=data.get('changedSyncPeriod', -1),
        )
        return jsonify(provider.to_dict()), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>', methods=['GET'])
@login_required
def api_get_federation_provider(realm_name, provider_id):
    """Get federation provider details"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import FederationService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    result = provider.to_dict(include_config=True)
    
    # Mask sensitive fields
    provider_class = FederationService.get_provider_class(provider.provider_type)
    if provider_class and 'config' in result:
        for key in provider_class.SENSITIVE_CONFIG_KEYS:
            if key in result['config']:
                result['config'][key] = '********'
    
    return jsonify(result)


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>', methods=['PUT'])
@login_required
def api_update_federation_provider(realm_name, provider_id):
    """Update federation provider"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import FederationService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    try:
        updated = FederationService.update_provider(
            provider_id=provider.id,
            config=data.get('config'),
            display_name=data.get('displayName'),
            enabled=data.get('enabled'),
            priority=data.get('priority'),
            import_enabled=data.get('importEnabled'),
            full_sync_period=data.get('fullSyncPeriod'),
            changed_sync_period=data.get('changedSyncPeriod'),
        )
        return jsonify(updated.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>', methods=['DELETE'])
@login_required
def api_delete_federation_provider(realm_name, provider_id):
    """Delete federation provider"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import FederationService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    FederationService.delete_provider(provider.id)
    return '', 204


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/test-connection', methods=['POST'])
@login_required
def api_test_federation_connection(realm_name, provider_id):
    """Test federation provider connection"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import FederationService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    result = FederationService.test_provider_connection(provider.id)
    return jsonify(result)


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/sync', methods=['POST'])
@login_required
def api_sync_federation_users(realm_name, provider_id):
    """Trigger federation user sync"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import SyncService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    data = request.get_json() or {}
    sync_type = data.get('type', 'full')
    
    if sync_type == 'changed':
        result = SyncService.sync_changed_users(provider.id)
    else:
        result = SyncService.sync_all_users(provider.id)
    
    return jsonify(result)


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/sync-status', methods=['GET'])
@login_required
def api_get_federation_sync_status(realm_name, provider_id):
    """Get federation sync status"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import SyncService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    status = SyncService.get_sync_status(provider.id)
    return jsonify(status)


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/mappers', methods=['GET'])
@login_required
def api_list_federation_mappers(realm_name, provider_id):
    """List federation provider mappers"""
    from apps.models.federation import UserFederationProvider, UserFederationMapper
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    mappers = UserFederationMapper.find_by_provider(provider.id)
    return jsonify([m.to_dict() for m in mappers])


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/mappers', methods=['POST'])
@login_required
def api_create_federation_mapper(realm_name, provider_id):
    """Create federation mapper"""
    from apps.models.federation import UserFederationProvider, UserFederationMapper
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Mapper name is required'}), 400
    
    mapper_type = data.get('mapperType', 'user-attribute-ldap-mapper')
    mapper = UserFederationMapper(
        provider_id=provider.id,
        name=name,
        mapper_type=mapper_type,
        internal_attribute=data.get('internalAttribute'),
        external_attribute=data.get('externalAttribute'),
        config=data.get('config', {})
    )
    db.session.add(mapper)
    db.session.commit()

    # Auto-create a corresponding protocol mapper so the custom attribute
    # appears in JWT tokens and userinfo responses.
    from apps.services.federation.federation_service import FederationService
    FederationService.ensure_protocol_mapper_for_attribute(
        realm.id,
        data.get('internalAttribute'),
        mapper_type,
    )

    return jsonify(mapper.to_dict()), 201


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/mappers/<mapper_id>', methods=['DELETE'])
@login_required
def api_delete_federation_mapper(realm_name, provider_id, mapper_id):
    """Delete federation mapper"""
    from apps.models.federation import UserFederationProvider, UserFederationMapper
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    mapper = UserFederationMapper.query.get(mapper_id)
    if not mapper or mapper.provider_id != provider.id:
        return jsonify({'error': 'Mapper not found'}), 404
    
    db.session.delete(mapper)
    db.session.commit()
    
    return '', 204


# =============================================================================
# Federation Role Mappings API
# =============================================================================

@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-mappings', methods=['GET'])
@login_required
def api_list_role_mappings(realm_name, provider_id):
    """List role mappings for a federation provider"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    mappings = FederationRoleMapping.find_by_provider(provider_id)
    return jsonify([m.to_dict() for m in mappings])


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-mappings', methods=['POST'])
@login_required
def api_create_role_mapping(realm_name, provider_id):
    """Create a role mapping for a federation provider"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    external_role = data.get('external_role_name', '').strip()
    internal_role_id = data.get('internal_role_id', '').strip()
    
    if not external_role or not internal_role_id:
        return jsonify({'error': 'external_role_name and internal_role_id are required'}), 400
    
    # Check if mapping already exists
    existing = FederationRoleMapping.query.filter_by(
        provider_id=provider_id, external_role_name=external_role
    ).first()
    if existing:
        return jsonify({'error': f'Mapping for "{external_role}" already exists'}), 409
    
    mapping = FederationRoleMapping(
        provider_id=provider_id,
        external_role_name=external_role,
        internal_role_id=internal_role_id,
        mapping_type=data.get('mapping_type', 'direct'),
        mapping_value=data.get('mapping_value'),
        priority=int(data.get('priority', 0)),
        enabled=data.get('enabled', True)
    )
    db.session.add(mapping)
    db.session.commit()
    
    return jsonify(mapping.to_dict()), 201


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-mappings/<mapping_id>', methods=['GET'])
@login_required
def api_get_role_mapping(realm_name, provider_id, mapping_id):
    """Get a specific role mapping"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    mapping = FederationRoleMapping.query.get(mapping_id)
    if not mapping or mapping.provider_id != provider_id:
        return jsonify({'error': 'Mapping not found'}), 404
    
    return jsonify(mapping.to_dict())


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-mappings/<mapping_id>', methods=['PUT'])
@login_required
def api_update_role_mapping(realm_name, provider_id, mapping_id):
    """Update a role mapping"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    from datetime import datetime
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    mapping = FederationRoleMapping.query.get(mapping_id)
    if not mapping or mapping.provider_id != provider_id:
        return jsonify({'error': 'Mapping not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    if 'external_role_name' in data:
        mapping.external_role_name = data['external_role_name']
    if 'internal_role_id' in data:
        mapping.internal_role_id = data['internal_role_id']
    if 'mapping_type' in data:
        mapping.mapping_type = data['mapping_type']
    if 'mapping_value' in data:
        mapping.mapping_value = data['mapping_value']
    if 'priority' in data:
        mapping.priority = int(data['priority'])
    if 'enabled' in data:
        mapping.enabled = data['enabled']
    
    mapping.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify(mapping.to_dict())


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-mappings/<mapping_id>', methods=['DELETE'])
@login_required
def api_delete_role_mapping(realm_name, provider_id, mapping_id):
    """Delete a role mapping"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    mapping = FederationRoleMapping.query.get(mapping_id)
    if not mapping or mapping.provider_id != provider_id:
        return jsonify({'error': 'Mapping not found'}), 404
    
    db.session.delete(mapping)
    db.session.commit()
    
    return '', 204


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-format', methods=['GET'])
@login_required
def api_get_role_format_config(realm_name, provider_id):
    """Get role format configuration for a provider"""
    from apps.models.federation import UserFederationProvider, FederationRoleFormatConfig
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    config = FederationRoleFormatConfig.get_for_provider(provider_id)
    return jsonify(config.to_dict() if config.id else {
        'format_type': 'string',
        'delimiter': ',',
        'role_field': 'roles',
        'auto_detect': True
    })


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-format', methods=['PUT'])
@login_required
def api_update_role_format_config(realm_name, provider_id):
    """Update role format configuration for a provider"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import RoleSyncService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    config = RoleSyncService.configure_role_format(
        provider_id=provider_id,
        format_type=data.get('format_type', 'string'),
        delimiter=data.get('delimiter', ','),
        array_path=data.get('array_path'),
        format_pattern=data.get('format_pattern'),
        role_field=data.get('role_field', 'roles'),
        auto_detect=data.get('auto_detect', True)
    )
    
    return jsonify(config.to_dict())


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/test-role-format', methods=['POST'])
@login_required
def api_test_role_format(realm_name, provider_id):
    """Test role format detection with sample data"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import RoleSyncService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    data = request.get_json()
    if not data or 'sample_data' not in data:
        return jsonify({'error': 'sample_data is required'}), 400
    
    result = RoleSyncService.test_role_format(
        data=data['sample_data'],
        format_type=data.get('format_type'),
        delimiter=data.get('delimiter'),
        array_path=data.get('array_path'),
        pattern=data.get('pattern')
    )
    
    return jsonify(result)


@admin_bp.route('/api/<realm_name>/user-federation/<provider_id>/role-sync-history', methods=['GET'])
@login_required
def api_role_sync_history(realm_name, provider_id):
    """Get role synchronization history for a provider"""
    from apps.models.federation import UserFederationProvider, FederatedRoleSync
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        return jsonify({'error': 'Provider not found'}), 404
    
    limit = request.args.get('limit', 50, type=int)
    syncs = FederatedRoleSync.query.filter_by(provider_id=provider_id)\
        .order_by(FederatedRoleSync.last_sync.desc()).limit(limit).all()
    
    return jsonify([s.to_dict() for s in syncs])


@admin_bp.route('/api/<realm_name>/users/<user_id>/role-sync-history', methods=['GET'])
@login_required
def api_user_role_sync_history(realm_name, user_id):
    """Get role synchronization history for a specific user"""
    from apps.models.federation import FederatedRoleSync
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    user = User.query.get(user_id)
    if not user or user.realm_id != realm.id:
        return jsonify({'error': 'User not found'}), 404
    
    limit = request.args.get('limit', 20, type=int)
    syncs = FederatedRoleSync.get_history(user_id, limit=limit)
    
    return jsonify([s.to_dict() for s in syncs])


# =============================================================================
# Protocol Mappers API
# =============================================================================

@admin_bp.route('/api/<realm_name>/clients/<client_id>/protocol-mappers', methods=['GET'])
@login_required
def api_list_client_mappers(realm_name, client_id):
    """List protocol mappers for a client"""
    from apps.models.client import ProtocolMapper
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        return jsonify({'error': 'Client not found'}), 404
    
    mappers = ProtocolMapper.find_by_client(client_id)
    return jsonify([m.to_dict() for m in mappers])


@admin_bp.route('/api/<realm_name>/clients/<client_id>/protocol-mappers', methods=['POST'])
@login_required
def api_create_client_mapper(realm_name, client_id):
    """Create a protocol mapper for a client"""
    from apps.models.client import ProtocolMapper
    from apps.services.mapper_service import MapperService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        return jsonify({'error': 'Client not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    name = data.get('name')
    mapper_type = data.get('protocolMapper')
    config = data.get('config', {})
    
    if not name:
        return jsonify({'error': 'Mapper name is required'}), 400
    if not mapper_type:
        return jsonify({'error': 'protocolMapper type is required'}), 400
    
    # Validate config
    errors = MapperService.validate_mapper_config(mapper_type, config)
    if errors:
        return jsonify({'error': 'Invalid configuration', 'details': errors}), 400
    
    mapper = ProtocolMapper(
        name=name,
        protocol=data.get('protocol', 'openid-connect'),
        protocol_mapper=mapper_type,
        client_id=client_id,
        config=config,
        priority=data.get('priority', 0)
    )
    db.session.add(mapper)
    db.session.commit()
    
    return jsonify(mapper.to_dict()), 201


@admin_bp.route('/api/<realm_name>/clients/<client_id>/protocol-mappers/<mapper_id>', methods=['GET'])
@login_required
def api_get_client_mapper(realm_name, client_id, mapper_id):
    """Get a specific protocol mapper"""
    from apps.models.client import ProtocolMapper
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        return jsonify({'error': 'Client not found'}), 404
    
    mapper = ProtocolMapper.query.get(mapper_id)
    if not mapper or mapper.client_id != client_id:
        return jsonify({'error': 'Mapper not found'}), 404
    
    return jsonify(mapper.to_dict())


@admin_bp.route('/api/<realm_name>/clients/<client_id>/protocol-mappers/<mapper_id>', methods=['PUT'])
@login_required
def api_update_client_mapper(realm_name, client_id, mapper_id):
    """Update a protocol mapper"""
    from apps.models.client import ProtocolMapper
    from apps.services.mapper_service import MapperService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        return jsonify({'error': 'Client not found'}), 404
    
    mapper = ProtocolMapper.query.get(mapper_id)
    if not mapper or mapper.client_id != client_id:
        return jsonify({'error': 'Mapper not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    # Validate config if provided
    if 'config' in data:
        errors = MapperService.validate_mapper_config(mapper.protocol_mapper, data['config'])
        if errors:
            return jsonify({'error': 'Invalid configuration', 'details': errors}), 400
        mapper.config = data['config']
    
    if 'name' in data:
        mapper.name = data['name']
    if 'priority' in data:
        mapper.priority = data['priority']
    
    db.session.commit()
    return jsonify(mapper.to_dict())


@admin_bp.route('/api/<realm_name>/clients/<client_id>/protocol-mappers/<mapper_id>', methods=['DELETE'])
@login_required
def api_delete_client_mapper(realm_name, client_id, mapper_id):
    """Delete a protocol mapper"""
    from apps.models.client import ProtocolMapper
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        return jsonify({'error': 'Client not found'}), 404
    
    mapper = ProtocolMapper.query.get(mapper_id)
    if not mapper or mapper.client_id != client_id:
        return jsonify({'error': 'Mapper not found'}), 404
    
    db.session.delete(mapper)
    db.session.commit()
    
    return '', 204


# =============================================================================
# Client Scopes API
# =============================================================================

@admin_bp.route('/api/<realm_name>/client-scopes', methods=['GET'])
@login_required
def api_list_client_scopes(realm_name):
    """List client scopes for a realm"""
    from apps.models.client import ClientScope
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    scopes = ClientScope.query.filter_by(realm_id=realm.id).order_by(ClientScope.name).all()
    return jsonify([s.to_dict() for s in scopes])


@admin_bp.route('/api/<realm_name>/client-scopes/<scope_id>', methods=['GET'])
@login_required
def api_get_client_scope(realm_name, scope_id):
    """Get client scope details"""
    from apps.models.client import ClientScope
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        return jsonify({'error': 'Client scope not found'}), 404
    
    return jsonify(scope.to_dict())


@admin_bp.route('/api/<realm_name>/client-scopes/<scope_id>/protocol-mappers', methods=['GET'])
@login_required
def api_list_scope_mappers(realm_name, scope_id):
    """List protocol mappers for a client scope"""
    from apps.models.client import ClientScope, ProtocolMapper
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        return jsonify({'error': 'Client scope not found'}), 404
    
    mappers = ProtocolMapper.find_by_client_scope(scope_id)
    return jsonify([m.to_dict() for m in mappers])


@admin_bp.route('/api/<realm_name>/client-scopes/<scope_id>/protocol-mappers', methods=['POST'])
@login_required
def api_create_scope_mapper(realm_name, scope_id):
    """Create a protocol mapper for a client scope"""
    from apps.models.client import ClientScope, ProtocolMapper
    from apps.services.mapper_service import MapperService
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        return jsonify({'error': 'Client scope not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    name = data.get('name')
    mapper_type = data.get('protocolMapper')
    config = data.get('config', {})
    
    if not name:
        return jsonify({'error': 'Mapper name is required'}), 400
    if not mapper_type:
        return jsonify({'error': 'protocolMapper type is required'}), 400
    
    # Validate config
    errors = MapperService.validate_mapper_config(mapper_type, config)
    if errors:
        return jsonify({'error': 'Invalid configuration', 'details': errors}), 400
    
    mapper = ProtocolMapper(
        name=name,
        protocol=data.get('protocol', 'openid-connect'),
        protocol_mapper=mapper_type,
        client_scope_id=scope_id,
        config=config,
        priority=data.get('priority', 0)
    )
    db.session.add(mapper)
    db.session.commit()
    
    return jsonify(mapper.to_dict()), 201


# =============================================================================
# Token Preview API
# =============================================================================

@admin_bp.route('/api/<realm_name>/clients/<client_id>/token-preview', methods=['GET'])
@login_required
def api_token_preview(realm_name, client_id):
    """Generate a preview of what tokens would look like with current mappers"""
    from apps.services.mapper_service import MapperService
    from flask_login import current_user
    
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        return jsonify({'error': 'Client not found'}), 404
    
    # Use current user or specified user for preview
    user_id = request.args.get('user_id', current_user.id)
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    token_type = request.args.get('token_type', 'access')
    scopes = request.args.get('scope', 'openid profile email')
    
    try:
        preview = MapperService.preview_token(client, user, token_type, scopes)
        return jsonify({
            'tokenType': token_type,
            'scope': scopes,
            'preview': preview
        })
    except Exception as e:
        return jsonify({'error': f'Error generating preview: {str(e)}'}), 500
