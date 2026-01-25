# -*- encoding: utf-8 -*-
"""
RijanAuth - Admin API
REST API endpoints for admin console
"""

from flask import jsonify, request
from flask_login import login_required
from apps.blueprints.admin import admin_bp
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.client import Client
from apps.models.role import Role
from apps.models.group import Group
from apps.services.user_service import UserService
from apps.services.client_service import ClientService
from apps.logging import log_action
from apps import db


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
    """Update a user"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        return jsonify({'error': 'Realm not found'}), 404
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Update allowed fields
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
    
    db.session.commit()
    return jsonify(user.to_dict())


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
    
    mapper = UserFederationMapper(
        provider_id=provider.id,
        name=name,
        mapper_type=data.get('mapperType', 'user-attribute-ldap-mapper'),
        internal_attribute=data.get('internalAttribute'),
        external_attribute=data.get('externalAttribute'),
        config=data.get('config', {})
    )
    db.session.add(mapper)
    db.session.commit()
    
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
