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
from apps import db


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
