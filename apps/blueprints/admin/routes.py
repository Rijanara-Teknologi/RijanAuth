# -*- encoding: utf-8 -*-
"""
RijanAuth - Admin Routes
Web routes for the administration console
"""

from flask import render_template, redirect, url_for, request, flash, g
from flask_login import login_required, current_user
from apps.blueprints.admin import admin_bp
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.client import Client
from apps.models.role import Role
from apps.models.group import Group
from apps.models.session import UserSession
from apps.models.event import Event
from apps.services.realm_service import RealmService
from apps.services.user_service import UserService
from apps.services.client_service import ClientService


def get_realm_or_404(realm_name):
    """Get realm by name or return 404"""
    realm = Realm.find_by_name(realm_name)
    if not realm:
        flash(f'Realm "{realm_name}" not found', 'error')
        return None
    return realm


# =============================================================================
# Dashboard
# =============================================================================

@admin_bp.route('/')
@login_required
def index():
    """Redirect to master realm dashboard"""
    return redirect(url_for('admin.dashboard', realm_name='master'))


@admin_bp.route('/<realm_name>')
@admin_bp.route('/<realm_name>/dashboard')
@login_required
def dashboard(realm_name):
    """Admin dashboard for a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    # Get statistics
    stats = {
        'users': User.query.filter_by(realm_id=realm.id).count(),
        'clients': Client.query.filter_by(realm_id=realm.id).count(),
        'groups': Group.query.filter_by(realm_id=realm.id).count(),
        'sessions': UserSession.query.filter_by(realm_id=realm.id, state='ACTIVE').count(),
    }
    
    # Get recent events
    recent_events = Event.get_events(realm.id, max_results=10)
    
    # Get all realms for selector
    realms = Realm.query.all()
    
    return render_template(
        'admin/dashboard.html',
        realm=realm,
        realms=realms,
        stats=stats,
        recent_events=recent_events,
        segment='dashboard'
    )


# =============================================================================
# Realm Management
# =============================================================================

@admin_bp.route('/<realm_name>/settings', methods=['GET', 'POST'])
@login_required
def realm_settings(realm_name):
    """Realm settings page"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    if request.method == 'POST':
        # General settings
        realm.display_name = request.form.get('display_name', '').strip() or None
        realm.enabled = request.form.get('enabled') == 'on'
        
        # Login settings
        realm.registration_allowed = request.form.get('registration_allowed') == 'on'
        realm.verify_email = request.form.get('verify_email') == 'on'
        realm.login_with_email_allowed = request.form.get('login_with_email_allowed') == 'on'
        realm.remember_me = request.form.get('remember_me') == 'on'
        realm.reset_password_allowed = request.form.get('reset_password_allowed') == 'on'
        
        # Email/SMTP settings
        realm.smtp_server = request.form.get('smtp_host', '').strip() or None
        realm.smtp_port = request.form.get('smtp_port', '').strip() or None
        realm.smtp_from = request.form.get('smtp_from', '').strip() or None
        
        # Token settings
        try:
            realm.access_token_lifespan = int(request.form.get('access_token_lifespan', 300))
        except (ValueError, TypeError):
            realm.access_token_lifespan = 300
            
        try:
            realm.sso_session_idle_timeout = int(request.form.get('sso_idle_timeout', 1800))
        except (ValueError, TypeError):
            realm.sso_session_idle_timeout = 1800
            
        try:
            realm.sso_session_max_lifespan = int(request.form.get('sso_max', 36000))
        except (ValueError, TypeError):
            realm.sso_session_max_lifespan = 36000
            
        try:
            realm.offline_session_idle_timeout = int(request.form.get('offline_idle', 2592000))
        except (ValueError, TypeError):
            realm.offline_session_idle_timeout = 2592000
        
        # Security settings
        realm.brute_force_protected = request.form.get('brute_force_protected') == 'on'
        try:
            realm.max_login_failures = int(request.form.get('max_login_failures', 30))
        except (ValueError, TypeError):
            realm.max_login_failures = 30
            
        try:
            realm.wait_increment_seconds = int(request.form.get('wait_increment', 60))
        except (ValueError, TypeError):
            realm.wait_increment_seconds = 60
        
        # Save changes
        realm.save()
        flash('Realm settings saved successfully', 'success')
        return redirect(url_for('admin.realm_settings', realm_name=realm_name))
    
    realms = Realm.query.all()
    return render_template(
        'admin/realms/settings.html',
        realm=realm,
        realms=realms,
        segment='realm-settings'
    )


@admin_bp.route('/realms/create', methods=['GET', 'POST'])
@login_required
def create_realm():
    """Create new realm"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip().lower()
        display_name = request.form.get('display_name', '').strip()
        
        if not name:
            flash('Realm name is required', 'error')
        elif Realm.find_by_name(name):
            flash(f'Realm "{name}" already exists', 'error')
        else:
            realm = RealmService.create_realm(name, display_name or name.title())
            flash(f'Realm "{name}" created successfully', 'success')
            return redirect(url_for('admin.dashboard', realm_name=name))
    
    realms = Realm.query.all()
    return render_template(
        'admin/realms/create.html',
        realms=realms,
        segment='create-realm'
    )


# =============================================================================
# User Management
# =============================================================================

@admin_bp.route('/<realm_name>/users')
@login_required
def users_list(realm_name):
    """List users in a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    # Get users
    if search:
        users = UserService.search_users(realm.id, search=search, first=(page-1)*per_page, max_results=per_page)
    else:
        users = User.query.filter_by(realm_id=realm.id).offset((page-1)*per_page).limit(per_page).all()
    
    total_users = User.query.filter_by(realm_id=realm.id).count()
    
    realms = Realm.query.all()
    return render_template(
        'admin/users/list.html',
        realm=realm,
        realms=realms,
        users=users,
        total_users=total_users,
        page=page,
        per_page=per_page,
        search=search,
        segment='users'
    )


@admin_bp.route('/<realm_name>/users/create', methods=['GET', 'POST'])
@login_required
def create_user(realm_name):
    """Create new user"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        password = request.form.get('password', '')
        enabled = request.form.get('enabled') == 'on'
        
        if not username:
            flash('Username is required', 'error')
        elif User.find_by_username(realm.id, username):
            flash(f'Username "{username}" already exists', 'error')
        else:
            user = UserService.create_user(
                realm_id=realm.id,
                username=username,
                email=email or None,
                first_name=first_name or None,
                last_name=last_name or None,
                password=password if password else None,
                enabled=enabled
            )
            flash(f'User "{username}" created successfully', 'success')
            return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user.id))
    
    realms = Realm.query.all()
    return render_template(
        'admin/users/create.html',
        realm=realm,
        realms=realms,
        segment='users'
    )


@admin_bp.route('/<realm_name>/users/<user_id>')
@login_required
def user_detail(realm_name, user_id):
    """User detail page"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        flash('User not found', 'error')
        return redirect(url_for('admin.users_list', realm_name=realm_name))
    
    # Get user data
    realm_roles = UserService.get_user_roles(user)
    groups = UserService.get_user_groups(user)
    sessions = user.sessions.filter_by(state='ACTIVE').all()
    
    realms = Realm.query.all()
    return render_template(
        'admin/users/detail.html',
        realm=realm,
        realms=realms,
        user=user,
        realm_roles=realm_roles,
        groups=groups,
        sessions=sessions,
        segment='users'
    )


# =============================================================================
# Client Management
# =============================================================================

@admin_bp.route('/<realm_name>/clients')
@login_required
def clients_list(realm_name):
    """List clients in a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    search = request.args.get('search', '')
    clients = ClientService.get_clients(realm.id, search=search if search else None)
    
    realms = Realm.query.all()
    return render_template(
        'admin/clients/list.html',
        realm=realm,
        realms=realms,
        clients=clients,
        search=search,
        segment='clients'
    )


@admin_bp.route('/<realm_name>/clients/create', methods=['GET', 'POST'])
@login_required
def create_client(realm_name):
    """Create new client"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    if request.method == 'POST':
        client_id = request.form.get('client_id', '').strip()
        name = request.form.get('name', '').strip()
        client_type = request.form.get('client_type', 'confidential')
        
        if not client_id:
            flash('Client ID is required', 'error')
        elif Client.find_by_client_id(realm.id, client_id):
            flash(f'Client ID "{client_id}" already exists', 'error')
        else:
            # Create client
            public_client = (client_type == 'public')
            client = ClientService.create_client(
                realm_id=realm.id,
                client_id=client_id,
                name=name or client_id,
                public_client=public_client,
                enabled=True
            )
            flash(f'Client "{client_id}" created successfully', 'success')
            return redirect(url_for('admin.client_detail', realm_name=realm_name, client_id=client.id))
    
    # If GET or validation failed, redirect back to clients list
    return redirect(url_for('admin.clients_list', realm_name=realm_name))


@admin_bp.route('/<realm_name>/clients/<client_id>')
@login_required
def client_detail(realm_name, client_id):
    """Client detail page"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    client = Client.find_by_id(client_id)
    if not client or client.realm_id != realm.id:
        flash('Client not found', 'error')
        return redirect(url_for('admin.clients_list', realm_name=realm_name))
    
    realms = Realm.query.all()
    return render_template(
        'admin/clients/detail.html',
        realm=realm,
        realms=realms,
        client=client,
        segment='clients'
    )


# =============================================================================
# Roles Management
# =============================================================================

@admin_bp.route('/<realm_name>/roles', methods=['GET', 'POST'])
@login_required
def roles_list(realm_name):
    """List roles in a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        
        if not name:
            flash('Role name is required', 'error')
        elif Role.find_realm_role(realm.id, name):
            flash(f'Role "{name}" already exists', 'error')
        else:
            # Create realm role
            role = Role(
                realm_id=realm.id,
                name=name,
                description=description or None,
                client_id=None,
                client_role=False,
                composite=False
            )
            role.save()
            flash(f'Role "{name}" created successfully', 'success')
        
        return redirect(url_for('admin.roles_list', realm_name=realm_name))
    
    roles = Role.get_realm_roles(realm.id)
    
    realms = Realm.query.all()
    return render_template(
        'admin/roles/list.html',
        realm=realm,
        realms=realms,
        roles=roles,
        segment='roles'
    )


# =============================================================================
# Groups Management
# =============================================================================

@admin_bp.route('/<realm_name>/groups', methods=['GET', 'POST'])
@login_required
def groups_list(realm_name):
    """List groups in a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        
        if not name:
            flash('Group name is required', 'error')
        else:
            # Create path for top-level group
            path = f'/{name}'
            
            if Group.find_by_path(realm.id, path):
                flash(f'Group "{name}" already exists', 'error')
            else:
                # Create top-level group
                group = Group(
                    realm_id=realm.id,
                    name=name,
                    path=path,
                    parent_id=None
                )
                group.save()
                flash(f'Group "{name}" created successfully', 'success')
        
        return redirect(url_for('admin.groups_list', realm_name=realm_name))
    
    groups = Group.get_top_level_groups(realm.id)
    
    realms = Realm.query.all()
    return render_template(
        'admin/groups/list.html',
        realm=realm,
        realms=realms,
        groups=groups,
        segment='groups'
    )


# =============================================================================
# Events
# =============================================================================

@admin_bp.route('/<realm_name>/events')
@login_required
def events_list(realm_name):
    """List events in a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    events = Event.get_events(realm.id, first=(page-1)*per_page, max_results=per_page)
    
    realms = Realm.query.all()
    return render_template(
        'admin/events/list.html',
        realm=realm,
        realms=realms,
        events=events,
        page=page,
        segment='events'
    )


# =============================================================================
# Sessions
# =============================================================================

@admin_bp.route('/<realm_name>/sessions')
@login_required
def sessions_list(realm_name):
    """List active sessions in a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    sessions = UserSession.query.filter_by(realm_id=realm.id, state='ACTIVE').all()
    
    realms = Realm.query.all()
    return render_template(
        'admin/sessions/list.html',
        realm=realm,
        realms=realms,
        sessions=sessions,
        segment='sessions'
    )
