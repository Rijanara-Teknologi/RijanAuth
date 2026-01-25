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


# =============================================================================
# User Federation
# =============================================================================

@admin_bp.route('/<realm_name>/user-federation')
@login_required
def federation_list(realm_name):
    """List user federation providers"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import FederationService
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    providers = UserFederationProvider.find_by_realm(realm.id)
    available_types = FederationService.get_available_providers()
    
    realms = Realm.query.all()
    return render_template(
        'admin/federation/list.html',
        realm=realm,
        realms=realms,
        providers=providers,
        available_types=available_types,
        segment='federation'
    )


@admin_bp.route('/<realm_name>/user-federation/create/<provider_type>', methods=['GET', 'POST'])
@login_required
def federation_create(realm_name, provider_type):
    """Create a new federation provider"""
    from apps.models.federation import UserFederationProvider
    from apps.services.federation import FederationService
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    # Check provider type is valid
    available_types = FederationService.get_available_providers()
    if provider_type not in available_types:
        flash(f'Unknown provider type: {provider_type}', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        display_name = request.form.get('display_name', '').strip()
        
        if not name:
            flash('Provider name is required', 'error')
        elif UserFederationProvider.find_by_name(realm.id, name):
            flash(f'Provider "{name}" already exists', 'error')
        else:
            # Build config from form
            config = _build_provider_config(provider_type, request.form)
            
            try:
                provider = FederationService.create_provider(
                    realm_id=realm.id,
                    name=name,
                    provider_type=provider_type,
                    config=config,
                    display_name=display_name or name,
                    enabled=request.form.get('enabled') == 'on',
                    priority=int(request.form.get('priority', 0)),
                    import_enabled=request.form.get('import_enabled') == 'on',
                    full_sync_period=int(request.form.get('full_sync_period', -1)),
                    changed_sync_period=int(request.form.get('changed_sync_period', -1)),
                )
                flash(f'Provider "{name}" created successfully', 'success')
                return redirect(url_for('admin.federation_edit', realm_name=realm_name, provider_id=provider.id))
            except Exception as e:
                flash(f'Error creating provider: {str(e)}', 'error')
    
    # Get provider config schema
    provider_class = FederationService.get_provider_class(provider_type)
    config_schema = provider_class.get_config_schema() if provider_class else {}
    
    realms = Realm.query.all()
    return render_template(
        f'admin/federation/create_{provider_type}.html',
        realm=realm,
        realms=realms,
        provider_type=provider_type,
        config_schema=config_schema,
        segment='federation'
    )


@admin_bp.route('/<realm_name>/user-federation/<provider_id>', methods=['GET', 'POST'])
@login_required
def federation_edit(realm_name, provider_id):
    """Edit federation provider"""
    from apps.models.federation import UserFederationProvider, UserFederationMapper, UserFederationLink
    from apps.services.federation import FederationService
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        flash('Provider not found', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    if request.method == 'POST':
        action = request.form.get('action', 'save')
        
        if action == 'save':
            # Update provider settings
            display_name = request.form.get('display_name', '').strip()
            config = _build_provider_config(provider.provider_type, request.form)
            
            try:
                FederationService.update_provider(
                    provider_id=provider.id,
                    config=config,
                    display_name=display_name or provider.name,
                    enabled=request.form.get('enabled') == 'on',
                    priority=int(request.form.get('priority', 0)),
                    import_enabled=request.form.get('import_enabled') == 'on',
                    full_sync_period=int(request.form.get('full_sync_period', -1)),
                    changed_sync_period=int(request.form.get('changed_sync_period', -1)),
                )
                flash('Provider updated successfully', 'success')
            except Exception as e:
                flash(f'Error updating provider: {str(e)}', 'error')
        
        elif action == 'test':
            # Test connection
            result = FederationService.test_provider_connection(provider.id)
            if result['success']:
                flash(f'Connection successful: {result["message"]}', 'success')
            else:
                flash(f'Connection failed: {result["message"]}', 'error')
        
        elif action == 'sync':
            # Trigger manual sync
            from apps.services.federation import SyncService
            result = SyncService.sync_all_users(provider.id)
            if result['success']:
                stats = result['stats']
                flash(f'Sync completed: {stats["users_processed"]} processed, '
                      f'{stats["users_created"]} created, {stats["users_updated"]} updated', 'success')
            else:
                flash(f'Sync failed: {result.get("error", "Unknown error")}', 'error')
        
        elif action == 'delete':
            FederationService.delete_provider(provider.id)
            flash('Provider deleted', 'success')
            return redirect(url_for('admin.federation_list', realm_name=realm_name))
        
        return redirect(url_for('admin.federation_edit', realm_name=realm_name, provider_id=provider.id))
    
    # Get mappers and linked users count
    mappers = provider.mappers.all()
    linked_users = UserFederationLink.query.filter_by(provider_id=provider.id).count()
    
    # Decrypt config for display (mask sensitive fields)
    display_config = FederationService._decrypt_config(provider.config, provider.provider_type)
    provider_class = FederationService.get_provider_class(provider.provider_type)
    if provider_class:
        for key in provider_class.SENSITIVE_CONFIG_KEYS:
            if key in display_config:
                display_config[key] = '********'
    
    realms = Realm.query.all()
    return render_template(
        'admin/federation/edit.html',
        realm=realm,
        realms=realms,
        provider=provider,
        mappers=mappers,
        linked_users=linked_users,
        config=display_config,
        segment='federation'
    )


@admin_bp.route('/<realm_name>/user-federation/<provider_id>/mappers', methods=['GET', 'POST'])
@login_required
def federation_mappers(realm_name, provider_id):
    """Manage federation provider mappers"""
    from apps.models.federation import UserFederationProvider, UserFederationMapper
    from apps import db
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        flash('Provider not found', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            name = request.form.get('name', '').strip()
            mapper_type = request.form.get('mapper_type', '')
            internal_attribute = request.form.get('internal_attribute', '').strip()
            external_attribute = request.form.get('external_attribute', '').strip()
            
            if not name:
                flash('Mapper name is required', 'error')
            else:
                mapper = UserFederationMapper(
                    provider_id=provider.id,
                    name=name,
                    mapper_type=mapper_type,
                    internal_attribute=internal_attribute,
                    external_attribute=external_attribute,
                    config={}
                )
                db.session.add(mapper)
                db.session.commit()
                flash(f'Mapper "{name}" created', 'success')
        
        elif action == 'delete':
            mapper_id = request.form.get('mapper_id')
            mapper = UserFederationMapper.query.get(mapper_id)
            if mapper and mapper.provider_id == provider.id:
                db.session.delete(mapper)
                db.session.commit()
                flash('Mapper deleted', 'success')
        
        return redirect(url_for('admin.federation_mappers', realm_name=realm_name, provider_id=provider.id))
    
    mappers = provider.mappers.all()
    
    realms = Realm.query.all()
    return render_template(
        'admin/federation/mappers.html',
        realm=realm,
        realms=realms,
        provider=provider,
        mappers=mappers,
        segment='federation'
    )


@admin_bp.route('/<realm_name>/user-federation/<provider_id>/sync-status')
@login_required
def federation_sync_status(realm_name, provider_id):
    """View federation sync status and logs"""
    from apps.models.federation import UserFederationProvider, FederationSyncLog
    from apps.services.federation import SyncService
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        flash('Provider not found', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    sync_status = SyncService.get_sync_status(provider_id)
    linked_users = SyncService.get_linked_users_count(provider_id)
    
    realms = Realm.query.all()
    return render_template(
        'admin/federation/sync_status.html',
        realm=realm,
        realms=realms,
        provider=provider,
        sync_status=sync_status,
        linked_users=linked_users,
        segment='federation'
    )


def _build_provider_config(provider_type, form):
    """Build provider config from form data"""
    config = {}
    
    if provider_type == 'ldap':
        config = {
            'connection_url': form.get('connection_url', ''),
            'bind_dn': form.get('bind_dn', ''),
            'bind_credential': form.get('bind_credential', ''),
            'use_ssl': form.get('use_ssl') == 'on',
            'use_starttls': form.get('use_starttls') == 'on',
            'users_dn': form.get('users_dn', ''),
            'username_ldap_attribute': form.get('username_ldap_attribute', 'uid'),
            'email_ldap_attribute': form.get('email_ldap_attribute', 'mail'),
            'first_name_ldap_attribute': form.get('first_name_ldap_attribute', 'givenName'),
            'last_name_ldap_attribute': form.get('last_name_ldap_attribute', 'sn'),
            'search_scope': form.get('search_scope', 'subtree'),
            'user_object_classes': [c.strip() for c in form.get('user_object_classes', 'inetOrgPerson').split(',')],
            'connection_timeout': int(form.get('connection_timeout', 30)),
            'batch_size': int(form.get('batch_size', 100)),
            'vendor': form.get('vendor', 'other'),
        }
    
    elif provider_type == 'mysql':
        config = {
            'host': form.get('host', 'localhost'),
            'port': int(form.get('port', 3306)),
            'database': form.get('database', ''),
            'username': form.get('db_username', ''),
            'password': form.get('db_password', ''),
            'user_table': form.get('user_table', 'users'),
            'id_column': form.get('id_column', 'id'),
            'username_column': form.get('username_column', 'username'),
            'email_column': form.get('email_column', 'email'),
            'password_column': form.get('password_column', 'password'),
            'first_name_column': form.get('first_name_column', ''),
            'last_name_column': form.get('last_name_column', ''),
            'enabled_column': form.get('enabled_column', ''),
            'password_hash_algorithm': form.get('password_hash_algorithm', 'bcrypt'),
            'batch_size': int(form.get('batch_size', 100)),
        }
    
    elif provider_type == 'postgresql':
        config = {
            'host': form.get('host', 'localhost'),
            'port': int(form.get('port', 5432)),
            'database': form.get('database', ''),
            'username': form.get('db_username', ''),
            'password': form.get('db_password', ''),
            'schema': form.get('schema', 'public'),
            'user_table': form.get('user_table', 'users'),
            'id_column': form.get('id_column', 'id'),
            'username_column': form.get('username_column', 'username'),
            'email_column': form.get('email_column', 'email'),
            'password_column': form.get('password_column', 'password'),
            'first_name_column': form.get('first_name_column', ''),
            'last_name_column': form.get('last_name_column', ''),
            'enabled_column': form.get('enabled_column', ''),
            'attributes_column': form.get('attributes_column', ''),
            'password_hash_algorithm': form.get('password_hash_algorithm', 'bcrypt'),
            'sslmode': form.get('sslmode', 'prefer'),
            'batch_size': int(form.get('batch_size', 100)),
        }
    
    return config


# =============================================================================
# Client Protocol Mappers
# =============================================================================

@admin_bp.route('/<realm_name>/clients/<client_id>/mappers')
@login_required
def client_mappers(realm_name, client_id):
    """List protocol mappers for a client"""
    from apps.models.client import ProtocolMapper, ClientScope, ClientScopeMapping
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        flash('Client not found', 'error')
        return redirect(url_for('admin.clients_list', realm_name=realm_name))
    
    # Get client's own mappers
    client_mappers = ProtocolMapper.find_by_client(client_id)
    
    # Get inherited mappers from default scopes
    inherited_mappers = []
    scope_mappings = ClientScopeMapping.query.filter_by(client_id=client_id, default_scope=True).all()
    for mapping in scope_mappings:
        scope = ClientScope.query.get(mapping.scope_id)
        if scope:
            scope_mappers = ProtocolMapper.find_by_client_scope(scope.id)
            for mapper in scope_mappers:
                inherited_mappers.append({
                    'mapper': mapper,
                    'scope': scope
                })
    
    # Mapper types for dropdown
    mapper_types = ProtocolMapper.MAPPER_TYPES
    
    return render_template(
        'admin/clients/mappers.html',
        realm=realm,
        client=client,
        mappers=client_mappers,
        inherited_mappers=inherited_mappers,
        mapper_types=mapper_types,
        segment='clients'
    )


@admin_bp.route('/<realm_name>/clients/<client_id>/mappers/add', methods=['GET', 'POST'])
@login_required
def client_mapper_add(realm_name, client_id):
    """Add a new protocol mapper to a client"""
    from apps.models.client import ProtocolMapper
    from apps import db
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        flash('Client not found', 'error')
        return redirect(url_for('admin.clients_list', realm_name=realm_name))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        mapper_type = request.form.get('mapper_type', '')
        
        if not name:
            flash('Mapper name is required', 'error')
            return redirect(url_for('admin.client_mapper_add', realm_name=realm_name, client_id=client_id))
        
        # Build config based on mapper type
        config = _build_mapper_config(mapper_type, request.form)
        
        # Validate config
        from apps.services.mapper_service import MapperService
        errors = MapperService.validate_mapper_config(mapper_type, config)
        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('admin.client_mapper_add', realm_name=realm_name, client_id=client_id))
        
        # Create mapper
        mapper = ProtocolMapper(
            name=name,
            protocol='openid-connect',
            protocol_mapper=mapper_type,
            client_id=client_id,
            config=config,
            priority=int(request.form.get('priority', 0))
        )
        db.session.add(mapper)
        db.session.commit()
        
        flash(f'Mapper "{name}" created successfully', 'success')
        return redirect(url_for('admin.client_mappers', realm_name=realm_name, client_id=client_id))
    
    # GET - show form
    mapper_type = request.args.get('type', 'oidc-usermodel-attribute-mapper')
    mapper_types = ProtocolMapper.MAPPER_TYPES
    
    return render_template(
        'admin/clients/mapper_form.html',
        realm=realm,
        client=client,
        mapper=None,
        mapper_type=mapper_type,
        mapper_types=mapper_types,
        segment='clients'
    )


@admin_bp.route('/<realm_name>/clients/<client_id>/mappers/<mapper_id>/edit', methods=['GET', 'POST'])
@login_required
def client_mapper_edit(realm_name, client_id, mapper_id):
    """Edit a protocol mapper"""
    from apps.models.client import ProtocolMapper
    from apps import db
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        flash('Client not found', 'error')
        return redirect(url_for('admin.clients_list', realm_name=realm_name))
    
    mapper = ProtocolMapper.query.get(mapper_id)
    if not mapper or mapper.client_id != client_id:
        flash('Mapper not found', 'error')
        return redirect(url_for('admin.client_mappers', realm_name=realm_name, client_id=client_id))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        
        if not name:
            flash('Mapper name is required', 'error')
            return redirect(url_for('admin.client_mapper_edit', realm_name=realm_name, client_id=client_id, mapper_id=mapper_id))
        
        # Build config
        config = _build_mapper_config(mapper.protocol_mapper, request.form)
        
        # Validate
        from apps.services.mapper_service import MapperService
        errors = MapperService.validate_mapper_config(mapper.protocol_mapper, config)
        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('admin.client_mapper_edit', realm_name=realm_name, client_id=client_id, mapper_id=mapper_id))
        
        # Update mapper
        mapper.name = name
        mapper.config = config
        mapper.priority = int(request.form.get('priority', 0))
        db.session.commit()
        
        flash(f'Mapper "{name}" updated successfully', 'success')
        return redirect(url_for('admin.client_mappers', realm_name=realm_name, client_id=client_id))
    
    # GET - show form
    mapper_types = ProtocolMapper.MAPPER_TYPES
    
    return render_template(
        'admin/clients/mapper_form.html',
        realm=realm,
        client=client,
        mapper=mapper,
        mapper_type=mapper.protocol_mapper,
        mapper_types=mapper_types,
        segment='clients'
    )


@admin_bp.route('/<realm_name>/clients/<client_id>/mappers/<mapper_id>/delete', methods=['POST'])
@login_required
def client_mapper_delete(realm_name, client_id, mapper_id):
    """Delete a protocol mapper"""
    from apps.models.client import ProtocolMapper
    from apps import db
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    client = Client.query.get(client_id)
    if not client or client.realm_id != realm.id:
        flash('Client not found', 'error')
        return redirect(url_for('admin.clients_list', realm_name=realm_name))
    
    mapper = ProtocolMapper.query.get(mapper_id)
    if not mapper or mapper.client_id != client_id:
        flash('Mapper not found', 'error')
        return redirect(url_for('admin.client_mappers', realm_name=realm_name, client_id=client_id))
    
    mapper_name = mapper.name
    db.session.delete(mapper)
    db.session.commit()
    
    flash(f'Mapper "{mapper_name}" deleted successfully', 'success')
    return redirect(url_for('admin.client_mappers', realm_name=realm_name, client_id=client_id))


# =============================================================================
# Client Scopes
# =============================================================================

@admin_bp.route('/<realm_name>/client-scopes')
@login_required
def client_scopes_list(realm_name):
    """List client scopes for a realm"""
    from apps.models.client import ClientScope
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    scopes = ClientScope.query.filter_by(realm_id=realm.id).order_by(ClientScope.name).all()
    
    return render_template(
        'admin/client_scopes/list.html',
        realm=realm,
        scopes=scopes,
        segment='client-scopes'
    )


@admin_bp.route('/<realm_name>/client-scopes/<scope_id>')
@login_required
def client_scope_detail(realm_name, scope_id):
    """View client scope details and mappers"""
    from apps.models.client import ClientScope, ProtocolMapper
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        flash('Client scope not found', 'error')
        return redirect(url_for('admin.client_scopes_list', realm_name=realm_name))
    
    mappers = ProtocolMapper.find_by_client_scope(scope_id)
    mapper_types = ProtocolMapper.MAPPER_TYPES
    
    return render_template(
        'admin/client_scopes/detail.html',
        realm=realm,
        scope=scope,
        mappers=mappers,
        mapper_types=mapper_types,
        segment='client-scopes'
    )


@admin_bp.route('/<realm_name>/client-scopes/<scope_id>/mappers/add', methods=['GET', 'POST'])
@login_required
def client_scope_mapper_add(realm_name, scope_id):
    """Add a mapper to a client scope"""
    from apps.models.client import ClientScope, ProtocolMapper
    from apps import db
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        flash('Client scope not found', 'error')
        return redirect(url_for('admin.client_scopes_list', realm_name=realm_name))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        mapper_type = request.form.get('mapper_type', '')
        
        if not name:
            flash('Mapper name is required', 'error')
            return redirect(url_for('admin.client_scope_mapper_add', realm_name=realm_name, scope_id=scope_id))
        
        config = _build_mapper_config(mapper_type, request.form)
        
        mapper = ProtocolMapper(
            name=name,
            protocol='openid-connect',
            protocol_mapper=mapper_type,
            client_scope_id=scope_id,
            config=config,
            priority=int(request.form.get('priority', 0))
        )
        db.session.add(mapper)
        db.session.commit()
        
        flash(f'Mapper "{name}" created successfully', 'success')
        return redirect(url_for('admin.client_scope_detail', realm_name=realm_name, scope_id=scope_id))
    
    mapper_type = request.args.get('type', 'oidc-usermodel-attribute-mapper')
    mapper_types = ProtocolMapper.MAPPER_TYPES
    
    return render_template(
        'admin/client_scopes/mapper_form.html',
        realm=realm,
        scope=scope,
        mapper=None,
        mapper_type=mapper_type,
        mapper_types=mapper_types,
        segment='client-scopes'
    )


def _build_mapper_config(mapper_type: str, form) -> dict:
    """Build mapper configuration from form data"""
    config = {
        'claim.name': form.get('claim_name', ''),
        'access.token.claim': 'true' if form.get('access_token_claim') else 'false',
        'id.token.claim': 'true' if form.get('id_token_claim') else 'false',
        'userinfo.token.claim': 'true' if form.get('userinfo_token_claim') else 'false',
        'jsonType.label': form.get('json_type', 'String'),
    }
    
    if mapper_type == 'oidc-usermodel-attribute-mapper':
        config['user.attribute'] = form.get('user_attribute', '')
        config['multivalued'] = 'true' if form.get('multivalued') else 'false'
        config['aggregate.attrs'] = 'true' if form.get('aggregate_attrs') else 'false'
    
    elif mapper_type == 'oidc-hardcoded-claim-mapper':
        config['claim.value'] = form.get('claim_value', '')
    
    elif mapper_type in ('oidc-usermodel-realm-role-mapper', 'oidc-usermodel-client-role-mapper'):
        config['multivalued'] = 'true' if form.get('multivalued', True) else 'false'
        config['role.prefix'] = form.get('role_prefix', '')
        if mapper_type == 'oidc-usermodel-client-role-mapper':
            config['client.id'] = form.get('target_client_id', '')
    
    elif mapper_type == 'oidc-group-membership-mapper':
        config['full.path'] = 'true' if form.get('full_path', True) else 'false'
    
    elif mapper_type == 'oidc-audience-mapper':
        config['included.client.audience'] = form.get('included_client_audience', '')
        config['included.custom.audience'] = form.get('included_custom_audience', '')
        config['add.to.access.token'] = 'true' if form.get('add_to_access_token', True) else 'false'
        config['add.to.id.token'] = 'true' if form.get('add_to_id_token') else 'false'
    
    elif mapper_type == 'oidc-full-name-mapper':
        pass  # Uses default claim.name
    
    elif mapper_type == 'oidc-address-mapper':
        pass  # Uses default claim.name
    
    return config
