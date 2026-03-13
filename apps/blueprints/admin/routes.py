# -*- encoding: utf-8 -*-
"""
RijanAuth - Admin Routes
Web routes for the administration console
"""

from flask import render_template, redirect, url_for, request, flash, g, Response
from flask_login import login_required, current_user
from apps.blueprints.admin import admin_bp
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.client import Client
from apps.models.role import Role
from apps.models.group import Group
from apps.models.session import UserSession
from apps.models.event import Event
from apps.models.customization import RealmPageCustomization, MediaAsset
from apps.services.realm_service import RealmService
from apps.services.user_service import UserService
from apps.services.client_service import ClientService
from apps.utils.css_sanitizer import CSSSanitizer
from apps.utils.media_handler import MediaHandler
from apps import db
import json


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
        realm.smtp_from_display_name = request.form.get('smtp_from_display_name', '').strip() or None
        realm.smtp_reply_to = request.form.get('smtp_reply_to', '').strip() or None
        realm.smtp_reply_to_display_name = request.form.get('smtp_reply_to_display_name', '').strip() or None
        realm.smtp_ssl = request.form.get('smtp_ssl') == 'on'
        realm.smtp_starttls = request.form.get('smtp_starttls') == 'on'
        realm.smtp_auth = request.form.get('smtp_auth') == 'on'
        realm.smtp_user = request.form.get('smtp_user', '').strip() or None
        # Only update password if a new value was provided
        new_smtp_password = request.form.get('smtp_password', '').strip()
        if new_smtp_password:
            realm.smtp_password = new_smtp_password
        
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


@admin_bp.route('/<realm_name>/settings/test-email', methods=['POST'])
@login_required
def realm_test_email(realm_name):
    """Send a test email using the realm's SMTP configuration"""
    import smtplib
    import ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    recipient = request.form.get('test_email_recipient', '').strip()
    if not recipient:
        flash('Please enter a recipient email address for the test.', 'error')
        return redirect(url_for('admin.realm_settings', realm_name=realm_name) + '#email')

    if not realm.smtp_server:
        flash('SMTP host is not configured.', 'error')
        return redirect(url_for('admin.realm_settings', realm_name=realm_name) + '#email')

    try:
        port = int(realm.smtp_port or 25)
    except (ValueError, TypeError):
        port = 25

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'RijanAuth SMTP Test - {realm.name}'
    msg['From'] = (
        f'{realm.smtp_from_display_name} <{realm.smtp_from}>'
        if realm.smtp_from_display_name and realm.smtp_from
        else (realm.smtp_from or 'rijanauth@localhost')
    )
    msg['To'] = recipient
    if realm.smtp_reply_to:
        reply_label = (
            f'{realm.smtp_reply_to_display_name} <{realm.smtp_reply_to}>'
            if realm.smtp_reply_to_display_name
            else realm.smtp_reply_to
        )
        msg['Reply-To'] = reply_label

    body = (
        f'<p>This is a test email from <strong>RijanAuth</strong> realm '
        f'<em>{realm.name}</em>.</p>'
        f'<p>If you received this, your SMTP settings are working correctly.</p>'
    )
    msg.attach(MIMEText(body, 'html'))

    try:
        context = ssl.create_default_context()
        if realm.smtp_ssl:
            server = smtplib.SMTP_SSL(realm.smtp_server, port, context=context, timeout=10)
        else:
            server = smtplib.SMTP(realm.smtp_server, port, timeout=10)
            if realm.smtp_starttls:
                server.starttls(context=context)

        try:
            if realm.smtp_auth and realm.smtp_user and realm.smtp_password:
                server.login(realm.smtp_user, realm.smtp_password)

            sender = realm.smtp_from or 'rijanauth@localhost'
            server.sendmail(sender, [recipient], msg.as_string())
        finally:
            server.quit()

        flash(f'Test email sent successfully to {recipient}.', 'success')
    except Exception as exc:
        flash(f'Failed to send test email: {exc}', 'error')

    return redirect(url_for('admin.realm_settings', realm_name=realm_name) + '#email')


@admin_bp.route('/<realm_name>/branding', methods=['GET', 'POST'])
@login_required
def realm_branding(realm_name):
    """Realm branding/customization page"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    page_type = request.args.get('page', 'login')  # Default to login page
    
    if request.method == 'POST':
        # Get or create customization
        customization = RealmPageCustomization.get_or_create(realm.id, page_type)
        
        # Update customization from form
        customization.background_type = request.form.get('background_type', 'color')
        customization.background_color = request.form.get('background_color', '#673AB7')
        
        # Handle gradient
        gradient_colors = request.form.getlist('gradient_colors[]')
        gradient_direction = request.form.get('gradient_direction', 'to right')
        if gradient_colors and len(gradient_colors) >= 2:
            customization.set_background_gradient_dict({
                'colors': gradient_colors,
                'direction': gradient_direction
            })
        else:
            customization.background_gradient = None
        
        # Colors
        customization.primary_color = request.form.get('primary_color', '#673AB7')
        customization.secondary_color = request.form.get('secondary_color', '#3F51B5')
        
        # Typography
        customization.font_family = request.form.get('font_family', 'Inter, system-ui, -apple-system, sans-serif')
        
        # Styling
        try:
            customization.button_radius = int(request.form.get('button_radius', 4))
        except (ValueError, TypeError):
            customization.button_radius = 4
        
        try:
            customization.form_radius = int(request.form.get('form_radius', 4))
        except (ValueError, TypeError):
            customization.form_radius = 4
        
        # Logo position
        customization.logo_position = request.form.get('logo_position', 'center')
        
        # Custom CSS (sanitized)
        custom_css = request.form.get('custom_css', '').strip()
        sanitized_css, warnings = CSSSanitizer.sanitize(custom_css)
        customization.custom_css = sanitized_css
        
        if warnings:
            flash(f'CSS warnings: {"; ".join(warnings)}', 'warning')
        
        customization.save()
        flash('Branding settings saved successfully', 'success')
        return redirect(url_for('admin.realm_branding', realm_name=realm_name, page=page_type))
    
    # GET request - show branding page
    customization = RealmPageCustomization.get(realm.id, page_type)
    if not customization:
        # Create default customization for display
        customization = RealmPageCustomization.get_or_create(realm.id, page_type)
    
    realms = Realm.query.all()
    return render_template(
        'admin/realms/branding.html',
        realm=realm,
        realms=realms,
        customization=customization,
        page_type=page_type,
        segment='realm-branding'
    )


@admin_bp.route('/<realm_name>/branding/upload-logo', methods=['POST'])
@login_required
def upload_logo(realm_name):
    """Upload logo for realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    if 'logo' not in request.files:
        flash('No file provided', 'error')
        return redirect(url_for('admin.realm_branding', realm_name=realm_name))
    
    file = request.files['logo']
    page_type = request.form.get('page_type', 'login')
    
    try:
        # Save file
        asset = MediaHandler.save_file(file, realm.id, 'logo')
        
        # Update customization
        customization = RealmPageCustomization.get_or_create(realm.id, page_type)
        customization.logo_id = asset.id
        customization.save()
        
        flash('Logo uploaded successfully', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        flash(f'Error uploading logo: {str(e)}', 'error')
    
    return redirect(url_for('admin.realm_branding', realm_name=realm_name, page=page_type))


@admin_bp.route('/<realm_name>/branding/upload-background', methods=['POST'])
@login_required
def upload_background(realm_name):
    """Upload background image for realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    if 'background' not in request.files:
        flash('No file provided', 'error')
        return redirect(url_for('admin.realm_branding', realm_name=realm_name))
    
    file = request.files['background']
    page_type = request.form.get('page_type', 'login')
    
    try:
        # Save file
        asset = MediaHandler.save_file(file, realm.id, 'background')
        
        # Update customization
        customization = RealmPageCustomization.get_or_create(realm.id, page_type)
        customization.background_image_id = asset.id
        customization.background_type = 'image'
        customization.save()
        
        flash('Background image uploaded successfully', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        flash(f'Error uploading background: {str(e)}', 'error')
    
    return redirect(url_for('admin.realm_branding', realm_name=realm_name, page=page_type))


@admin_bp.route('/<realm_name>/branding/remove-logo', methods=['POST'])
@login_required
def remove_logo(realm_name):
    """Remove logo from realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    page_type = request.form.get('page_type', 'login')
    customization = RealmPageCustomization.get(realm.id, page_type)
    
    if customization and customization.logo_id:
        asset = MediaAsset.find_by_id(customization.logo_id)
        if asset:
            MediaHandler.delete_file(asset)
        customization.logo_id = None
        customization.save()
        flash('Logo removed successfully', 'success')
    
    return redirect(url_for('admin.realm_branding', realm_name=realm_name, page=page_type))


@admin_bp.route('/<realm_name>/branding/remove-background', methods=['POST'])
@login_required
def remove_background(realm_name):
    """Remove background image from realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    page_type = request.form.get('page_type', 'login')
    customization = RealmPageCustomization.get(realm.id, page_type)
    
    if customization and customization.background_image_id:
        asset = MediaAsset.find_by_id(customization.background_image_id)
        if asset:
            MediaHandler.delete_file(asset)
        customization.background_image_id = None
        customization.background_type = 'color'
        customization.save()
        flash('Background image removed successfully', 'success')
    
    return redirect(url_for('admin.realm_branding', realm_name=realm_name, page=page_type))


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


@admin_bp.route('/<realm_name>/users/import-template')
@login_required
def download_import_template(realm_name):
    """Download a minimal CSV template for bulk user import."""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    csv_content = 'username,email,password,first_name,last_name\nexample_user,user@example.com,secret123,John,Doe\n'
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=users_import_template.csv'}
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
    user_realm_roles = UserService.get_user_roles(user)
    user_groups = UserService.get_user_groups(user)
    sessions = user.sessions.filter_by(state='ACTIVE').all()
    
    # Get all available realm roles (for assigning)
    all_realm_roles = Role.get_realm_roles(realm.id)
    user_role_ids = [r.id for r in user_realm_roles]
    available_roles = [r for r in all_realm_roles if r.id not in user_role_ids]
    
    # Get all available groups (for assigning)
    all_groups = Group.query.filter_by(realm_id=realm.id).all()
    user_group_ids = [g.id for g in user_groups]
    available_groups = [g for g in all_groups if g.id not in user_group_ids]
    
    realms = Realm.query.all()
    return render_template(
        'admin/users/detail.html',
        realm=realm,
        realms=realms,
        user=user,
        realm_roles=user_realm_roles,
        available_roles=available_roles,
        groups=user_groups,
        available_groups=available_groups,
        sessions=sessions,
        segment='users'
    )


@admin_bp.route('/<realm_name>/users/<user_id>/roles/assign', methods=['POST'])
@login_required
def user_role_assign(realm_name, user_id):
    """Assign a role to a user"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        flash('User not found', 'error')
        return redirect(url_for('admin.users_list', realm_name=realm_name))
    
    role_id = request.form.get('role_id')
    if not role_id:
        flash('Role is required', 'error')
        return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))
    
    role = Role.query.filter_by(id=role_id, realm_id=realm.id).first()
    if not role:
        flash('Role not found', 'error')
        return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))
    
    UserService.assign_role(user, role)
    flash(f'Role "{role.name}" assigned to {user.username}', 'success')
    return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))


@admin_bp.route('/<realm_name>/users/<user_id>/roles/<role_id>/remove', methods=['POST'])
@login_required
def user_role_remove(realm_name, user_id, role_id):
    """Remove a role from a user"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        flash('User not found', 'error')
        return redirect(url_for('admin.users_list', realm_name=realm_name))
    
    role = Role.query.filter_by(id=role_id, realm_id=realm.id).first()
    if not role:
        flash('Role not found', 'error')
        return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))
    
    UserService.remove_role(user, role)
    flash(f'Role "{role.name}" removed from {user.username}', 'success')
    return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))


@admin_bp.route('/<realm_name>/users/<user_id>/groups/assign', methods=['POST'])
@login_required
def user_group_assign(realm_name, user_id):
    """Assign a group to a user"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        flash('User not found', 'error')
        return redirect(url_for('admin.users_list', realm_name=realm_name))
    
    group_id = request.form.get('group_id')
    if not group_id:
        flash('Group is required', 'error')
        return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))
    
    group = Group.query.filter_by(id=group_id, realm_id=realm.id).first()
    if not group:
        flash('Group not found', 'error')
        return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))
    
    UserService.join_group(user, group)
    flash(f'User added to group "{group.name}"', 'success')
    return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))


@admin_bp.route('/<realm_name>/users/<user_id>/groups/<group_id>/remove', methods=['POST'])
@login_required
def user_group_remove(realm_name, user_id, group_id):
    """Remove a user from a group"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        flash('User not found', 'error')
        return redirect(url_for('admin.users_list', realm_name=realm_name))
    
    group = Group.query.filter_by(id=group_id, realm_id=realm.id).first()
    if not group:
        flash('Group not found', 'error')
        return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))
    
    UserService.leave_group(user, group)
    flash(f'User removed from group "{group.name}"', 'success')
    return redirect(url_for('admin.user_detail', realm_name=realm_name, user_id=user_id))


@admin_bp.route('/<realm_name>/users/<user_id>/delete', methods=['POST'])
@login_required
def user_delete(realm_name, user_id):
    """Delete a user"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    user = User.find_by_id(user_id)
    if not user or user.realm_id != realm.id:
        flash('User not found', 'error')
        return redirect(url_for('admin.users_list', realm_name=realm_name))

    username = user.username
    user.delete()

    flash(f'User "{username}" deleted successfully', 'success')
    return redirect(url_for('admin.users_list', realm_name=realm_name))


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


@admin_bp.route('/<realm_name>/clients/<client_id>', methods=['GET', 'POST'])
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
    
    if request.method == 'POST':
        # Parse redirect URIs - one per line
        redirect_uris_raw = request.form.get('redirect_uris', '')
        redirect_uris = [u.strip() for u in redirect_uris_raw.splitlines() if u.strip()]

        ClientService.update_client(client,
            # Use the submitted name, or fall back to client_id to keep it non-empty
            name=request.form.get('name', '').strip() or client.client_id,
            description=request.form.get('description', '').strip(),
            # Treat empty string as NULL so the column remains nullable
            root_url=request.form.get('root_url', '').strip() if request.form.get('root_url', '').strip() else None,
            redirect_uris=redirect_uris,
            standard_flow_enabled='standard_flow_enabled' in request.form,
            implicit_flow_enabled='implicit_flow_enabled' in request.form,
            direct_access_grants_enabled='direct_access_grants_enabled' in request.form,
            service_accounts_enabled='service_accounts_enabled' in request.form,
            public_client='public_client' in request.form,
        )
        flash('Client settings saved successfully', 'success')
        return redirect(url_for('admin.client_detail', realm_name=realm_name, client_id=client_id))

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


@admin_bp.route('/<realm_name>/roles/<role_id>/edit', methods=['POST'])
@login_required
def role_edit(realm_name, role_id):
    """Edit a realm role"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    role = Role.query.filter_by(id=role_id, realm_id=realm.id).first()
    if not role:
        flash('Role not found', 'error')
        return redirect(url_for('admin.roles_list', realm_name=realm_name))
    
    # Check if it's a protected system role
    protected_roles = ['default-roles-' + realm.name, 'offline_access', 'uma_authorization']
    if role.name in protected_roles:
        flash(f'Cannot edit protected role "{role.name}"', 'error')
        return redirect(url_for('admin.roles_list', realm_name=realm_name))
    
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    
    if not name:
        flash('Role name is required', 'error')
        return redirect(url_for('admin.roles_list', realm_name=realm_name))
    
    # Check if name already exists (if changed)
    if name != role.name:
        existing = Role.find_realm_role(realm.id, name)
        if existing:
            flash(f'Role "{name}" already exists', 'error')
            return redirect(url_for('admin.roles_list', realm_name=realm_name))
    
    role.name = name
    role.description = description or None
    role.save()
    
    flash(f'Role "{name}" updated successfully', 'success')
    return redirect(url_for('admin.roles_list', realm_name=realm_name))


@admin_bp.route('/<realm_name>/roles/<role_id>/delete', methods=['POST'])
@login_required
def role_delete(realm_name, role_id):
    """Delete a realm role"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    role = Role.query.filter_by(id=role_id, realm_id=realm.id).first()
    if not role:
        flash('Role not found', 'error')
        return redirect(url_for('admin.roles_list', realm_name=realm_name))
    
    # Check if it's a protected system role
    protected_roles = ['default-roles-' + realm.name, 'offline_access', 'uma_authorization']
    if role.name in protected_roles:
        flash(f'Cannot delete protected role "{role.name}"', 'error')
        return redirect(url_for('admin.roles_list', realm_name=realm_name))
    
    role_name = role.name
    role.delete()
    
    flash(f'Role "{role_name}" deleted successfully', 'success')
    return redirect(url_for('admin.roles_list', realm_name=realm_name))


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


@admin_bp.route('/<realm_name>/sessions/<session_id>/signout', methods=['POST'])
@login_required
def session_signout(realm_name, session_id):
    """Sign out a single active session"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    session = UserSession.query.filter_by(id=session_id, realm_id=realm.id).first()
    if not session:
        flash('Session not found', 'error')
        return redirect(url_for('admin.sessions_list', realm_name=realm_name))

    session.logout()
    flash('Session signed out successfully', 'success')
    return redirect(url_for('admin.sessions_list', realm_name=realm_name))


@admin_bp.route('/<realm_name>/sessions/signout-all', methods=['POST'])
@login_required
def session_signout_all(realm_name):
    """Sign out all active sessions in a realm"""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    active_sessions = UserSession.query.filter_by(realm_id=realm.id, state='ACTIVE').all()
    count = len(active_sessions)
    for s in active_sessions:
        s.logout()

    flash(f'{count} session(s) signed out successfully', 'success')
    return redirect(url_for('admin.sessions_list', realm_name=realm_name))


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


@admin_bp.route('/<realm_name>/user-federation/<provider_id>/role-mappings')
@login_required
def federation_role_mappings(realm_name, provider_id):
    """View and manage federation role mappings"""
    from apps.models.federation import (
        UserFederationProvider, FederationRoleMapping, FederatedRoleSync
    )
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        flash('Provider not found', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    # Get role mappings
    mappings = FederationRoleMapping.find_by_provider(provider_id)
    
    # Get realm roles for mapping selection
    realm_roles = Role.query.filter_by(realm_id=realm.id, client_id=None).order_by(Role.name).all()
    
    # Get recent role sync events
    recent_syncs = FederatedRoleSync.query.filter_by(provider_id=provider_id)\
        .order_by(FederatedRoleSync.last_sync.desc()).limit(10).all()
    
    realms = Realm.query.all()
    return render_template(
        'admin/federation/role_mappings.html',
        realm=realm,
        realms=realms,
        provider=provider,
        mappings=mappings,
        realm_roles=realm_roles,
        recent_syncs=recent_syncs,
        segment='federation'
    )


@admin_bp.route('/<realm_name>/user-federation/<provider_id>/role-mappings/add', methods=['POST'])
@login_required
def federation_role_mapping_add(realm_name, provider_id):
    """Add a new role mapping"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    from apps import db
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        flash('Provider not found', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    external_role = request.form.get('external_role_name', '').strip()
    internal_role_id = request.form.get('internal_role_id', '').strip()
    mapping_type = request.form.get('mapping_type', 'direct')
    mapping_value = request.form.get('mapping_value', '').strip() or None
    priority = int(request.form.get('priority', 0))
    enabled = request.form.get('enabled') == 'on'
    
    if not external_role or not internal_role_id:
        flash('External role name and internal role are required', 'error')
        return redirect(url_for('admin.federation_role_mappings', realm_name=realm_name, provider_id=provider_id))
    
    # Check if mapping already exists
    existing = FederationRoleMapping.query.filter_by(
        provider_id=provider_id, external_role_name=external_role
    ).first()
    
    if existing:
        flash(f'Mapping for external role "{external_role}" already exists', 'error')
        return redirect(url_for('admin.federation_role_mappings', realm_name=realm_name, provider_id=provider_id))
    
    try:
        mapping = FederationRoleMapping(
            provider_id=provider_id,
            external_role_name=external_role,
            internal_role_id=internal_role_id,
            mapping_type=mapping_type,
            mapping_value=mapping_value,
            priority=priority,
            enabled=enabled
        )
        db.session.add(mapping)
        db.session.commit()
        flash(f'Role mapping for "{external_role}" created successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to create role mapping: {str(e)}', 'error')
    
    return redirect(url_for('admin.federation_role_mappings', realm_name=realm_name, provider_id=provider_id))


@admin_bp.route('/<realm_name>/user-federation/<provider_id>/role-mappings/<mapping_id>/edit', methods=['POST'])
@login_required
def federation_role_mapping_edit(realm_name, provider_id, mapping_id):
    """Edit an existing role mapping"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    from apps import db
    from datetime import datetime
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        flash('Provider not found', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    mapping = FederationRoleMapping.query.get(mapping_id)
    if not mapping or mapping.provider_id != provider_id:
        flash('Mapping not found', 'error')
        return redirect(url_for('admin.federation_role_mappings', realm_name=realm_name, provider_id=provider_id))
    
    try:
        mapping.external_role_name = request.form.get('external_role_name', mapping.external_role_name).strip()
        mapping.internal_role_id = request.form.get('internal_role_id', mapping.internal_role_id).strip()
        mapping.mapping_type = request.form.get('mapping_type', mapping.mapping_type)
        mapping.mapping_value = request.form.get('mapping_value', '').strip() or None
        mapping.priority = int(request.form.get('priority', mapping.priority))
        mapping.enabled = request.form.get('enabled') == 'on'
        mapping.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Role mapping updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to update role mapping: {str(e)}', 'error')
    
    return redirect(url_for('admin.federation_role_mappings', realm_name=realm_name, provider_id=provider_id))


@admin_bp.route('/<realm_name>/user-federation/<provider_id>/role-mappings/<mapping_id>/delete', methods=['POST'])
@login_required
def federation_role_mapping_delete(realm_name, provider_id, mapping_id):
    """Delete a role mapping"""
    from apps.models.federation import UserFederationProvider, FederationRoleMapping
    from apps import db
    
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))
    
    provider = UserFederationProvider.find_by_id(provider_id)
    if not provider or provider.realm_id != realm.id:
        flash('Provider not found', 'error')
        return redirect(url_for('admin.federation_list', realm_name=realm_name))
    
    mapping = FederationRoleMapping.query.get(mapping_id)
    if not mapping or mapping.provider_id != provider_id:
        flash('Mapping not found', 'error')
        return redirect(url_for('admin.federation_role_mappings', realm_name=realm_name, provider_id=provider_id))
    
    try:
        external_role = mapping.external_role_name
        db.session.delete(mapping)
        db.session.commit()
        flash(f'Role mapping for "{external_role}" deleted', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete role mapping: {str(e)}', 'error')
    
    return redirect(url_for('admin.federation_role_mappings', realm_name=realm_name, provider_id=provider_id))


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
            # Role sync settings
            'role_sync_enabled': form.get('role_sync_enabled') == 'on',
            'role_source': form.get('role_source', 'memberOf'),
            'role_attribute': form.get('role_attribute', 'memberOf'),
            'extract_cn_from_dn': form.get('extract_cn_from_dn') == 'on',
            'groups_dn': form.get('groups_dn', ''),
            'group_object_classes': [c.strip() for c in form.get('group_object_classes', 'groupOfNames,groupOfUniqueNames').split(',') if c.strip()],
            'group_name_ldap_attribute': form.get('group_name_ldap_attribute', 'cn'),
            'create_missing_roles': form.get('create_missing_roles') == 'on',
            'default_role_if_empty': form.get('default_role_if_empty', ''),
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
            # Role sync settings
            'role_sync_enabled': form.get('role_sync_enabled') == 'on',
            'role_source': form.get('role_source', 'column'),
            'role_column': form.get('role_column', 'roles'),
            'role_table': form.get('role_table', ''),
            'role_user_id_column': form.get('role_user_id_column', 'user_id'),
            'role_name_column': form.get('role_name_column', 'role_name'),
            'role_delimiter': form.get('role_delimiter', ','),
            'create_missing_roles': form.get('create_missing_roles') == 'on',
            'default_role_if_empty': form.get('default_role_if_empty', ''),
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
            # Role sync settings
            'role_sync_enabled': form.get('role_sync_enabled') == 'on',
            'role_source': form.get('role_source', 'column'),
            'role_column': form.get('role_column', 'roles'),
            'role_jsonb_path': form.get('role_jsonb_path', 'roles'),
            'role_table': form.get('role_table', ''),
            'role_user_id_column': form.get('role_user_id_column', 'user_id'),
            'role_name_column': form.get('role_name_column', 'role_name'),
            'role_delimiter': form.get('role_delimiter', ','),
            'create_missing_roles': form.get('create_missing_roles') == 'on',
            'default_role_if_empty': form.get('default_role_if_empty', ''),
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


@admin_bp.route('/<realm_name>/client-scopes/<scope_id>/delete', methods=['POST'])
@login_required
def client_scope_delete(realm_name, scope_id):
    """Delete a client scope"""
    from apps.models.client import ClientScope

    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        flash('Client scope not found', 'error')
        return redirect(url_for('admin.client_scopes_list', realm_name=realm_name))

    scope_name = scope.name
    scope.delete()

    flash(f'Client scope "{scope_name}" deleted successfully', 'success')
    return redirect(url_for('admin.client_scopes_list', realm_name=realm_name))


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


@admin_bp.route('/<realm_name>/client-scopes/<scope_id>/mappers/<mapper_id>/edit', methods=['GET', 'POST'])
@login_required
def client_scope_mapper_edit(realm_name, scope_id, mapper_id):
    """Edit a protocol mapper on a client scope"""
    from apps.models.client import ClientScope, ProtocolMapper
    from apps import db

    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        flash('Client scope not found', 'error')
        return redirect(url_for('admin.client_scopes_list', realm_name=realm_name))

    mapper = ProtocolMapper.query.get(mapper_id)
    if not mapper or mapper.client_scope_id != scope_id:
        flash('Mapper not found', 'error')
        return redirect(url_for('admin.client_scope_detail', realm_name=realm_name, scope_id=scope_id))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()

        if not name:
            flash('Mapper name is required', 'error')
            return redirect(url_for('admin.client_scope_mapper_edit', realm_name=realm_name, scope_id=scope_id, mapper_id=mapper_id))

        config = _build_mapper_config(mapper.protocol_mapper, request.form)

        from apps.services.mapper_service import MapperService
        errors = MapperService.validate_mapper_config(mapper.protocol_mapper, config)
        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('admin.client_scope_mapper_edit', realm_name=realm_name, scope_id=scope_id, mapper_id=mapper_id))

        mapper.name = name
        mapper.config = config
        mapper.priority = int(request.form.get('priority', 0))
        db.session.commit()

        flash(f'Mapper "{name}" updated successfully', 'success')
        return redirect(url_for('admin.client_scope_detail', realm_name=realm_name, scope_id=scope_id))

    mapper_types = ProtocolMapper.MAPPER_TYPES

    return render_template(
        'admin/client_scopes/mapper_form.html',
        realm=realm,
        scope=scope,
        mapper=mapper,
        mapper_type=mapper.protocol_mapper,
        mapper_types=mapper_types,
        segment='client-scopes'
    )


@admin_bp.route('/<realm_name>/client-scopes/<scope_id>/mappers/<mapper_id>/delete', methods=['POST'])
@login_required
def client_scope_mapper_delete(realm_name, scope_id, mapper_id):
    """Delete a protocol mapper from a client scope"""
    from apps.models.client import ClientScope, ProtocolMapper
    from apps import db

    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    scope = ClientScope.query.get(scope_id)
    if not scope or scope.realm_id != realm.id:
        flash('Client scope not found', 'error')
        return redirect(url_for('admin.client_scopes_list', realm_name=realm_name))

    mapper = ProtocolMapper.query.get(mapper_id)
    if not mapper or mapper.client_scope_id != scope_id:
        flash('Mapper not found', 'error')
        return redirect(url_for('admin.client_scope_detail', realm_name=realm_name, scope_id=scope_id))

    mapper_name = mapper.name
    db.session.delete(mapper)
    db.session.commit()

    flash(f'Mapper "{mapper_name}" deleted successfully', 'success')
    return redirect(url_for('admin.client_scope_detail', realm_name=realm_name, scope_id=scope_id))


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


# =============================================================================
# Backup & Restore  (master realm only)
# =============================================================================

from apps.models.backup import BackupConfig, BackupRecord
from apps.services.backup_service import BackupService

# Cloud provider metadata used in templates
PROVIDER_INFO = {
    'google_drive': {
        'label': 'Google Drive',
        'icon': 'fa-google-drive',
        'icon_prefix': 'fab',
        'dev_url': 'https://console.cloud.google.com/',
        'dev_label': 'Google Cloud Console',
        'uses_oauth': True,
        'fields': [
            {'key': 'client_id', 'label': 'OAuth2 Client ID', 'type': 'text',
             'help': 'OAuth 2.0 Client ID from Google Cloud Console → APIs &amp; Services → Credentials.'},
            {'key': 'client_secret', 'label': 'OAuth2 Client Secret', 'type': 'password',
             'help': 'OAuth 2.0 Client Secret from Google Cloud Console.'},
            {'key': 'refresh_token', 'label': 'OAuth2 Refresh Token', 'type': 'password',
             'help': 'Long-lived refresh token obtained after completing the OAuth2 consent flow.'},
            {'key': 'folder_id', 'label': 'Drive Folder ID (optional)', 'type': 'text',
             'help': 'ID of the Google Drive folder to store backups in. Leave blank for root.'},
        ],
        'instructions': [
            '1. Open <a href="https://console.cloud.google.com/" target="_blank" rel="noopener noreferrer">Google Cloud Console</a> and create a project (or select an existing one).',
            '2. Go to <strong>APIs &amp; Services → Library</strong> and enable the <strong>Google Drive API</strong>.',
            '3. Go to <strong>APIs &amp; Services → Credentials</strong> and click <strong>Create Credentials → OAuth 2.0 Client ID</strong>.',
            '4. Set the application type to <strong>Web application</strong>.',
            '5. Under <strong>Authorised redirect URIs</strong>, add the redirect URL shown above and click <strong>Save</strong>.',
            '6. Copy the <strong>Client ID</strong> and <strong>Client Secret</strong> and paste them in the fields above.',
            '7. Complete the OAuth2 consent flow using those credentials to obtain a refresh token, then paste it in the <strong>OAuth2 Refresh Token</strong> field.',
            '8. (Optional) Create a folder in Google Drive, copy its ID from the URL, and paste it in the <strong>Drive Folder ID</strong> field.',
        ],
    },
    'mega': {
        'label': 'Mega.nz',
        'icon': 'fa-cloud',
        'icon_prefix': 'fas',
        'dev_url': 'https://mega.nz/',
        'dev_label': 'Mega.nz',
        'uses_oauth': False,
        'fields': [
            {'key': 'email', 'label': 'Mega Account Email', 'type': 'email', 'help': 'Your Mega.nz login email.'},
            {'key': 'password', 'label': 'Mega Account Password', 'type': 'password', 'help': 'Your Mega.nz login password.'},
            {'key': 'folder', 'label': 'Folder Name (optional)', 'type': 'text',
             'help': 'Name of the folder inside Mega where backups will be stored. Defaults to "RijanAuth Backups".'},
        ],
        'instructions': [
            '1. Register or log in at <a href="https://mega.nz/" target="_blank" rel="noopener noreferrer">Mega.nz</a>.',
            '2. Enter your Mega account email and password in the fields above.',
            '3. Backups will be stored in a folder called <strong>RijanAuth Backups</strong> (or the name you specify).',
            '<strong>Note:</strong> Mega.nz does not have a separate API key — authentication uses your account credentials.',
        ],
    },
    'dropbox': {
        'label': 'Dropbox',
        'icon': 'fa-dropbox',
        'icon_prefix': 'fab',
        'dev_url': 'https://www.dropbox.com/developers/apps',
        'dev_label': 'Dropbox App Console',
        'uses_oauth': True,
        'fields': [
            {'key': 'app_key', 'label': 'App Key', 'type': 'text', 'help': 'Your Dropbox app key.'},
            {'key': 'app_secret', 'label': 'App Secret', 'type': 'password', 'help': 'Your Dropbox app secret.'},
            {'key': 'refresh_token', 'label': 'OAuth2 Refresh Token', 'type': 'password',
             'help': 'Long-lived refresh token for your Dropbox app.'},
        ],
        'instructions': [
            '1. Go to <a href="https://www.dropbox.com/developers/apps" target="_blank" rel="noopener noreferrer">Dropbox App Console</a> and click <strong>Create app</strong>.',
            '2. Choose <strong>Scoped access</strong> → <strong>Full Dropbox</strong>. Give your app a name.',
            '3. Under the <strong>Permissions</strong> tab, enable: <code>files.content.write</code>, <code>files.content.read</code>, <code>sharing.write</code>.',
            '4. Under the <strong>Settings</strong> tab, find <strong>OAuth 2 → Redirect URIs</strong> and add the redirect URL shown above, then click <strong>Add</strong>.',
            '5. Copy the <strong>App key</strong> and <strong>App secret</strong> from the <strong>Settings</strong> tab and paste them in the fields above.',
            '6. Complete the OAuth2 PKCE flow to obtain a refresh token (see the <a href="https://developers.dropbox.com/oauth-guide" target="_blank" rel="noopener noreferrer">Dropbox OAuth guide</a>), then paste it in the <strong>OAuth2 Refresh Token</strong> field.',
        ],
    },
    'box': {
        'label': 'Box',
        'icon': 'fa-box',
        'icon_prefix': 'fas',
        'dev_url': 'https://app.box.com/developers/console',
        'dev_label': 'Box Developer Console',
        'uses_oauth': True,
        'fields': [
            {'key': 'client_id', 'label': 'OAuth2 Client ID', 'type': 'text', 'help': 'Your Box app Client ID.'},
            {'key': 'client_secret', 'label': 'OAuth2 Client Secret', 'type': 'password', 'help': 'Your Box app Client Secret.'},
            {'key': 'refresh_token', 'label': 'OAuth2 Refresh Token', 'type': 'password',
             'help': 'Long-lived refresh token obtained after completing the Box OAuth2 flow.'},
        ],
        'instructions': [
            '1. Go to <a href="https://app.box.com/developers/console" target="_blank" rel="noopener noreferrer">Box Developer Console</a> and log in.',
            '2. Click <strong>Create New App</strong> → <strong>Custom App</strong> → <strong>User Authentication (OAuth 2.0)</strong>.',
            '3. After creating, open the app and go to the <strong>Configuration</strong> tab.',
            '4. Under <strong>OAuth 2.0 Redirect URI</strong>, add the redirect URL shown above and click <strong>Save Changes</strong>.',
            '5. Copy the <strong>Client ID</strong> and <strong>Client Secret</strong> and paste them in the fields above.',
            '6. To obtain a refresh token, send your user to the Box authorization URL (<code>https://account.box.com/api/oauth2/authorize?client_id=YOUR_CLIENT_ID&amp;response_type=code&amp;redirect_uri=REDIRECT_URL</code>). After approval, Box will redirect to your redirect URL with a <code>code</code> parameter. Exchange that code at <code>https://api.box.com/oauth2/token</code> with your client ID and secret to receive an access token and a refresh token.',
            '7. Paste the refresh token in the <strong>OAuth2 Refresh Token</strong> field above.',
        ],
    },
    's3': {
        'label': 'S3 Object Storage',
        'icon': 'fa-aws',
        'icon_prefix': 'fab',
        'dev_url': 'https://aws.amazon.com/s3/',
        'dev_label': 'AWS Console',
        'uses_oauth': False,
        'fields': [
            {'key': 'aws_access_key_id', 'label': 'Access Key ID', 'type': 'text',
             'help': 'Your AWS (or S3-compatible provider) Access Key ID.'},
            {'key': 'aws_secret_access_key', 'label': 'Secret Access Key', 'type': 'password',
             'help': 'Your AWS (or S3-compatible provider) Secret Access Key.'},
            {'key': 'bucket_name', 'label': 'Bucket Name', 'type': 'text',
             'help': 'Name of the S3 bucket where backups will be stored.'},
            {'key': 'region', 'label': 'Region (e.g. us-east-1)', 'type': 'text',
             'help': 'AWS region of the bucket. For non-AWS providers this can often be any value.'},
            {'key': 'endpoint_url', 'label': 'Custom Endpoint URL (optional)', 'type': 'text',
             'help': 'Leave blank for AWS S3. For S3-compatible services (MinIO, DigitalOcean Spaces, Wasabi, etc.) enter the provider endpoint, e.g. https://s3.us-east-1.wasabisys.com'},
            {'key': 'prefix', 'label': 'Object Key Prefix (optional)', 'type': 'text',
             'help': 'Folder/prefix inside the bucket. Defaults to "rijanauth-backups" if left blank.'},
        ],
        'instructions': [
            '1. Log in to the <a href="https://console.aws.amazon.com/s3/" target="_blank" rel="noopener noreferrer">AWS Console</a> and create an S3 bucket (or use an existing one).',
            '2. Go to <strong>IAM → Users</strong>, create a user with <strong>programmatic access</strong>, and attach the <strong>AmazonS3FullAccess</strong> policy (or a scoped policy that allows <code>s3:PutObject</code> and <code>s3:GetObject</code> on the bucket).',
            '3. Copy the <strong>Access Key ID</strong> and <strong>Secret Access Key</strong> shown after creation.',
            '4. Enter the bucket name and the AWS region (e.g. <code>us-east-1</code>).',
            '5. <strong>S3-compatible providers</strong> (MinIO, DigitalOcean Spaces, Wasabi, Backblaze B2, etc.): enter your provider\'s endpoint URL in the <strong>Custom Endpoint URL</strong> field and use your provider\'s access key and secret key.',
        ],
    },
}


def _require_master_realm(realm_name):
    """Return True if we are in the master realm, otherwise redirect."""
    from config.seeding import SeedingConfig
    return realm_name == SeedingConfig.MASTER_REALM_NAME


@admin_bp.route('/<realm_name>/backup', methods=['GET', 'POST'])
@login_required
def backup_index(realm_name):
    """Backup configuration & manual trigger page (master realm only)."""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    if not _require_master_realm(realm_name):
        flash('The backup feature is only available in the master realm.', 'warning')
        return redirect(url_for('admin.dashboard', realm_name=realm_name))

    realms = Realm.query.all()
    config = BackupConfig.get_config()
    history = BackupRecord.get_history(limit=20)

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'save_config':
            provider = request.form.get('storage_provider', '').strip()
            interval = request.form.get('auto_backup_interval', '') or None
            zip_password = request.form.get('zip_password', '').strip()

            # Build credentials dict
            creds: dict = {}
            if zip_password:
                creds['zip_password'] = zip_password

            if provider and provider in PROVIDER_INFO:
                for field in PROVIDER_INFO[provider]['fields']:
                    val = request.form.get(field['key'], '').strip()
                    if val:
                        creds[field['key']] = val

            if not config:
                config = BackupConfig()
                db.session.add(config)

            config.storage_provider = provider or None
            config.auto_backup_interval = interval
            config.credentials_json = json.dumps(creds) if creds else None
            db.session.commit()

            BackupService.apply_config()
            flash('Backup configuration saved.', 'success')
            return redirect(url_for('admin.backup_index', realm_name=realm_name))

        elif action == 'manual_backup':
            zip_password = request.form.get('backup_password', '').strip() or None
            try:
                record = BackupService.create_backup(
                    zip_password,
                    triggered_by_user_id=str(current_user.id),
                )
                if record.status == 'success':
                    flash(f'Backup created successfully: {record.filename}', 'success')
                else:
                    flash(f'Backup failed: {record.error_message}', 'error')
            except Exception as exc:
                flash(f'Backup error: {exc}', 'error')

            return redirect(url_for('admin.backup_index', realm_name=realm_name))

    # Decode stored credentials for display (omit secrets)
    stored_creds: dict = {}
    if config and config.credentials_json:
        try:
            raw = json.loads(config.credentials_json)
            # Expose non-secret fields for pre-fill; mask passwords/tokens
            secret_keys = {'password', 'app_secret', 'refresh_token',
                           'developer_token', 'service_account_json', 'zip_password',
                           'aws_secret_access_key', 'client_secret'}
            for k, v in raw.items():
                stored_creds[k] = '' if k in secret_keys else v
        except Exception:
            pass

    # Build OAuth redirect URLs for providers that use OAuth
    oauth_redirect_urls = {
        key: url_for('admin.backup_oauth_callback', realm_name=realm_name,
                     provider=key, _external=True)
        for key, info in PROVIDER_INFO.items()
        if info.get('uses_oauth')
    }

    return render_template(
        'admin/backup/backup.html',
        realm=realm,
        realms=realms,
        backup_config=config,
        history=history,
        stored_creds=stored_creds,
        provider_info=PROVIDER_INFO,
        oauth_redirect_urls=oauth_redirect_urls,
        segment='backup',
    )


@admin_bp.route('/<realm_name>/backup/oauth/callback/<provider>', methods=['GET'])
@login_required
def backup_oauth_callback(realm_name, provider):
    """
    OAuth2 redirect URI for cloud storage providers (Google Drive, Dropbox, Box).
    Register the URL of this endpoint in each provider's OAuth app settings.
    After the provider redirects here with an authorization code, the user is
    sent back to the backup configuration page where they can complete setup.
    """
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    if not _require_master_realm(realm_name):
        return redirect(url_for('admin.dashboard', realm_name=realm_name))

    if provider not in PROVIDER_INFO or not PROVIDER_INFO[provider].get('uses_oauth'):
        flash(f'Unknown OAuth provider: {provider}', 'error')
        return redirect(url_for('admin.backup_index', realm_name=realm_name))

    provider_label = PROVIDER_INFO[provider]['label']
    auth_code = request.args.get('code', '')
    error = request.args.get('error', '')

    if error:
        flash(f'{provider_label} OAuth error: {error}', 'error')
        return redirect(url_for('admin.backup_index', realm_name=realm_name))

    if auth_code:
        flash(
            f'{provider_label} authorization code received. '
            'Exchange this code for a refresh token using your OAuth client credentials '
            'and paste the resulting refresh token in the configuration below.',
            'info',
        )
    else:
        flash(
            f'No authorization code was returned by {provider_label}. '
            'Please complete the OAuth flow from your provider\'s app console.',
            'warning',
        )

    return redirect(url_for('admin.backup_index', realm_name=realm_name))


@admin_bp.route('/<realm_name>/backup/restore', methods=['GET', 'POST'])
@login_required
def backup_restore(realm_name):
    """Restore from a previous backup (master realm only)."""
    realm = get_realm_or_404(realm_name)
    if not realm:
        return redirect(url_for('admin.index'))

    if not _require_master_realm(realm_name):
        flash('The restore feature is only available in the master realm.', 'warning')
        return redirect(url_for('admin.dashboard', realm_name=realm_name))

    realms = Realm.query.all()
    history = BackupRecord.get_history(limit=50)

    if request.method == 'POST':
        record_id = request.form.get('record_id', '').strip()
        zip_password = request.form.get('zip_password', '').strip()

        if not record_id:
            flash('Please select a backup to restore.', 'error')
        else:
            try:
                stats = BackupService.restore_from_record(record_id, zip_password or None)
                flash(
                    f'Restore completed: {stats["tables_restored"]} tables, '
                    f'{stats["rows_restored"]} rows restored.',
                    'success',
                )
                if stats.get('errors'):
                    flash(
                        'Some non-fatal errors occurred: ' + '; '.join(stats['errors'][:5]),
                        'warning',
                    )
            except Exception as exc:
                flash(f'Restore failed: {exc}', 'error')

        return redirect(url_for('admin.backup_restore', realm_name=realm_name))

    return render_template(
        'admin/backup/restore.html',
        realm=realm,
        realms=realms,
        history=history,
        segment='backup',
    )
