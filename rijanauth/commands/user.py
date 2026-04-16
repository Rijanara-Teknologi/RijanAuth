# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - User Commands
Manage users
"""

import click
import json
from tabulate import tabulate
from datetime import datetime

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.session import UserSession
from apps.services.user_service import UserService


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


@click.group()
def user():
    """Manage users"""
    pass


@user.command('list')
@click.argument('realm')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--search', '-s', help='Search by username or email')
@click.option('--enabled/--disabled', default=None, help='Filter by enabled status')
@click.option('--limit', '-l', type=int, default=50, help='Maximum results')
@click.option('--offset', type=int, default=0, help='Offset for pagination')
def list_users(realm, output_json, search, enabled, limit, offset):
    """List users in a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        query = User.query.filter_by(realm_id=realm_obj.id)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                db.or_(
                    User.username.ilike(search_pattern),
                    User.email.ilike(search_pattern),
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern)
                )
            )
        
        if enabled is not None:
            query = query.filter_by(enabled=enabled)
        
        total = query.count()
        users = query.offset(offset).limit(limit).all()
        
        if output_json:
            data = [{
                'id': u.id,
                'username': u.username,
                'email': u.email,
                'first_name': u.first_name,
                'last_name': u.last_name,
                'enabled': u.enabled,
                'created_at': u.created_at.isoformat() if u.created_at else None,
            } for u in users]
            click.echo(json.dumps({'total': total, 'users': data}, indent=2))
        else:
            if not users:
                click.echo(f"No users found in realm '{realm}'.")
                return
            
            click.echo(f"\nUsers in '{realm}' (showing {len(users)} of {total}):")
            
            table = []
            for u in users:
                name = f"{u.first_name or ''} {u.last_name or ''}".strip() or '-'
                table.append([
                    u.username,
                    u.email or '-',
                    name,
                    'Yes' if u.enabled else 'No',
                    u.created_at.strftime('%Y-%m-%d') if u.created_at else '-',
                ])
            
            click.echo(tabulate(table, headers=['Username', 'Email', 'Name', 'Enabled', 'Created'], tablefmt='grid'))


@user.command()
@click.argument('realm')
@click.argument('username')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def get(realm, username, output_json):
    """Get user details"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        if output_json:
            data = user.to_dict(include_attributes=True)
            click.echo(json.dumps(data, indent=2, default=str))
        else:
            roles = UserService.get_user_roles(user)
            groups = UserService.get_user_groups(user)
            sessions = user.sessions.filter_by(state='ACTIVE').all()
            
            click.echo(f"\n{'=' * 60}")
            click.echo(f"User: {user.username}")
            click.echo(f"{'=' * 60}")
            
            click.echo("\nBasic Info:")
            basic_table = [
                ['ID', user.id],
                ['Username', user.username],
                ['Email', user.email or '-'],
                ['First Name', user.first_name or '-'],
                ['Last Name', user.last_name or '-'],
                ['Enabled', 'Yes' if user.enabled else 'No'],
                ['Email Verified', 'Yes' if user.email_verified else 'No'],
                ['Created', user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else '-'],
                ['Last Login', user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never'],
            ]
            click.echo(tabulate(basic_table, tablefmt='plain'))
            
            click.echo(f"\nRoles ({len(roles)}):")
            if roles:
                for r in roles:
                    click.echo(f"  - {r.name}")
            else:
                click.echo("  None")
            
            click.echo(f"\nGroups ({len(groups)}):")
            if groups:
                for g in groups:
                    click.echo(f"  - {g.name}")
            else:
                click.echo("  None")
            
            click.echo(f"\nActive Sessions ({len(sessions)}):")
            if sessions:
                for s in sessions[:5]:
                    ip = s.ip_address or 'Unknown'
                    started = s.started.strftime('%Y-%m-%d %H:%M') if s.started else 'Unknown'
                    click.echo(f"  - {ip} ({started})")
                if len(sessions) > 5:
                    click.echo(f"  ... and {len(sessions) - 5} more")
            else:
                click.echo("  None")


@user.command()
@click.argument('realm')
@click.argument('username')
@click.option('--email', help='Email address')
@click.option('--first-name', help='First name')
@click.option('--last-name', help='Last name')
@click.option('--password', help='Initial password')
@click.option('--enabled/--disabled', default=True, help='Enable or disable user')
def create(realm, username, email, first_name, last_name, password, enabled):
    """Create a new user"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        existing = User.find_by_username(realm_obj.id, username)
        if existing:
            click.echo(f"User '{username}' already exists in realm '{realm}'.", err=True)
            return
        
        try:
            user = UserService.create_user(
                realm_id=realm_obj.id,
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=password,
                enabled=enabled,
            )
            
            click.echo(f"Created user '{username}' in realm '{realm}'.")
            
        except Exception as e:
            click.echo(f"Error creating user: {str(e)}", err=True)


@user.command('reset-password')
@click.argument('realm')
@click.argument('username')
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=True, help='New password')
def reset_password(realm, username, password):
    """Reset user password"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        try:
            UserService.set_password(user, password)
            click.echo(f"Password reset for user '{username}'.")
        except Exception as e:
            click.echo(f"Error resetting password: {str(e)}", err=True)


@user.command('set-password')
@click.argument('realm')
@click.argument('username')
@click.option('--password', '-p', required=True, help='New password')
def set_password(realm, username, password):
    """Set user password (non-interactive)"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        try:
            UserService.set_password(user, password)
            click.echo(f"Password set for user '{username}'.")
        except Exception as e:
            click.echo(f"Error setting password: {str(e)}", err=True)


@user.command()
@click.argument('realm')
@click.argument('username')
@click.confirmation_option(prompt='Are you sure you want to delete this user?')
def delete(realm, username):
    """Delete a user"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        try:
            UserService.delete_user(user)
            click.echo(f"Deleted user '{username}'.")
        except Exception as e:
            click.echo(f"Error deleting user: {str(e)}", err=True)


@user.command()
@click.argument('realm')
@click.argument('username')
@click.option('--enable/--disable', 'enable', default=True, help='Enable or disable user')
def toggle(realm, username, enable):
    """Enable or disable a user"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        user.enabled = enable
        db.session.commit()
        
        action = 'Enabled' if enable else 'Disabled'
        click.echo(f"{action} user '{username}'.")


@user.command('logout')
@click.argument('realm')
@click.argument('username')
@click.option('--all-clients', is_flag=True, help='Logout from all client sessions')
def logout(realm, username, all_clients):
    """Logout a user (revoke all sessions)"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        sessions = UserSession.query.filter_by(user_id=user.id, state='ACTIVE').all()
        count = len(sessions)
        
        for session in sessions:
            session.logout()
        
        db.session.commit()
        
        click.echo(f"Logged out {count} session(s) for user '{username}'.")


@user.command('stats')
@click.argument('realm')
def stats(realm):
    """Show user statistics for a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        total = User.query.filter_by(realm_id=realm_obj.id).count()
        enabled = User.query.filter_by(realm_id=realm_obj.id, enabled=True).count()
        disabled = total - enabled
        
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent = User.query.filter(
            User.realm_id == realm_obj.id,
            User.created_at >= week_ago
        ).count()
        
        active_sessions = UserSession.query.filter_by(
            realm_id=realm_obj.id,
            state='ACTIVE'
        ).count()
        
        click.echo(f"\nUser Statistics for '{realm}':")
        stats_table = [
            ['Total Users', total],
            ['Enabled', enabled],
            ['Disabled', disabled],
            ['Recent Registrations (7 days)', recent],
            ['Active Sessions', active_sessions],
        ]
        click.echo(tabulate(stats_table, tablefmt='grid'))


@user.command()
@click.argument('realm')
@click.argument('username')
@click.argument('role_name')
def add_role(realm, username, role_name):
    """Add a role to a user"""
    app = init_app()
    
    with app.app_context():
        from apps.models.role import Role
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        role = Role.find_realm_role(realm_obj.id, role_name)
        if not role:
            click.echo(f"Role '{role_name}' not found in realm '{realm}'.", err=True)
            return
        
        try:
            UserService.assign_role(user, role)
            click.echo(f"Added role '{role_name}' to user '{username}'.")
        except Exception as e:
            click.echo(f"Error adding role: {str(e)}", err=True)


@user.command()
@click.argument('realm')
@click.argument('username')
@click.argument('role_name')
def remove_role(realm, username, role_name):
    """Remove a role from a user"""
    app = init_app()
    
    with app.app_context():
        from apps.models.role import Role
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found in realm '{realm}'.", err=True)
            return
        
        role = Role.find_realm_role(realm_obj.id, role_name)
        if not role:
            click.echo(f"Role '{role_name}' not found in realm '{realm}'.", err=True)
            return
        
        try:
            UserService.remove_role(user, role)
            click.echo(f"Removed role '{role_name}' from user '{username}'.")
        except Exception as e:
            click.echo(f"Error removing role: {str(e)}", err=True)


from datetime import timedelta
