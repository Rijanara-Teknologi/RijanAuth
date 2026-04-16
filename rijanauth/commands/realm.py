# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Realm Commands
Manage realms
"""

import click
import json
from tabulate import tabulate

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.services.realm_service import RealmService


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


REALM_SETTABLE_FIELDS = {
    'access_token_lifespan': {'type': 'int', 'default': 86400, 'description': 'Access token lifetime in seconds'},
    'access_token_lifespan_for_implicit_flow': {'type': 'int', 'default': 900, 'description': 'Access token lifetime for implicit flow'},
    'sso_session_idle_timeout': {'type': 'int', 'default': 1800, 'description': 'SSO session idle timeout'},
    'sso_session_max_lifespan': {'type': 'int', 'default': 36000, 'description': 'SSO session max lifespan'},
    'offline_session_idle_timeout': {'type': 'int', 'default': 2592000, 'description': 'Offline session idle timeout'},
    'access_code_lifespan': {'type': 'int', 'default': 60, 'description': 'Access code lifetime'},
    'access_code_lifespan_user_action': {'type': 'int', 'default': 300, 'description': 'Access code lifetime for user action'},
    'access_code_lifespan_login': {'type': 'int', 'default': 1800, 'description': 'Access code lifetime for login'},
    'max_login_failures': {'type': 'int', 'default': 30, 'description': 'Max login failures before lockout'},
    'wait_increment_seconds': {'type': 'int', 'default': 60, 'description': 'Wait time increment'},
    'brute_force_protected': {'type': 'bool', 'default': True, 'description': 'Enable brute force protection'},
    'registration_allowed': {'type': 'bool', 'default': False, 'description': 'Allow user registration'},
    'verify_email': {'type': 'bool', 'default': False, 'description': 'Require email verification'},
    'login_with_email_allowed': {'type': 'bool', 'default': True, 'description': 'Allow login with email'},
    'reset_password_allowed': {'type': 'bool', 'default': True, 'description': 'Allow password reset'},
    'remember_me': {'type': 'bool', 'default': True, 'description': 'Enable remember me'},
    'enabled': {'type': 'bool', 'default': True, 'description': 'Enable realm'},
    'display_name': {'type': 'str', 'default': None, 'description': 'Display name'},
}


@click.group()
def realm():
    """Manage realms"""
    pass


@realm.command('list')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def list_realms(output_json):
    """List all realms"""
    app = init_app()
    
    with app.app_context():
        realms = Realm.query.all()
        
        if output_json:
            data = [{'name': r.name, 'display_name': r.display_name, 'enabled': r.enabled} for r in realms]
            click.echo(json.dumps(data, indent=2))
        else:
            if not realms:
                click.echo("No realms found.")
                return
            
            table = []
            for r in realms:
                table.append([
                    r.name,
                    r.display_name or '-',
                    'Yes' if r.enabled else 'No',
                    r.access_token_lifespan,
                ])
            
            click.echo("\nRealms:")
            click.echo(tabulate(table, headers=['Name', 'Display Name', 'Enabled', 'Token Lifespan'], tablefmt='grid'))


@realm.command()
@click.argument('name')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--all', 'show_all', is_flag=True, help='Show all settings including SMTP (masked)')
def get(name, output_json, show_all):
    """Get realm details"""
    app = init_app()
    
    with app.app_context():
        realm = Realm.find_by_name(name)
        
        if not realm:
            click.echo(f"Realm '{name}' not found.", err=True)
            return
        
        if output_json:
            data = realm.to_dict()
            if not show_all:
                for key in ['smtp_password', 'smtp_user']:
                    if key in data:
                        data[key] = '********' if data[key] else None
            click.echo(json.dumps(data, indent=2, default=str))
        else:
            click.echo(f"\n{'=' * 60}")
            click.echo(f"Realm: {realm.name}")
            click.echo(f"{'=' * 60}")
            
            click.echo("\nBasic Settings:")
            basic_table = [
                ['Display Name', realm.display_name or '-'],
                ['Enabled', 'Yes' if realm.enabled else 'No'],
            ]
            click.echo(tabulate(basic_table, tablefmt='plain'))
            
            click.echo("\nToken Settings:")
            token_table = [
                ['access_token_lifespan', realm.access_token_lifespan, 'seconds'],
                ['access_token_lifespan_for_implicit_flow', realm.access_token_lifespan_for_implicit_flow, 'seconds'],
                ['sso_session_idle_timeout', realm.sso_session_idle_timeout, 'seconds'],
                ['sso_session_max_lifespan', realm.sso_session_max_lifespan, 'seconds'],
                ['offline_session_idle_timeout', realm.offline_session_idle_timeout, 'seconds'],
                ['access_code_lifespan', realm.access_code_lifespan, 'seconds'],
                ['access_code_lifespan_user_action', realm.access_code_lifespan_user_action, 'seconds'],
                ['access_code_lifespan_login', realm.access_code_lifespan_login, 'seconds'],
            ]
            click.echo(tabulate(token_table, headers=['Setting', 'Value', 'Unit'], tablefmt='grid'))
            
            click.echo("\nLogin Settings:")
            login_table = [
                ['registration_allowed', 'Yes' if realm.registration_allowed else 'No'],
                ['verify_email', 'Yes' if realm.verify_email else 'No'],
                ['login_with_email_allowed', 'Yes' if realm.login_with_email_allowed else 'No'],
                ['reset_password_allowed', 'Yes' if realm.reset_password_allowed else 'No'],
                ['remember_me', 'Yes' if realm.remember_me else 'No'],
            ]
            click.echo(tabulate(login_table, tablefmt='grid'))
            
            click.echo("\nSecurity Settings:")
            security_table = [
                ['brute_force_protected', 'Yes' if realm.brute_force_protected else 'No'],
                ['max_login_failures', realm.max_login_failures],
                ['wait_increment_seconds', realm.wait_increment_seconds],
            ]
            click.echo(tabulate(security_table, tablefmt='grid'))
            
            if show_all:
                click.echo("\nSMTP Settings:")
                smtp_table = [
                    ['smtp_server', realm.smtp_server or '-'],
                    ['smtp_port', realm.smtp_port or '-'],
                    ['smtp_from', realm.smtp_from or '-'],
                    ['smtp_ssl', 'Yes' if realm.smtp_ssl else 'No'],
                    ['smtp_starttls', 'Yes' if realm.smtp_starttls else 'No'],
                    ['smtp_auth', 'Yes' if realm.smtp_auth else 'No'],
                    ['smtp_user', '********' if realm.smtp_user else '-'],
                ]
                click.echo(tabulate(smtp_table, tablefmt='grid'))


@realm.command()
@click.argument('name')
@click.argument('key')
@click.argument('value')
def set(name, key, value):
    """Set a realm setting
    
    NAME: Realm name
    KEY: Setting key (use 'list-keys' to see all available keys)
    VALUE: New value
    
    Example:
        rijanauth realm set alfida access_token_lifespan 86400
    """
    app = init_app()
    
    with app.app_context():
        realm = Realm.find_by_name(name)
        
        if not realm:
            click.echo(f"Realm '{name}' not found.", err=True)
            return
        
        if key not in REALM_SETTABLE_FIELDS:
            click.echo(f"Unknown setting key: {key}", err=True)
            click.echo("Use 'rijanauth realm list-keys' to see all available keys.")
            return
        
        field_info = REALM_SETTABLE_FIELDS[key]
        field_type = field_info['type']
        
        try:
            if field_type == 'int':
                new_value = int(value)
            elif field_type == 'bool':
                new_value = value.lower() in ('true', 'yes', '1', 'on')
            else:
                new_value = value
            
            old_value = getattr(realm, key)
            setattr(realm, key, new_value)
            db.session.commit()
            
            click.echo(f"Updated {name}.{key}: {old_value} -> {new_value}")
            
        except ValueError:
            click.echo(f"Invalid value for {key}: '{value}' (expected {field_type})", err=True)


@realm.command('list-keys')
def list_keys():
    """List all configurable realm settings"""
    click.echo("\nConfigurable Realm Settings:\n")
    
    for key, info in REALM_SETTABLE_FIELDS.items():
        default_str = f" (default: {info['default']})" if info['default'] is not None else ""
        click.echo(f"  {key}{default_str}")
        click.echo(f"    {info['description']}")
        click.echo(f"    Type: {info['type']}")
        click.echo()


@realm.command()
@click.argument('name')
@click.option('--display-name', help='Display name for the realm')
@click.option('--token-lifespan', type=int, default=86400, help='Access token lifespan in seconds')
@click.option('--sso-idle-timeout', type=int, default=1800, help='SSO idle timeout in seconds')
@click.option('--enabled/--disabled', default=True, help='Enable or disable realm')
def create(name, display_name, token_lifespan, sso_idle_timeout, enabled):
    """Create a new realm"""
    app = init_app()
    
    with app.app_context():
        existing = Realm.find_by_name(name)
        if existing:
            click.echo(f"Realm '{name}' already exists.", err=True)
            return
        
        try:
            realm = RealmService.create_realm(
                name=name,
                display_name=display_name or name.title()
            )
            
            realm.access_token_lifespan = token_lifespan
            realm.sso_session_idle_timeout = sso_idle_timeout
            realm.enabled = enabled
            realm.save()
            
            click.echo(f"Created realm '{name}' successfully.")
            
        except Exception as e:
            click.echo(f"Error creating realm: {str(e)}", err=True)


@realm.command()
@click.argument('name')
@click.confirmation_option(prompt='Are you sure you want to delete this realm?')
def delete(name):
    """Delete a realm"""
    app = init_app()
    
    with app.app_context():
        realm = Realm.find_by_name(name)
        
        if not realm:
            click.echo(f"Realm '{name}' not found.", err=True)
            return
        
        try:
            realm.delete()
            db.session.commit()
            click.echo(f"Deleted realm '{name}' successfully.")
        except Exception as e:
            click.echo(f"Error deleting realm: {str(e)}", err=True)


@realm.command()
@click.argument('name')
@click.option('--interactive', '-i', is_flag=True, help='Interactive mode')
def update(name, interactive):
    """Update realm settings interactively"""
    app = init_app()
    
    with app.app_context():
        realm = Realm.find_by_name(name)
        
        if not realm:
            click.echo(f"Realm '{name}' not found.", err=True)
            return
        
        if not interactive:
            click.echo("Use --interactive flag to update settings interactively.")
            click.echo("Or use: rijanauth realm set <name> <key> <value>")
            return
        
        click.echo(f"\nUpdating realm: {name}")
        click.echo("Press Enter to keep current value.\n")
        
        for key, info in REALM_SETTABLE_FIELDS.items():
            current = getattr(realm, key)
            prompt = f"{key} [{current}]: "
            value = click.prompt(prompt, default=str(current), show_default=False)
            
            if value == str(current):
                continue
            
            try:
                if info['type'] == 'int':
                    new_value = int(value)
                elif info['type'] == 'bool':
                    new_value = value.lower() in ('true', 'yes', '1', 'on')
                else:
                    new_value = value
                
                setattr(realm, key, new_value)
                click.echo(f"  Set {key} = {new_value}")
                
            except ValueError:
                click.echo(f"  Invalid value, skipping.")
        
        db.session.commit()
        click.echo("\nRealm updated successfully.")


@realm.command()
@click.argument('name')
def enable(name):
    """Enable a realm"""
    app = init_app()
    
    with app.app_context():
        realm = Realm.find_by_name(name)
        
        if not realm:
            click.echo(f"Realm '{name}' not found.", err=True)
            return
        
        realm.enabled = True
        realm.save()
        click.echo(f"Enabled realm '{name}'.")


@realm.command()
@click.argument('name')
def disable(name):
    """Disable a realm"""
    app = init_app()
    
    with app.app_context():
        realm = Realm.find_by_name(name)
        
        if not realm:
            click.echo(f"Realm '{name}' not found.", err=True)
            return
        
        realm.enabled = False
        realm.save()
        click.echo(f"Disabled realm '{name}'.")
