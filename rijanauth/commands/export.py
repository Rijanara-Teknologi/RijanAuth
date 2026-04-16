# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Export/Import Commands
Import and export data
"""

import click
import csv
import io
from tabulate import tabulate
from datetime import datetime

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.services.import_service import ImportService
from apps.services.user_service import UserService


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


@click.group()
def export():
    """Import and export data"""
    pass


@export.command('users')
@click.argument('realm')
@click.option('--output', '-o', type=click.File('w'), default='-', help='Output file (default: stdout)')
@click.option('--format', 'output_format', type=click.Choice(['csv', 'json']), default='csv', help='Output format')
def export_users(realm, output, output_format):
    """Export users from a realm to CSV"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        users = app.extensions['sqlalchemy'].session.query(
            __import__('apps.models.user', fromlist=['User']).User
        ).filter_by(realm_id=realm_obj.id).all()
        
        click.echo(f"Exporting {len(users)} users from '{realm}'...")
        
        if output_format == 'json':
            import json
            data = []
            for user in users:
                roles = UserService.get_user_roles(user)
                groups = UserService.get_user_groups(user)
                data.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'enabled': user.enabled,
                    'roles': [r.name for r in roles],
                    'groups': [g.name for g in groups],
                })
            output.write(json.dumps(data, indent=2))
        else:
            output_writer = csv.writer(output)
            output_writer.writerow(['id', 'username', 'email', 'first_name', 'last_name', 'enabled', 'roles', 'groups'])
            
            for user in users:
                roles = UserService.get_user_roles(user)
                groups = UserService.get_user_groups(user)
                output_writer.writerow([
                    user.id,
                    user.username,
                    user.email or '',
                    user.first_name or '',
                    user.last_name or '',
                    user.enabled,
                    ';'.join(r.name for r in roles),
                    ';'.join(g.name for g in groups),
                ])
        
        click.echo(f"Exported {len(users)} users.")


@export.command('roles')
@click.argument('realm')
@click.option('--output', '-o', type=click.File('w'), default='-', help='Output file (default: stdout)')
def export_roles(realm, output):
    """Export roles from a realm to CSV"""
    app = init_app()
    
    with app.app_context():
        from apps.models.role import Role
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        roles = Role.get_realm_roles(realm_obj.id)
        
        click.echo(f"Exporting {len(roles)} roles from '{realm}'...")
        
        writer = csv.writer(output)
        writer.writerow(['name', 'description'])
        
        for role in roles:
            writer.writerow([role.name, role.description or ''])
        
        click.echo(f"Exported {len(roles)} roles.")


@export.command('groups')
@click.argument('realm')
@click.option('--output', '-o', type=click.File('w'), default='-', help='Output file (default: stdout)')
def export_groups(realm, output):
    """Export groups from a realm to CSV"""
    app = init_app()
    
    with app.app_context():
        from apps.models.group import Group
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        groups = Group.get_top_level_groups(realm_obj.id)
        
        click.echo(f"Exporting groups from '{realm}'...")
        
        writer = csv.writer(output)
        writer.writerow(['name', 'path'])
        
        def write_group(g, prefix=''):
            writer.writerow([prefix + g.name, g.path])
            for child in g.children:
                write_group(child, prefix + g.name + '/')
        
        for group in groups:
            write_group(group)
        
        click.echo(f"Exported groups.")


@export.command('template')
@click.argument('type')
@click.option('--output', '-o', type=click.File('w'), default='-', help='Output file (default: stdout)')
def export_template(type, output):
    """Export import template for users, roles, or groups"""
    if type == 'users':
        output.write('username,email,password,first_name,last_name,roles,groups\nexample,user@example.com,password123,John,Doe,admin;user,group1;group2\n')
    elif type == 'roles':
        output.write('name,description\nguru_quran,Guru Quran\nguru_ekstrakurikuler,Guru Ekstrakurikuler\n')
    elif type == 'groups':
        output.write('name\nPQA dan Asrama\nSDIT 3\n')
    else:
        click.echo(f"Unknown template type: {type}", err=True)
        return
    
    click.echo(f"Template for {type} exported.")


@export.command('import-users')
@click.argument('realm')
@click.argument('file', type=click.File('r'))
@click.option('--dry-run', is_flag=True, help='Preview changes without applying')
def import_users(realm, file, dry_run):
    """Import users from CSV file"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        csv_content = file.read()
        
        click.echo(f"Importing users into '{realm}'...")
        
        if dry_run:
            click.echo("[DRY RUN] Preview of changes:")
        
        result = ImportService.import_users(realm_obj.id, csv_content)
        
        click.echo(f"\nImport Results:")
        click.echo(f"  Total rows: {result.get('total_rows', 0)}")
        click.echo(f"  Imported: {result.get('imported', 0)}")
        click.echo(f"  Updated: {result.get('updated', 0)}")
        click.echo(f"  Skipped: {result.get('skipped', 0)}")
        click.echo(f"  Errors: {len(result.get('errors', []))}")
        
        if result.get('errors'):
            click.echo("\nErrors:")
            for error in result['errors'][:10]:
                click.echo(f"  - {error}")


@export.command('import-roles')
@click.argument('realm')
@click.argument('file', type=click.File('r'))
def import_roles(realm, file):
    """Import roles from CSV file"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        csv_content = file.read()
        
        click.echo(f"Importing roles into '{realm}'...")
        
        result = ImportService.import_roles(realm_obj.id, csv_content)
        
        click.echo(f"\nImport Results:")
        click.echo(f"  Total rows: {result.get('total_rows', 0)}")
        click.echo(f"  Imported: {result.get('imported', 0)}")
        click.echo(f"  Skipped: {result.get('skipped', 0)}")
        click.echo(f"  Errors: {len(result.get('errors', []))}")


@export.command('import-groups')
@click.argument('realm')
@click.argument('file', type=click.File('r'))
def import_groups(realm, file):
    """Import groups from CSV file"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        csv_content = file.read()
        
        click.echo(f"Importing groups into '{realm}'...")
        
        result = ImportService.import_groups(realm_obj.id, csv_content)
        
        click.echo(f"\nImport Results:")
        click.echo(f"  Total rows: {result.get('total_rows', 0)}")
        click.echo(f"  Imported: {result.get('imported', 0)}")
        click.echo(f"  Skipped: {result.get('skipped', 0)}")
        click.echo(f"  Errors: {len(result.get('errors', []))}")
