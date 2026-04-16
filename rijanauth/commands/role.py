# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Role Commands
Manage roles
"""

import click
import json
from tabulate import tabulate

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.models.role import Role


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


@click.group()
def role():
    """Manage roles"""
    pass


@role.command('list')
@click.argument('realm')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--search', '-s', help='Search by name')
def list_roles(realm, output_json, search):
    """List roles in a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        query = Role.query.filter_by(realm_id=realm_obj.id, client_id=None)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                db.or_(
                    Role.name.ilike(search_pattern),
                    Role.description.ilike(search_pattern)
                )
            )
        
        roles = query.all()
        
        if output_json:
            data = [{
                'id': r.id,
                'name': r.name,
                'description': r.description,
                'composite': r.composite,
            } for r in roles]
            click.echo(json.dumps(data, indent=2))
        else:
            if not roles:
                click.echo(f"No roles found in realm '{realm}'.")
                return
            
            click.echo(f"\nRoles in '{realm}':")
            
            table = []
            for r in roles:
                table.append([
                    r.name,
                    r.description or '-',
                    'Yes' if r.composite else 'No',
                ])
            
            click.echo(tabulate(table, headers=['Name', 'Description', 'Composite'], tablefmt='grid'))


@role.command()
@click.argument('realm')
@click.argument('name')
@click.option('--description', '-d', help='Role description')
def create(realm, name, description):
    """Create a new role"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        existing = Role.find_realm_role(realm_obj.id, name)
        if existing:
            click.echo(f"Role '{name}' already exists in realm '{realm}'.", err=True)
            return
        
        try:
            role = Role(
                realm_id=realm_obj.id,
                name=name,
                description=description,
                client_id=None,
                client_role=False,
                composite=False
            )
            role.save()
            
            click.echo(f"Created role '{name}' in realm '{realm}'.")
            
        except Exception as e:
            click.echo(f"Error creating role: {str(e)}", err=True)


@role.command()
@click.argument('realm')
@click.argument('name')
@click.confirmation_option(prompt='Are you sure you want to delete this role?')
def delete(realm, name):
    """Delete a role"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        role = Role.find_realm_role(realm_obj.id, name)
        if not role:
            click.echo(f"Role '{name}' not found in realm '{realm}'.", err=True)
            return
        
        protected = ['default-roles-' + realm, 'offline_access', 'uma_authorization']
        if role.name in protected:
            click.echo(f"Cannot delete protected role '{name}'.", err=True)
            return
        
        try:
            role.delete()
            db.session.commit()
            click.echo(f"Deleted role '{name}'.")
        except Exception as e:
            click.echo(f"Error deleting role: {str(e)}", err=True)


@role.command('add-composite')
@click.argument('realm')
@click.argument('composite_role')
@click.argument('child_role')
def add_composite(realm, composite_role, child_role):
    """Add a child role to a composite role"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        composite = Role.find_realm_role(realm_obj.id, composite_role)
        if not composite:
            click.echo(f"Composite role '{composite_role}' not found.", err=True)
            return
        
        child = Role.find_realm_role(realm_obj.id, child_role)
        if not child:
            click.echo(f"Child role '{child_role}' not found.", err=True)
            return
        
        if not composite.composite:
            composite.composite = True
            composite.save()
        
        from apps.models.role import CompositeRole
        existing = CompositeRole.query.filter_by(
            parent_id=composite.id,
            child_id=child.id
        ).first()
        
        if existing:
            click.echo(f"Role '{child_role}' is already part of '{composite_role}'.")
            return
        
        composite_link = CompositeRole(parent_id=composite.id, child_id=child.id)
        db.session.add(composite_link)
        db.session.commit()
        
        click.echo(f"Added '{child_role}' to composite role '{composite_role}'.")


@role.command('remove-composite')
@click.argument('realm')
@click.argument('composite_role')
@click.argument('child_role')
def remove_composite(realm, composite_role, child_role):
    """Remove a child role from a composite role"""
    app = init_app()
    
    with app.app_context():
        from apps.models.role import CompositeRole
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        composite = Role.find_realm_role(realm_obj.id, composite_role)
        if not composite:
            click.echo(f"Composite role '{composite_role}' not found.", err=True)
            return
        
        child = Role.find_realm_role(realm_obj.id, child_role)
        if not child:
            click.echo(f"Child role '{child_role}' not found.", err=True)
            return
        
        link = CompositeRole.query.filter_by(
            parent_id=composite.id,
            child_id=child.id
        ).first()
        
        if not link:
            click.echo(f"Role '{child_role}' is not part of '{composite_role}'.")
            return
        
        db.session.delete(link)
        db.session.commit()
        
        click.echo(f"Removed '{child_role}' from composite role '{composite_role}'.")
