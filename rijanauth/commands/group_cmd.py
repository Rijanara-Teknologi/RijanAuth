# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Group Commands
Manage groups
"""

import click
import json
from tabulate import tabulate

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.models.group import Group


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


@click.group()
def group():
    """Manage groups"""
    pass


@group.command('list')
@click.argument('realm')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--tree', is_flag=True, help='Show as tree structure')
def list_groups(realm, output_json, tree):
    """List groups in a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        groups = Group.query.filter_by(realm_id=realm_obj.id).all()
        
        if output_json:
            data = [g.to_dict(include_subgroups=True) for g in Group.get_top_level_groups(realm_obj.id)]
            click.echo(json.dumps(data, indent=2, default=str))
        elif tree:
            click.echo(f"\nGroups in '{realm}':\n")
            _print_group_tree(Group.get_top_level_groups(realm_obj.id), "")
        else:
            if not groups:
                click.echo(f"No groups found in realm '{realm}'.")
                return
            
            click.echo(f"\nGroups in '{realm}':")
            
            table = []
            for g in groups:
                members = g.members.count() if hasattr(g, 'members') else 0
                table.append([
                    g.name,
                    g.path,
                    members,
                ])
            
            click.echo(tabulate(table, headers=['Name', 'Path', 'Members'], tablefmt='grid'))


def _print_group_tree(groups, prefix):
    """Print groups in tree format"""
    for i, g in enumerate(groups):
        is_last = i == len(groups) - 1
        connector = "`--" if is_last else "|--"
        
        members = g.members.count() if hasattr(g, 'members') else 0
        click.echo(f"{prefix}{connector} {g.name} ({members} members)")
        
        subprefix = prefix + ("   " if is_last else "|  ")
        for child in g.children:
            _print_group_tree([child], subprefix)


@group.command()
@click.argument('realm')
@click.argument('name')
@click.option('--path', '-p', help='Group path (default: /name)')
def create(realm, name, path):
    """Create a new group"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        group_path = path or f'/{name}'
        
        existing = Group.find_by_path(realm_obj.id, group_path)
        if existing:
            click.echo(f"Group with path '{group_path}' already exists.", err=True)
            return
        
        try:
            group = Group(
                realm_id=realm_obj.id,
                name=name,
                path=group_path,
                parent_id=None
            )
            group.save()
            
            click.echo(f"Created group '{name}' in realm '{realm}'.")
            
        except Exception as e:
            click.echo(f"Error creating group: {str(e)}", err=True)


@group.command()
@click.argument('realm')
@click.argument('name')
@click.confirmation_option(prompt='Are you sure you want to delete this group?')
def delete(realm, name):
    """Delete a group"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        group = Group.query.filter_by(realm_id=realm_obj.id, name=name).first()
        if not group:
            click.echo(f"Group '{name}' not found in realm '{realm}'.", err=True)
            return
        
        try:
            group.delete()
            db.session.commit()
            click.echo(f"Deleted group '{name}'.")
        except Exception as e:
            click.echo(f"Error deleting group: {str(e)}", err=True)


@group.command('add-member')
@click.argument('realm')
@click.argument('group_name')
@click.argument('username')
def add_member(realm, group_name, username):
    """Add a user to a group"""
    app = init_app()
    
    with app.app_context():
        from apps.models.user import User
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        group = Group.query.filter_by(realm_id=realm_obj.id, name=group_name).first()
        if not group:
            click.echo(f"Group '{group_name}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found.", err=True)
            return
        
        try:
            from apps.services.user_service import UserService
            UserService.join_group(user, group)
            
            click.echo(f"Added '{username}' to group '{group_name}'.")
        except Exception as e:
            click.echo(f"Error adding member: {str(e)}", err=True)


@group.command('remove-member')
@click.argument('realm')
@click.argument('group_name')
@click.argument('username')
def remove_member(realm, group_name, username):
    """Remove a user from a group"""
    app = init_app()
    
    with app.app_context():
        from apps.models.user import User
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        group = Group.query.filter_by(realm_id=realm_obj.id, name=group_name).first()
        if not group:
            click.echo(f"Group '{group_name}' not found.", err=True)
            return
        
        user = User.find_by_username(realm_obj.id, username)
        if not user:
            click.echo(f"User '{username}' not found.", err=True)
            return
        
        try:
            from apps.services.user_service import UserService
            UserService.leave_group(user, group)
            
            click.echo(f"Removed '{username}' from group '{group_name}'.")
        except Exception as e:
            click.echo(f"Error removing member: {str(e)}", err=True)


@group.command('members')
@click.argument('realm')
@click.argument('group_name')
def list_members(realm, group_name):
    """List members of a group"""
    app = init_app()
    
    with app.app_context():
        from apps.models.user import User, GroupMembership
        
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        group = Group.query.filter_by(realm_id=realm_obj.id, name=group_name).first()
        if not group:
            click.echo(f"Group '{group_name}' not found.", err=True)
            return
        
        memberships = GroupMembership.query.filter_by(group_id=group.id).all()
        
        click.echo(f"\nMembers of '{group_name}' ({len(memberships)}):\n")
        
        table = []
        for m in memberships:
            user = User.find_by_id(m.user_id)
            if user:
                table.append([
                    user.username,
                    user.email or '-',
                    user.first_name or '-',
                    user.last_name or '-',
                ])
        
        if table:
            click.echo(tabulate(table, headers=['Username', 'Email', 'First Name', 'Last Name'], tablefmt='grid'))
        else:
            click.echo("No members found.")
