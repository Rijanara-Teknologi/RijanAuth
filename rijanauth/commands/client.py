# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Client Commands
Manage clients
"""

import click
import json
from tabulate import tabulate

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.models.client import Client
from apps.services.client_service import ClientService


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


@click.group()
def client():
    """Manage clients"""
    pass


@client.command('list')
@click.argument('realm')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def list_clients(realm, output_json):
    """List clients in a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        clients = Client.query.filter_by(realm_id=realm_obj.id).all()
        
        if output_json:
            data = [{
                'id': c.id,
                'client_id': c.client_id,
                'name': c.name,
                'enabled': c.enabled,
                'public_client': c.public_client,
                'access_token_lifespan': c.access_token_lifespan,
            } for c in clients]
            click.echo(json.dumps(data, indent=2))
        else:
            if not clients:
                click.echo(f"No clients found in realm '{realm}'.")
                return
            
            table = []
            for c in clients:
                table.append([
                    c.client_id,
                    c.name or '-',
                    'Yes' if c.enabled else 'No',
                    'Public' if c.public_client else 'Confidential',
                    c.access_token_lifespan or 'Inherit',
                ])
            
            click.echo(f"\nClients in '{realm}':")
            click.echo(tabulate(table, headers=['Client ID', 'Name', 'Enabled', 'Type', 'Token Lifespan'], tablefmt='grid'))


@client.command()
@click.argument('realm')
@click.argument('client_id')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def get(realm, client_id, output_json):
    """Get client details"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        client = Client.find_by_client_id(realm_obj.id, client_id)
        if not client:
            click.echo(f"Client '{client_id}' not found in realm '{realm}'.", err=True)
            return
        
        if output_json:
            click.echo(json.dumps(client.to_dict(), indent=2, default=str))
        else:
            click.echo(f"\n{'=' * 60}")
            click.echo(f"Client: {client.client_id}")
            click.echo(f"{'=' * 60}")
            
            click.echo("\nBasic Settings:")
            basic_table = [
                ['ID', client.id],
                ['Client ID', client.client_id],
                ['Name', client.name or '-'],
                ['Description', client.description or '-'],
                ['Enabled', 'Yes' if client.enabled else 'No'],
                ['Public Client', 'Yes' if client.public_client else 'No'],
            ]
            click.echo(tabulate(basic_table, tablefmt='plain'))
            
            click.echo("\nOAuth Settings:")
            oauth_table = [
                ['Standard Flow (Auth Code)', 'Yes' if client.standard_flow_enabled else 'No'],
                ['Implicit Flow', 'Yes' if client.implicit_flow_enabled else 'No'],
                ['Direct Access Grants', 'Yes' if client.direct_access_grants_enabled else 'No'],
                ['Service Accounts', 'Yes' if client.service_accounts_enabled else 'No'],
            ]
            click.echo(tabulate(oauth_table, tablefmt='grid'))
            
            click.echo("\nToken Settings:")
            token_table = [
                ['Access Token Lifespan', client.access_token_lifespan or 'Inherits from realm'],
            ]
            click.echo(tabulate(token_table, tablefmt='grid'))
            
            click.echo("\nURLs:")
            urls_table = [
                ['Root URL', client.root_url or '-'],
                ['Admin URL', client.admin_url or '-'],
                ['Base URL', client.base_url or '-'],
            ]
            click.echo(tabulate(urls_table, tablefmt='grid'))
            
            if client.redirect_uris:
                click.echo("\nRedirect URIs:")
                for uri in client.redirect_uris:
                    click.echo(f"  - {uri}")
            
            if client.web_origins:
                click.echo("\nWeb Origins:")
                for origin in client.web_origins:
                    click.echo(f"  - {origin}")


@client.command()
@click.argument('realm')
@click.argument('client_id')
@click.option('--name', help='Client display name')
@click.option('--type', 'client_type', type=click.Choice(['confidential', 'public']), default='confidential', help='Client type')
@click.option('--standard-flow/--no-standard-flow', default=True, help='Enable standard flow')
@click.option('--implicit-flow/--no-implicit-flow', default=False, help='Enable implicit flow')
@click.option('--direct-grant/--no-direct-grant', default=False, help='Enable direct access grants')
@click.option('--service-account/--no-service-account', default=False, help='Enable service accounts')
@click.option('--root-url', help='Root URL')
@click.option('--redirect-uris', help='Comma-separated redirect URIs')
@click.option('--token-lifespan', type=int, help='Access token lifespan override')
def create(realm, client_id, name, client_type, standard_flow, implicit_flow, direct_grant, service_account, root_url, redirect_uris, token_lifespan):
    """Create a new client"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        existing = Client.find_by_client_id(realm_obj.id, client_id)
        if existing:
            click.echo(f"Client '{client_id}' already exists in realm '{realm}'.", err=True)
            return
        
        try:
            public_client = (client_type == 'public')
            
            redirect_uris_list = []
            if redirect_uris:
                redirect_uris_list = [u.strip() for u in redirect_uris.split(',')]
            
            client = ClientService.create_client(
                realm_id=realm_obj.id,
                client_id=client_id,
                name=name or client_id,
                public_client=public_client,
                enabled=True,
                root_url=root_url,
                redirect_uris=redirect_uris_list if redirect_uris_list else None,
                standard_flow_enabled=standard_flow,
                implicit_flow_enabled=implicit_flow,
                direct_access_grants_enabled=direct_grant,
                service_accounts_enabled=service_account,
            )
            
            if token_lifespan:
                client.access_token_lifespan = token_lifespan
                client.save()
            
            click.echo(f"Created client '{client_id}' in realm '{realm}'.")
            
        except Exception as e:
            click.echo(f"Error creating client: {str(e)}", err=True)


@client.command()
@click.argument('realm')
@click.argument('client_id')
@click.option('--name', help='Client display name')
@click.option('--root-url', help='Root URL')
@click.option('--admin-url', help='Admin URL')
@click.option('--redirect-uris', help='Comma-separated redirect URIs')
@click.option('--standard-flow/--no-standard-flow', default=None, help='Enable/disable standard flow')
@click.option('--implicit-flow/--no-implicit-flow', default=None, help='Enable/disable implicit flow')
@click.option('--enabled/--disabled', default=None, help='Enable/disable client')
@click.option('--token-lifespan', type=int, help='Access token lifespan override')
def update(realm, client_id, name, root_url, admin_url, redirect_uris, standard_flow, implicit_flow, enabled, token_lifespan):
    """Update client settings"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        client = Client.find_by_client_id(realm_obj.id, client_id)
        if not client:
            click.echo(f"Client '{client_id}' not found in realm '{realm}'.", err=True)
            return
        
        redirect_uris_list = None
        if redirect_uris is not None:
            redirect_uris_list = [u.strip() for u in redirect_uris.split(',')] if redirect_uris else []
        
        try:
            ClientService.update_client(
                client,
                name=name,
                root_url=root_url,
                admin_url=admin_url,
                redirect_uris=redirect_uris_list,
                standard_flow_enabled=standard_flow,
                implicit_flow_enabled=implicit_flow,
                public_client=client.public_client,
            )
            
            if enabled is not None:
                client.enabled = enabled
            
            if token_lifespan is not None:
                if token_lifespan > 0:
                    client.access_token_lifespan = token_lifespan
                else:
                    client.access_token_lifespan = None
            
            db.session.commit()
            click.echo(f"Updated client '{client_id}'.")
            
        except Exception as e:
            click.echo(f"Error updating client: {str(e)}", err=True)


@client.command()
@click.argument('realm')
@click.argument('client_id')
@click.confirmation_option(prompt='Are you sure you want to delete this client?')
def delete(realm, client_id):
    """Delete a client"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        client = Client.find_by_client_id(realm_obj.id, client_id)
        if not client:
            click.echo(f"Client '{client_id}' not found in realm '{realm}'.", err=True)
            return
        
        try:
            client.delete()
            db.session.commit()
            click.echo(f"Deleted client '{client_id}'.")
        except Exception as e:
            click.echo(f"Error deleting client: {str(e)}", err=True)


@client.command()
@click.argument('realm')
@click.argument('client_id')
def regenerate_secret(realm, client_id):
    """Regenerate client secret (confidential clients only)"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        client = Client.find_by_client_id(realm_obj.id, client_id)
        if not client:
            click.echo(f"Client '{client_id}' not found in realm '{realm}'.", err=True)
            return
        
        if client.public_client:
            click.echo("Cannot regenerate secret for public clients.", err=True)
            return
        
        try:
            new_secret = ClientService.regenerate_secret(client)
            click.echo(f"\nNew client secret for '{client_id}':")
            click.echo(f"  {new_secret}")
            click.echo("\n[WARNING] Store this secret securely - it cannot be retrieved again!")
        except Exception as e:
            click.echo(f"Error regenerating secret: {str(e)}", err=True)
