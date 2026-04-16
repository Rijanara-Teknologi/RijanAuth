# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Federation Commands
Manage user federation providers
"""

import click
import json
from tabulate import tabulate
from datetime import datetime

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.models.federation import UserFederationProvider


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


def get_federation_service():
    """Lazy import to avoid ldap3 dependency issues"""
    from apps.services.federation import FederationService
    return FederationService


def get_sync_service():
    """Lazy import to avoid ldap3 dependency issues"""
    from apps.services.federation.sync_service import SyncService
    return SyncService


@click.group()
def federation():
    """Manage user federation providers"""
    pass


@federation.command('list')
@click.argument('realm')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def list_providers(realm, output_json):
    """List federation providers in a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        providers = UserFederationProvider.find_by_realm(realm_obj.id)
        
        if output_json:
            data = [{
                'id': p.id,
                'name': p.name,
                'display_name': p.display_name,
                'provider_type': p.provider_type,
                'enabled': p.enabled,
                'priority': p.priority,
                'import_enabled': p.import_enabled,
                'last_sync': p.last_sync.isoformat() if p.last_sync else None,
            } for p in providers]
            click.echo(json.dumps(data, indent=2))
        else:
            if not providers:
                click.echo(f"No federation providers found in realm '{realm}'.")
                return
            
            click.echo(f"\nFederation Providers in '{realm}':\n")
            
            table = []
            for p in providers:
                last_sync = p.last_sync.strftime('%Y-%m-%d %H:%M') if p.last_sync else 'Never'
                table.append([
                    p.name,
                    p.provider_type,
                    'Yes' if p.enabled else 'No',
                    p.priority,
                    'Yes' if p.import_enabled else 'No',
                    last_sync,
                ])
            
            click.echo(tabulate(table, headers=['Name', 'Type', 'Enabled', 'Priority', 'Import', 'Last Sync'], tablefmt='grid'))


@federation.command('test')
@click.argument('realm')
@click.argument('provider_name')
def test_connection(realm, provider_name):
    """Test connection to a federation provider"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        provider = UserFederationProvider.query.filter_by(
            realm_id=realm_obj.id,
            name=provider_name
        ).first()
        
        if not provider:
            click.echo(f"Provider '{provider_name}' not found.", err=True)
            return
        
        click.echo(f"Testing connection to '{provider_name}'...")
        
        FederationService = get_federation_service()
        result = FederationService.test_provider_connection(provider.id)
        
        if result['success']:
            click.echo(f"\n[SUCCESS] {result['message']}")
        else:
            click.echo(f"\n[FAILED] {result['message']}", err=True)


@federation.command('sync')
@click.argument('realm')
@click.argument('provider_name')
@click.option('--type', 'sync_type', type=click.Choice(['full', 'changed']), default='full', help='Sync type')
def sync_users(realm, provider_name, sync_type):
    """Synchronize users from a federation provider"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        provider = UserFederationProvider.query.filter_by(
            realm_id=realm_obj.id,
            name=provider_name
        ).first()
        
        if not provider:
            click.echo(f"Provider '{provider_name}' not found.", err=True)
            return
        
        click.echo(f"Starting {sync_type} sync for '{provider_name}'...")
        click.echo("This may take a while for large datasets.")
        
        SyncService = get_sync_service()
        
        try:
            if sync_type == 'changed':
                result = SyncService.sync_changed_users(provider.id)
            else:
                result = SyncService.sync_all_users(provider.id)
            
            if result['success']:
                stats = result.get('stats', {})
                click.echo(f"\n[SUCCESS] Sync completed!")
                click.echo(f"  Users processed: {stats.get('users_processed', 0)}")
                click.echo(f"  Users created: {stats.get('users_created', 0)}")
                click.echo(f"  Users updated: {stats.get('users_updated', 0)}")
                click.echo(f"  Users skipped: {stats.get('users_skipped', 0)}")
                click.echo(f"  Errors: {stats.get('errors', 0)}")
            else:
                click.echo(f"\n[FAILED] {result.get('error', 'Unknown error')}", err=True)
                
        except Exception as e:
            click.echo(f"\n[ERROR] {str(e)}", err=True)


@federation.command('status')
@click.argument('realm')
@click.argument('provider_name')
def sync_status(realm, provider_name):
    """Get sync status for a federation provider"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        provider = UserFederationProvider.query.filter_by(
            realm_id=realm_obj.id,
            name=provider_name
        ).first()
        
        if not provider:
            click.echo(f"Provider '{provider_name}' not found.", err=True)
            return
        
        click.echo(f"\nSync Status for '{provider_name}':\n")
        
        SyncService = get_sync_service()
        status = SyncService.get_sync_status(provider.id)
        
        rows = [
            ['Provider', provider.name],
            ['Type', provider.provider_type],
            ['Enabled', 'Yes' if provider.enabled else 'No'],
            ['Last Sync', provider.last_sync.strftime('%Y-%m-%d %H:%M:%S') if provider.last_sync else 'Never'],
            ['Last Sync Status', status.get('status', 'N/A')],
            ['Last Sync Error', status.get('error', '-')],
            ['Full Sync Period', f"{provider.full_sync_period}s" if provider.full_sync_period > 0 else 'Disabled'],
            ['Changed Sync Period', f"{provider.changed_sync_period}s" if provider.changed_sync_period > 0 else 'Disabled'],
        ]
        
        click.echo(tabulate(rows, tablefmt='grid'))


@federation.command('providers')
def list_types():
    """List available federation provider types"""
    app = init_app()
    
    with app.app_context():
        FederationService = get_federation_service()
        available = FederationService.get_available_providers()
        
        click.echo("\nAvailable Federation Provider Types:\n")
        
        for ptype in available:
            click.echo(f"  - {ptype}")
        
        click.echo("\nNote: Some providers may require additional dependencies.")
