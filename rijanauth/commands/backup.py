# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Backup Commands
Manage backups
"""

import click
import json
from tabulate import tabulate
from datetime import datetime

from run import create_app
from apps import db
from apps.models.backup import BackupConfig, BackupRecord
from apps.services.backup_service import BackupService


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


@click.group()
def backup():
    """Manage backups"""
    pass


@backup.command('list')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--limit', '-l', type=int, default=20, help='Maximum results')
def list_backups(output_json, limit):
    """List backup records"""
    app = init_app()
    
    with app.app_context():
        records = BackupRecord.query.order_by(BackupRecord.created_at.desc()).limit(limit).all()
        
        if output_json:
            data = [{
                'id': r.id,
                'filename': r.filename,
                'storage_provider': r.storage_provider,
                'status': r.status,
                'size_bytes': r.size_bytes,
                'created_at': r.created_at.isoformat() if r.created_at else None,
                'backed_up_at': r.backed_up_at.isoformat() if r.backed_up_at else None,
            } for r in records]
            click.echo(json.dumps(data, indent=2))
        else:
            if not records:
                click.echo("No backup records found.")
                return
            
            click.echo(f"\nBackup Records (showing {len(records)}):\n")
            
            table = []
            for r in records:
                size_mb = f"{r.size_bytes / (1024*1024):.2f} MB" if r.size_bytes else '-'
                table.append([
                    r.filename,
                    r.storage_provider,
                    r.status,
                    size_mb,
                    r.created_at.strftime('%Y-%m-%d %H:%M') if r.created_at else '-',
                ])
            
            click.echo(tabulate(table, headers=['Filename', 'Storage', 'Status', 'Size', 'Created'], tablefmt='grid'))


@backup.command('create')
@click.option('--password', '-p', help='Password for encrypted backup')
@click.option('--local', 'storage', flag_value='local_server', default=True, help='Save to local server')
@click.option('--download', 'storage', flag_value='download', help='Download backup file')
def create_backup(password, storage):
    """Create a manual backup"""
    app = init_app()
    
    with app.app_context():
        click.echo("Creating backup...")
        
        try:
            if storage == 'local_server':
                record = BackupService.save_local_backup(password=password)
                click.echo(f"\nBackup created: {record.filename}")
                click.echo(f"Status: {record.status}")
                if record.size_bytes:
                    click.echo(f"Size: {record.size_bytes / (1024*1024):.2f} MB")
            else:
                zip_data, filename, size = BackupService.build_download_backup(password=password)
                click.echo(f"\nBackup ready for download: {filename}")
                click.echo(f"Size: {size / (1024*1024):.2f} MB")
                click.echo("\nRedirect output to file to save:")
                click.echo(f"  rijanauth backup create --download > backup.zip")
                
        except Exception as e:
            click.echo(f"Error creating backup: {str(e)}", err=True)


@backup.command('restore')
@click.argument('record_id')
@click.option('--password', '-p', help='Backup password (if encrypted)')
@click.confirmation_option(prompt='This will overwrite current data. Continue?')
def restore_backup(record_id, password):
    """Restore from a backup record"""
    app = init_app()
    
    with app.app_context():
        record = BackupRecord.find_by_id(record_id)
        if not record:
            click.echo(f"Backup record '{record_id}' not found.", err=True)
            return
        
        if record.status != 'success':
            click.echo(f"Cannot restore from backup with status '{record.status}'.", err=True)
            return
        
        click.echo(f"Restoring from: {record.filename}")
        
        try:
            stats = BackupService.restore_from_record(record_id, password)
            
            click.echo("\nRestore completed:")
            click.echo(f"  Tables restored: {stats.get('tables_restored', 0)}")
            click.echo(f"  Rows restored: {stats.get('rows_restored', 0)}")
            
            if stats.get('errors'):
                click.echo(f"\nErrors ({len(stats['errors'])}):")
                for error in stats['errors'][:10]:
                    click.echo(f"  - {error}")
                    
        except Exception as e:
            click.echo(f"Error restoring backup: {str(e)}", err=True)


@backup.command('config')
@click.option('--show', is_flag=True, help='Show current backup configuration')
@click.option('--interval', type=click.Choice(['daily', 'weekly', 'monthly']), help='Set auto-backup interval')
@click.option('--enable/--disable', 'enabled', default=None, help='Enable or disable auto-backup')
def config_backup(show, interval, enabled):
    """Configure automatic backups"""
    app = init_app()
    
    with app.app_context():
        config = BackupConfig.get_config()
        
        if show or (interval is None and enabled is None):
            if config:
                click.echo("\nBackup Configuration:")
                config_table = [
                    ['Enabled', 'Yes' if config.is_active else 'No'],
                    ['Interval', config.auto_backup_interval or 'Not set'],
                    ['Last Backup', config.last_backup_at.strftime('%Y-%m-%d %H:%M') if config.last_backup_at else 'Never'],
                    ['Next Backup', config.next_backup_at.strftime('%Y-%m-%d %H:%M') if config.next_backup_at else 'N/A'],
                ]
                click.echo(tabulate(config_table, tablefmt='grid'))
            else:
                click.echo("Backup is not configured.")
            return
        
        if not config:
            config = BackupConfig()
            db.session.add(config)
        
        if interval is not None:
            config.auto_backup_interval = interval
        
        if enabled is not None:
            config.is_active = enabled
        
        db.session.commit()
        
        BackupService.apply_config(app)
        
        click.echo("Backup configuration updated.")


@backup.command('cleanup')
@click.option('--days', type=int, default=30, help='Delete backups older than N days')
@click.confirmation_option(prompt='Delete old backup files?')
def cleanup_backups(days):
    """Clean up old backup files"""
    app = init_app()
    
    with app.app_context():
        deleted = BackupService.cleanup_old_local_backups()
        click.echo(f"Deleted {deleted} old backup file(s).")
