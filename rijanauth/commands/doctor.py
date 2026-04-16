# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Doctor Command
Diagnostic and repair tool for RijanAuth
"""

import click
import json
import os
import sys
from datetime import datetime, timedelta
from tabulate import tabulate

from run import create_app
from apps import db
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.client import Client
from apps.models.session import UserSession
from apps.models.event import Event
from apps.models.backup import BackupConfig, BackupRecord
from apps.models.federation import UserFederationProvider


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


def format_seconds(seconds):
    """Format seconds to human readable string"""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds}s ({seconds/60:.1f} min)"
    elif seconds < 86400:
        return f"{seconds}s ({seconds/3600:.1f} hours)"
    else:
        return f"{seconds}s ({seconds/86400:.1f} days)"


def mask_sensitive(value, show_chars=4):
    """Mask sensitive information"""
    if value is None:
        return "N/A"
    if isinstance(value, str) and len(value) > show_chars:
        return value[:show_chars] + "***"
    return value


@click.group()
def doctor():
    """System diagnostic and repair tool"""
    pass


@doctor.command()
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output with all details')
@click.option('--realm', default=None, help='Specific realm to analyze')
def analyze(output_json, verbose, realm):
    """Analyze RijanAuth system for issues and misconfigurations"""
    
    app = init_app()
    
    with app.app_context():
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'database': analyze_database(),
            'realms': analyze_realms(realm),
            'clients': analyze_clients(realm),
            'users': analyze_users(realm),
            'sessions': analyze_sessions(realm),
            'security': analyze_security(realm),
            'backup': analyze_backup(),
            'federation': analyze_federation(realm),
        }
        
        results['issues'] = collect_issues(results)
        
        if output_json:
            click.echo(json.dumps(results, indent=2, default=str))
        else:
            print_report(results, verbose)


def analyze_database():
    """Analyze database health"""
    result = {
        'status': 'ok',
        'tables': 0,
        'size_bytes': 0,
        'integrity': 'unknown',
        'issues': [],
    }
    
    try:
        tables = db.session.execute(db.text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()
        result['tables'] = len(tables)
        
        integrity = db.session.execute(db.text("PRAGMA integrity_check")).fetchone()
        result['integrity'] = integrity[0] if integrity else 'unknown'
        
        db_path = db.session.execute(db.text("PRAGMA database_list")).fetchall()
        for path in db_path:
            if path[1] == 'main':
                actual_path = path[2]
                if os.path.exists(actual_path):
                    result['size_bytes'] = os.path.getsize(actual_path)
                break
            
    except Exception as e:
        result['status'] = 'error'
        result['issues'].append(str(e))
    
    return result


def analyze_realms(filter_name=None):
    """Analyze realm configurations"""
    result = {
        'total': 0,
        'realms': [],
        'issues': [],
    }
    
    query = Realm.query
    if filter_name:
        query = query.filter_by(name=filter_name)
    
    realms = query.all()
    result['total'] = len(realms)
    
    for r in realms:
        realm_data = {
            'name': r.name,
            'enabled': r.enabled,
            'token_settings': {
                'access_token_lifespan': r.access_token_lifespan,
                'sso_session_idle_timeout': r.sso_session_idle_timeout,
                'sso_session_max_lifespan': r.sso_session_max_lifespan,
                'offline_session_idle_timeout': r.offline_session_idle_timeout,
                'access_code_lifespan': r.access_code_lifespan,
            },
            'login_settings': {
                'registration_allowed': r.registration_allowed,
                'verify_email': r.verify_email,
                'login_with_email_allowed': r.login_with_email_allowed,
                'reset_password_allowed': r.reset_password_allowed,
            },
            'security_settings': {
                'brute_force_protected': r.brute_force_protected,
                'max_login_failures': r.max_login_failures,
            },
            'smtp': {
                'server': mask_sensitive(r.smtp_server),
                'port': r.smtp_port,
                'configured': bool(r.smtp_server),
            },
            'issues': [],
        }
        
        if r.access_token_lifespan < 3600:
            realm_data['issues'].append({
                'type': 'critical',
                'message': f"access_token_lifespan is {r.access_token_lifespan}s (recommended: 86400s / 24h)"
            })
        
        if r.access_token_lifespan == 300:
            realm_data['issues'].append({
                'type': 'critical',
                'message': "access_token_lifespan is 300s (5 min) - THIS IS THE DEFAULT AND MAY CAUSE LOGOUT ISSUES"
            })
        
        if not r.brute_force_protected:
            realm_data['issues'].append({
                'type': 'warning',
                'message': "Brute force protection is disabled"
            })
        
        if not r.verify_email and r.registration_allowed:
            realm_data['issues'].append({
                'type': 'info',
                'message': "Email verification is disabled - users may register with invalid emails"
            })
        
        result['realms'].append(realm_data)
        result['issues'].extend(realm_data['issues'])
    
    return result


def analyze_clients(filter_realm=None):
    """Analyze client configurations"""
    result = {
        'total': 0,
        'clients': [],
        'issues': [],
    }
    
    query = Client.query
    if filter_realm:
        realm = Realm.find_by_name(filter_realm)
        if realm:
            query = query.filter_by(realm_id=realm.id)
    
    clients = query.all()
    result['total'] = len(clients)
    
    for c in clients:
        client_data = {
            'client_id': c.client_id,
            'realm_id': c.realm_id,
            'enabled': c.enabled,
            'public_client': c.public_client,
            'access_token_lifespan': c.access_token_lifespan,
            'has_override': c.access_token_lifespan is not None,
            'standard_flow': c.standard_flow_enabled,
            'issues': [],
        }
        
        if c.enabled and not c.standard_flow_enabled:
            client_data['issues'].append({
                'type': 'info',
                'message': "Standard flow (Authorization Code) is not enabled"
            })
        
        if c.enabled and c.public_client and not c.client_authenticator_type:
            client_data['issues'].append({
                'type': 'warning',
                'message': "Public client without explicit authenticator type"
            })
        
        result['clients'].append(client_data)
    
    return result


def analyze_users(filter_realm=None):
    """Analyze user statistics"""
    result = {
        'total': 0,
        'enabled': 0,
        'disabled': 0,
        'with_password': 0,
        'federated': 0,
        'recent_registrations': 0,
        'recent_logins': 0,
        'issues': [],
    }
    
    query = User.query
    if filter_realm:
        realm = Realm.find_by_name(filter_realm)
        if realm:
            query = query.filter_by(realm_id=realm.id)
    
    users = query.all()
    result['total'] = len(users)
    result['enabled'] = sum(1 for u in users if u.enabled)
    result['disabled'] = sum(1 for u in users if not u.enabled)
    result['federated'] = sum(1 for u in users if getattr(u, 'federation_link', None))
    
    week_ago = datetime.utcnow() - timedelta(days=7)
    result['recent_registrations'] = sum(1 for u in users if u.created_at and u.created_at > week_ago)
    
    sessions = UserSession.query.filter_by(state='ACTIVE').all()
    if filter_realm:
        realm = Realm.find_by_name(filter_realm)
        if realm:
            sessions = [s for s in sessions if str(s.realm_id) == str(realm.id)]
    
    result['recent_logins'] = len(sessions)
    
    return result


def analyze_sessions(filter_realm=None):
    """Analyze session statistics"""
    result = {
        'active': 0,
        'stale': 0,
        'issues': [],
    }
    
    query = UserSession.query.filter_by(state='ACTIVE')
    if filter_realm:
        realm = Realm.find_by_name(filter_realm)
        if realm:
            query = query.filter_by(realm_id=realm.id)
    
    sessions = query.all()
    result['active'] = len(sessions)
    
    day_ago = datetime.utcnow() - timedelta(days=1)
    result['stale'] = sum(1 for s in sessions if s.started and s.started < day_ago)
    
    if result['stale'] > 10:
        result['issues'].append({
            'type': 'warning',
            'message': f"{result['stale']} sessions are older than 24 hours"
        })
    
    return result


def analyze_security(filter_realm=None):
    """Analyze security settings"""
    result = {
        'issues': [],
        'recommendations': [],
    }
    
    realms_query = Realm.query
    if filter_realm:
        realm = Realm.find_by_name(filter_realm)
        if realm:
            realms_query = realms_query.filter_by(id=realm.id)
    
    for realm in realms_query.all():
        if not realm.brute_force_protected:
            result['issues'].append({
                'realm': realm.name,
                'type': 'warning',
                'message': "Brute force protection is disabled"
            })
            result['recommendations'].append({
                'realm': realm.name,
                'action': 'Enable brute force protection',
                'command': f'rijanauth realm set {realm.name} brute_force_protected true'
            })
        
        if realm.access_token_lifespan < 3600:
            result['issues'].append({
                'realm': realm.name,
                'type': 'critical',
                'message': f"Token lifespan is {realm.access_token_lifespan}s (recommended: 86400s)"
            })
            result['recommendations'].append({
                'realm': realm.name,
                'action': 'Set token lifespan to 24 hours',
                'command': f'rijanauth realm set {realm.name} access_token_lifespan 86400'
            })
        
        if realm.access_token_lifespan == 300:
            result['issues'].append({
                'realm': realm.name,
                'type': 'critical',
                'message': "Token lifespan is 300s (5 min) - DEFAULT VALUE NOT CHANGED"
            })
    
    return result


def analyze_backup():
    """Analyze backup configuration"""
    result = {
        'configured': False,
        'auto_backup': False,
        'schedule': None,
        'last_backup': None,
        'local_backups_count': 0,
        'issues': [],
    }
    
    config = BackupConfig.get_config()
    if config:
        result['configured'] = True
        result['auto_backup'] = config.auto_backup_enabled if hasattr(config, 'auto_backup_enabled') else False
        result['schedule'] = config.auto_backup_interval if hasattr(config, 'auto_backup_interval') else None
        result['last_backup'] = config.last_backup_at.isoformat() if config.last_backup_at else None
    
    local_backups = BackupRecord.query.filter_by(
        storage_provider='local_server',
        status='success'
    ).count()
    result['local_backups_count'] = local_backups
    
    if not result['configured']:
        result['issues'].append({
            'type': 'warning',
            'message': "Backup is not configured"
        })
    elif not result['auto_backup']:
        result['issues'].append({
            'type': 'info',
            'message': "Auto-backup is disabled"
        })
    
    return result


def analyze_federation(filter_realm=None):
    """Analyze federation providers"""
    result = {
        'total': 0,
        'providers': [],
        'issues': [],
    }
    
    query = UserFederationProvider.query
    if filter_realm:
        realm = Realm.find_by_name(filter_realm)
        if realm:
            query = query.filter_by(realm_id=realm.id)
    
    providers = query.all()
    result['total'] = len(providers)
    
    for p in providers:
        provider_data = {
            'name': p.name,
            'type': p.provider_type,
            'enabled': p.enabled,
            'priority': p.priority,
            'import_enabled': p.import_enabled,
            'last_sync': p.last_sync.isoformat() if p.last_sync else None,
            'issues': [],
        }
        
        if not p.enabled:
            provider_data['issues'].append({
                'type': 'info',
                'message': "Provider is disabled"
            })
        
        if p.last_sync:
            sync_age = datetime.utcnow() - p.last_sync
            if sync_age > timedelta(days=1):
                provider_data['issues'].append({
                    'type': 'warning',
                    'message': f"Last sync was {sync_age.days} days ago"
                })
        
        result['providers'].append(provider_data)
    
    return result


def collect_issues(results):
    """Collect all issues from analysis results"""
    issues = {
        'critical': [],
        'warning': [],
        'info': [],
    }
    
    for realm_data in results.get('realms', {}).get('realms', []):
        for issue in realm_data.get('issues', []):
            issues[issue['type']].append({
                'resource': 'realm',
                'name': realm_data['name'],
                'message': issue['message']
            })
    
    for issue in results.get('security', {}).get('issues', []):
        issues[issue['type']].append({
            'resource': 'security',
            'name': issue.get('realm', 'all'),
            'message': issue['message']
        })
    
    for issue in results.get('backup', {}).get('issues', []):
        issues[issue['type']].append({
            'resource': 'backup',
            'name': 'system',
            'message': issue['message']
        })
    
    return issues


def print_report(results, verbose=False):
    """Print human-readable report"""
    
    click.echo("\n" + "=" * 80)
    click.echo("RIJANAUTH DOCTOR - System Diagnostic Report")
    click.echo("Generated: " + results['timestamp'])
    click.echo("=" * 80)
    
    click.echo("\n[1/8] DATABASE CHECKS")
    db_result = results.get('database', {})
    click.echo(f"    Status: {db_result.get('status', 'unknown').upper()}")
    click.echo(f"    Tables: {db_result.get('tables', 0)}")
    click.echo(f"    Integrity: {db_result.get('integrity', 'unknown')}")
    if db_result.get('size_bytes', 0) > 0:
        size_mb = db_result['size_bytes'] / (1024 * 1024)
        click.echo(f"    Size: {size_mb:.2f} MB")
    
    click.echo("\n[2/8] REALM CONFIGURATION")
    realms_result = results.get('realms', {})
    click.echo(f"    Total realms: {realms_result.get('total', 0)}")
    
    for realm_data in realms_result.get('realms', []):
        click.echo(f"\n    Realm: {realm_data['name']}")
        click.echo(f"    Status: {'ENABLED' if realm_data['enabled'] else 'DISABLED'}")
        
        click.echo("\n    Token Settings:")
        token_table = []
        token_settings = realm_data.get('token_settings', {})
        
        checks = [
            ('access_token_lifespan', 'Access Token', 86400),
            ('sso_session_idle_timeout', 'SSO Idle', 1800),
            ('sso_session_max_lifespan', 'SSO Max', 36000),
            ('offline_session_idle_timeout', 'Offline Idle', 2592000),
            ('access_code_lifespan', 'Access Code', 60),
        ]
        
        for key, label, expected in checks:
            value = token_settings.get(key)
            status = "OK" if value == expected else f"MISCONFIG (expected {expected})"
            status_icon = "OK" if value == expected else "FAIL"
            token_table.append([label, format_seconds(value), status_icon, status])
        
        click.echo(tabulate(token_table, headers=['Setting', 'Current', 'Status', 'Details'], tablefmt='grid'))
        
        if realm_data.get('issues'):
            click.echo("\n    Issues:")
            for issue in realm_data['issues']:
                icon = {"critical": "[X]", "warning": "[!]", "info": "[i]"}.get(issue['type'], "[-]")
                click.echo(f"    {icon} {issue['message']}")
    
    click.echo("\n[3/8] CLIENT CONFIGURATION")
    clients_result = results.get('clients', {})
    click.echo(f"    Total clients: {clients_result.get('total', 0)}")
    
    if clients_result.get('clients'):
        client_table = []
        for c in clients_result['clients'][:10]:
            lifespan = format_seconds(c.get('access_token_lifespan'))
            override = "Yes" if c.get('has_override') else "No"
            client_table.append([c['client_id'], lifespan, override, "OK" if c['enabled'] else "DISABLED"])
        
        click.echo(tabulate(client_table, headers=['Client ID', 'Token Lifespan', 'Override', 'Status'], tablefmt='grid'))
    
    click.echo("\n[4/8] USER STATISTICS")
    users_result = results.get('users', {})
    user_table = [
        ['Total Users', users_result.get('total', 0)],
        ['Enabled', users_result.get('enabled', 0)],
        ['Disabled', users_result.get('disabled', 0)],
        ['Federated', users_result.get('federated', 0)],
        ['Registrations (7 days)', users_result.get('recent_registrations', 0)],
        ['Active Sessions', users_result.get('recent_logins', 0)],
    ]
    click.echo(tabulate(user_table, tablefmt='grid'))
    
    click.echo("\n[5/8] SECURITY CHECKS")
    security_result = results.get('security', {})
    if security_result.get('issues'):
        for issue in security_result['issues']:
            icon = {"critical": "[X]", "warning": "[!]"}.get(issue['type'], "[-]")
            click.echo(f"    {icon} [{issue.get('realm', 'all')}] {issue['message']}")
    else:
        click.echo("    No security issues found")
    
    click.echo("\n[6/8] SESSION ANALYSIS")
    sessions_result = results.get('sessions', {})
    sessions_table = [
        ['Active Sessions', sessions_result.get('active', 0)],
        ['Stale Sessions (>24h)', sessions_result.get('stale', 0)],
    ]
    click.echo(tabulate(sessions_table, tablefmt='grid'))
    
    click.echo("\n[7/8] BACKUP STATUS")
    backup_result = results.get('backup', {})
    backup_table = [
        ['Configured', 'Yes' if backup_result.get('configured') else 'No'],
        ['Auto-backup', 'Yes' if backup_result.get('auto_backup') else 'No'],
        ['Schedule', backup_result.get('schedule', 'N/A')],
        ['Last Backup', backup_result.get('last_backup', 'Never')],
        ['Local Backups', backup_result.get('local_backups_count', 0)],
    ]
    click.echo(tabulate(backup_table, tablefmt='grid'))
    
    click.echo("\n[8/8] FEDERATION PROVIDERS")
    fed_result = results.get('federation', {})
    click.echo(f"    Total providers: {fed_result.get('total', 0)}")
    
    if fed_result.get('providers'):
        fed_table = []
        for p in fed_result['providers']:
            fed_table.append([p['name'], p['type'], 'Enabled' if p['enabled'] else 'Disabled', p.get('last_sync', 'Never')])
        click.echo(tabulate(fed_table, headers=['Name', 'Type', 'Status', 'Last Sync'], tablefmt='grid'))
    
    click.echo("\n" + "=" * 80)
    click.echo("SUMMARY")
    click.echo("=" * 80)
    
    all_issues = results.get('issues', {})
    click.echo(f"  Critical Issues: {len(all_issues.get('critical', []))}")
    click.echo(f"  Warnings: {len(all_issues.get('warning', []))}")
    click.echo(f"  Info: {len(all_issues.get('info', []))}")
    
    if all_issues.get('critical'):
        click.echo("\n  CRITICAL ISSUES:")
        for issue in all_issues['critical']:
            click.echo(f"    - [{issue.get('resource')}] {issue['message']}")
    
    if verbose and security_result.get('recommendations'):
        click.echo("\n  RECOMMENDATIONS:")
        for rec in security_result['recommendations']:
            click.echo(f"    - [{rec['realm']}] {rec['action']}")
            click.echo(f"      Command: {rec['command']}")
    
    click.echo("\n" + "=" * 80)


@doctor.command()
@click.argument('issue', required=False)
@click.option('--dry-run', is_flag=True, help='Show what would be fixed without making changes')
def repair(issue, dry_run):
    """Repair common issues automatically
    
    Available issues to repair:
      access-token-lifespan  - Fix access_token_lifespan to 86400s (24h)
      brute-force           - Enable brute force protection
      all                   - Repair all issues
    """
    
    app = init_app()
    
    with app.app_context():
        if issue is None or issue == 'all':
            issues_to_fix = ['access-token-lifespan', 'brute-force']
        else:
            issues_to_fix = [issue]
        
        results = []
        
        for fix_issue in issues_to_fix:
            if fix_issue == 'access-token-lifespan':
                result = repair_token_lifespan(dry_run)
                results.append(result)
            elif fix_issue == 'brute-force':
                result = repair_brute_force(dry_run)
                results.append(result)
            else:
                click.echo(f"Unknown issue: {fix_issue}")
        
        print_repair_results(results, dry_run)


def repair_token_lifespan(dry_run=False):
    """Repair access_token_lifespan to 86400 for all realms"""
    realms = Realm.query.all()
    fixed = []
    already_ok = []
    errors = []
    
    for realm in realms:
        if realm.access_token_lifespan != 86400:
            if dry_run:
                fixed.append(f"{realm.name}: would change from {realm.access_token_lifespan}s to 86400s")
            else:
                old_value = realm.access_token_lifespan
                realm.access_token_lifespan = 86400
                try:
                    db.session.commit()
                    fixed.append(f"{realm.name}: changed from {old_value}s to 86400s")
                except Exception as e:
                    db.session.rollback()
                    errors.append(f"{realm.name}: {str(e)}")
        else:
            already_ok.append(f"{realm.name}: already at 86400s")
    
    return {
        'issue': 'access-token-lifespan',
        'action': 'Set access_token_lifespan to 86400s (24 hours)',
        'fixed': fixed,
        'already_ok': already_ok,
        'errors': errors,
    }


def repair_brute_force(dry_run=False):
    """Enable brute force protection for all realms"""
    realms = Realm.query.all()
    fixed = []
    already_ok = []
    errors = []
    
    for realm in realms:
        if not realm.brute_force_protected:
            if dry_run:
                fixed.append(f"{realm.name}: would enable brute_force_protected")
            else:
                realm.brute_force_protected = True
                realm.max_login_failures = 30
                realm.wait_increment_seconds = 60
                realm.max_failure_wait_seconds = 900
                realm.minimum_quick_login_wait_seconds = 30
                realm.quick_login_check_milli_seconds = 1000
                realm.max_delta_time_seconds = 3600
                realm.max_temporary_lockouts = 4
                try:
                    db.session.commit()
                    fixed.append(f"{realm.name}: enabled with default settings")
                except Exception as e:
                    db.session.rollback()
                    errors.append(f"{realm.name}: {str(e)}")
        else:
            already_ok.append(f"{realm.name}: already enabled")
    
    return {
        'issue': 'brute-force',
        'action': 'Enable brute force protection',
        'fixed': fixed,
        'already_ok': already_ok,
        'errors': errors,
    }


def print_repair_results(results, dry_run):
    """Print repair results"""
    mode = "[DRY RUN] " if dry_run else ""
    
    click.echo("\n" + "=" * 80)
    click.echo(f"{mode}RIJANAUTH DOCTOR REPAIR")
    click.echo("=" * 80)
    
    for result in results:
        click.echo(f"\n{result['action']}:")
        
        if result['fixed']:
            click.echo(f"  Fixed ({len(result['fixed'])}):")
            for item in result['fixed']:
                click.echo(f"    + {item}")
        
        if result['already_ok']:
            click.echo(f"  Already OK ({len(result['already_ok'])}):")
            for item in result['already_ok']:
                click.echo(f"    = {item}")
        
        if result['errors']:
            click.echo(f"  Errors ({len(result['errors'])}):")
            for item in result['errors']:
                click.echo(f"    ! {item}")
    
    total_fixed = sum(len(r['fixed']) for r in results)
    click.echo(f"\n{mode}Total fixed: {total_fixed}")
    click.echo("=" * 80)


@doctor.command()
def list_issues():
    """List all available repairable issues"""
    issues = [
        {
            'name': 'access-token-lifespan',
            'description': 'Fix access_token_lifespan to 86400s (24 hours) for all realms',
            'severity': 'critical',
        },
        {
            'name': 'brute-force',
            'description': 'Enable brute force protection with recommended settings',
            'severity': 'warning',
        },
    ]
    
    click.echo("\nAvailable repairable issues:\n")
    
    for issue in issues:
        icon = {"critical": "[X]", "warning": "[!]"}.get(issue['severity'], "[-]")
        click.echo(f"{icon} {issue['name']}")
        click.echo(f"    {issue['description']}")
        click.echo(f"    Usage: rijanauth doctor repair {issue['name']}")
        click.echo()
