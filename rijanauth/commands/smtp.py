# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - SMTP Commands
Test and configure SMTP settings
"""

import click
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from run import create_app
from apps.models.realm import Realm


def init_app():
    """Initialize Flask app context"""
    app = create_app('default')
    return app


@click.group()
def smtp():
    """Test SMTP configuration"""
    pass


@smtp.command('test')
@click.argument('realm')
@click.option('--to', '-t', required=True, help='Recipient email address')
@click.option('--subject', '-s', default='RijanAuth SMTP Test', help='Email subject')
@click.option('--body', '-b', default='This is a test email from RijanAuth CLI.', help='Email body')
def test_smtp(realm, to, subject, body):
    """Test SMTP configuration for a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        if not realm_obj.smtp_server:
            click.echo("SMTP server is not configured for this realm.", err=True)
            click.echo("\nConfigure SMTP settings first:")
            click.echo(f"  rijanauth realm set {realm} smtp_server smtp.example.com")
            click.echo(f"  rijanauth realm set {realm} smtp_port 587")
            click.echo(f"  rijanauth realm set {realm} smtp_from noreply@example.com")
            return
        
        click.echo(f"Testing SMTP for realm '{realm}'...")
        click.echo(f"  Server: {realm_obj.smtp_server}:{realm_obj.smtp_port or 25}")
        click.echo(f"  From: {realm_obj.smtp_from}")
        click.echo(f"  To: {to}")
        
        try:
            port = int(realm_obj.smtp_port) if realm_obj.smtp_port else 25
        except (ValueError, TypeError):
            port = 25
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = realm_obj.smtp_from
        msg['To'] = to
        
        if realm_obj.smtp_from_display_name:
            msg['From'] = f"{realm_obj.smtp_from_display_name} <{realm_obj.smtp_from}>"
        
        if realm_obj.smtp_reply_to:
            if realm_obj.smtp_reply_to_display_name:
                msg['Reply-To'] = f"{realm_obj.smtp_reply_to_display_name} <{realm_obj.smtp_reply_to}>"
            else:
                msg['Reply-To'] = realm_obj.smtp_reply_to
        
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            context = ssl.create_default_context()
            
            click.echo("\nConnecting to SMTP server...")
            
            if realm_obj.smtp_ssl:
                server = smtplib.SMTP_SSL(realm_obj.smtp_server, port, context=context, timeout=30)
            else:
                server = smtplib.SMTP(realm_obj.smtp_server, port, timeout=30)
                if realm_obj.smtp_starttls:
                    click.echo("Starting TLS...")
                    server.starttls(context=context)
            
            if realm_obj.smtp_auth and realm_obj.smtp_user and realm_obj.smtp_password:
                click.echo("Authenticating...")
                server.login(realm_obj.smtp_user, realm_obj.smtp_password)
            
            click.echo("Sending email...")
            sender = realm_obj.smtp_from or 'rijanauth@localhost'
            server.sendmail(sender, [to], msg.as_string())
            server.quit()
            
            click.echo("\n[SUCCESS] Test email sent successfully!")
            
        except smtplib.SMTPAuthenticationError as e:
            click.echo(f"\n[ERROR] Authentication failed: {str(e)}", err=True)
            click.echo("\nCheck your SMTP credentials:")
            click.echo(f"  rijanauth realm set {realm} smtp_user <username>")
            click.echo(f"  rijanauth realm set {realm} smtp_password <password>")
            
        except smtplib.SMTPRecipientsRefused as e:
            click.echo(f"\n[ERROR] Recipient refused: {str(e)}", err=True)
            
        except smtplib.SMTPSenderRefused as e:
            click.echo(f"\n[ERROR] Sender refused: {str(e)}", err=True)
            
        except smtplib.SMTPException as e:
            click.echo(f"\n[ERROR] SMTP error: {str(e)}", err=True)
            
        except Exception as e:
            click.echo(f"\n[ERROR] {type(e).__name__}: {str(e)}", err=True)


@smtp.command('check')
@click.argument('realm')
def check_smtp(realm):
    """Check SMTP configuration for a realm"""
    app = init_app()
    
    with app.app_context():
        realm_obj = Realm.find_by_name(realm)
        if not realm_obj:
            click.echo(f"Realm '{realm}' not found.", err=True)
            return
        
        click.echo(f"\nSMTP Configuration for '{realm}':\n")
        
        if not realm_obj.smtp_server:
            click.echo("[NOT CONFIGURED]")
            click.echo("\nRequired settings:")
            click.echo("  smtp_server      - SMTP server hostname")
            click.echo("  smtp_port        - SMTP port (usually 587 for TLS, 465 for SSL)")
            click.echo("  smtp_from        - From email address")
            return
        
        from tabulate import tabulate
        
        rows = [
            ['smtp_server', realm_obj.smtp_server],
            ['smtp_port', realm_obj.smtp_port or '25 (default)'],
            ['smtp_from', realm_obj.smtp_from],
            ['smtp_from_display_name', realm_obj.smtp_from_display_name or '-'],
            ['smtp_reply_to', realm_obj.smtp_reply_to or '-'],
            ['smtp_ssl', 'Yes' if realm_obj.smtp_ssl else 'No'],
            ['smtp_starttls', 'Yes' if realm_obj.smtp_starttls else 'No'],
            ['smtp_auth', 'Yes' if realm_obj.smtp_auth else 'No'],
            ['smtp_user', realm_obj.smtp_user or '-'],
        ]
        
        click.echo(tabulate(rows, tablefmt='grid'))
        
        click.echo("\nTest with:")
        click.echo(f"  rijanauth smtp test {realm} -t your@email.com")
