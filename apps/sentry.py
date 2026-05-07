# -*- encoding: utf-8 -*-
"""
RijanAuth - Sentry Error Tracking Integration
Auto-activates when SENTRY_DSN is set in environment
"""

import logging
from flask import request, g, jsonify, current_app, Response
from werkzeug.exceptions import HTTPException

_sentry_initialized = False


def is_sentry_configured():
    """Check if Sentry is configured and active"""
    global _sentry_initialized
    return _sentry_initialized


def configure_sentry(app):
    """
    Configure Sentry error tracking if SENTRY_DSN is set in environment.
    This function is called automatically by create_app() if SENTRY_DSN exists.
    
    The function does nothing if SENTRY_DSN is not set, ensuring no errors
    in environments without Sentry configured.
    """
    global _sentry_initialized
    
    dsn = app.config.get('SENTRY_DSN', '')
    
    if not dsn:
        app.logger.info("Sentry not configured (SENTRY_DSN not set)")
        return False
    
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlAlchemyIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
        
        environment = app.config.get('ENVIRONMENT', 'production')
        release = f"rijanauth@{app.config.get('RIJANAUTH_VERSION', '0.0.0')}"
        
        sentry_sdk.init(
            dsn=dsn,
            integrations=[
                FlaskIntegration(
                    transaction_style='url',
                    inherit_exc_info=True,
                ),
                SqlAlchemyIntegration(),
                LoggingIntegration(
                    level=logging.WARNING,
                    event_level=logging.ERROR,
                ),
            ],
            release=release,
            environment=environment,
            sample_rate=float(app.config.get('SENTRY_SAMPLE_RATE', 1.0)),
            traces_sample_rate=float(app.config.get('SENTRY_TRACES_SAMPLE_RATE', 0.1)),
            attach_stacktrace=True,
            send_default_pii=False,
            before_send=before_send,
            before_send_transaction=before_send_transaction,
        )
        
        _sentry_initialized = True
        app.logger.info(f"Sentry initialized: environment={environment}, release={release}")
        return True
        
    except ImportError:
        app.logger.warning("Sentry SDK not installed. Install with: pip install sentry-sdk[flask]")
        return False
    except Exception as e:
        app.logger.error(f"Failed to initialize Sentry: {e}")
        return False


def before_send(event, hint):
    """
    Clean sensitive data before sending to Sentry.
    Removes passwords, tokens, secrets from error reports.
    """
    if event.get('request'):
        headers = event['request'].get('headers', {})
        sensitive_headers = ['authorization', 'cookie', 'x-api-key']
        for header in sensitive_headers:
            if header in headers:
                headers[header] = '[REDACTED]'
    
    if event.get('contexts'):
        for key in ['user', 'response']:
            if key in event['contexts']:
                user_data = event['contexts'][key]
                sensitive_fields = ['password', 'token', 'secret', 'api_key', 'credit_card']
                for field in sensitive_fields:
                    if field in user_data:
                        user_data[field] = '[REDACTED]'
    
    if event.get('extra'):
        sensitive_fields = ['password', 'secret', 'token', 'key', 'credential', 'ssn', 'credit_card', 'smtp_password', 'client_secret']
        for field in sensitive_fields:
            if field in event['extra']:
                event['extra'][field] = '[REDACTED]'
    
    return event


def before_send_transaction(event, hint):
    """
    Clean sensitive data from transaction events (performance monitoring).
    """
    if event.get('request'):
        headers = event['request'].get('headers', {})
        sensitive_headers = ['authorization', 'cookie', 'x-api-key']
        for header in sensitive_headers:
            if header in headers:
                headers[header] = '[REDACTED]'
    
    return event


def set_user_context(user):
    """
    Set user context for Sentry error tracking.
    Call this after successful authentication.
    """
    if not _sentry_initialized:
        return
    
    try:
        import sentry_sdk
        sentry_sdk.set_user({
            'id': user.id if hasattr(user, 'id') else None,
            'username': user.username if hasattr(user, 'username') else None,
            'email': user.email if hasattr(user, 'email') else None,
        })
    except Exception:
        pass


def clear_user_context():
    """
    Clear user context when user logs out.
    """
    if not _sentry_initialized:
        return
    
    try:
        import sentry_sdk
        sentry_sdk.set_user(None)
    except Exception:
        pass


def add_realm_context(realm):
    """
    Add realm context to Sentry events for multi-tenant apps.
    """
    if not _sentry_initialized:
        return
    
    try:
        import sentry_sdk
        sentry_sdk.set_context('realm', {
            'id': realm.id if hasattr(realm, 'id') else None,
            'name': realm.name if hasattr(realm, 'name') else None,
            'display_name': realm.display_name if hasattr(realm, 'display_name') else None,
        })
    except Exception:
        pass


def capture_exception_with_context(exception, realm=None, user=None, extra=None):
    """
    Capture an exception with additional context.
    """
    if not _sentry_initialized:
        return None
    
    try:
        import sentry_sdk
        
        with sentry_sdk.push_scope() as scope:
            if user:
                scope.set_user({
                    'id': user.id if hasattr(user, 'id') else None,
                    'username': user.username if hasattr(user, 'username') else None,
                    'email': user.email if hasattr(user, 'email') else None,
                })
            
            if realm:
                scope.set_context('realm', {
                    'id': realm.id if hasattr(realm, 'id') else None,
                    'name': realm.name if hasattr(realm, 'name') else None,
                })
            
            if extra:
                for key, value in extra.items():
                    scope.set_extra(key, value)
            
            return sentry_sdk.capture_exception(exception)
    except Exception:
        return None


def _render_internal_server_error():
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Internal server error'}), 500
    return Response('Internal Server Error', status=500, mimetype='text/plain')


def register_error_handlers(app):
    """
    Register Flask error handlers that report to Sentry and keep web output generic.
    """

    @app.errorhandler(404)
    def not_found_error(error):
        capture_404_error(error)
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        return jsonify({'error': 'Access forbidden'}), 403

    @app.errorhandler(401)
    def unauthorized_error(error):
        return jsonify({'error': 'Authentication required'}), 401

    @app.errorhandler(Exception)
    def handle_exception(error):
        if isinstance(error, HTTPException):
            if error.code in (401, 403, 404):
                return error

        current_app.logger.exception('Unhandled exception during request')
        capture_exception(error)
        return _render_internal_server_error()


def capture_404_error(error):
    """
    Capture 404 errors to Sentry (optional - can be noisy)
    """
    if not _sentry_initialized:
        return
    
    try:
        import sentry_sdk
        sentry_sdk.capture_message(
            f"404 Not Found: {request.path}",
            level='info',
            extras={
                'path': request.path,
                'method': request.method,
                'remote_addr': request.remote_addr,
            }
        )
    except Exception:
        pass


def capture_exception(exception):
    """
    Capture an exception to Sentry with request context.
    """
    if not _sentry_initialized:
        return
    
    try:
        import sentry_sdk
        sentry_sdk.capture_exception(exception)
    except Exception:
        pass


def capture_message(message, level='info', extras=None):
    """
    Capture a message to Sentry.
    """
    if not _sentry_initialized:
        return
    
    try:
        import sentry_sdk
        extras = extras or {}
        sentry_sdk.capture_message(message, level=level, extras=extras)
    except Exception:
        pass
