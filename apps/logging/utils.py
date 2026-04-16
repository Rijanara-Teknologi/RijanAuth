
import logging
from functools import wraps
from flask import current_app, request, g, has_request_context


def log_activity(action, source='SERVER', level=logging.INFO, **kwargs):
    """
    Log an activity to the console activity logger.
    Used for tracking user actions, page loads, button clicks, AJAX calls, etc.
    
    Args:
        action: Description of the action (e.g., "loaded /admin/users", "clicked Create User")
        source: Source of the log (BROWSER, SERVER, OIDC, etc.)
        level: Log level (INFO, WARNING, ERROR)
        **kwargs: Additional context (username, realm, resource, etc.)
    """
    try:
        activity_logger = current_app.extensions.get('activity_logger')
        if activity_logger is None:
            try:
                from .logger import get_activity_logger
                activity_logger = get_activity_logger()
            except Exception:
                activity_logger = None
        
        if activity_logger:
            context = kwargs.copy()
            context['source'] = source
            activity_logger.log(level, action, extra=context)
    except Exception:
        pass


def log_security_event(event_type, message, level=logging.WARNING, **kwargs):
    """
    Log a security related event (failed login, password change, etc.)
    """
    logger = current_app.logger
    
    context = kwargs.copy()
    context['event_type'] = event_type
    context['category'] = 'security'
    
    # Inject user info if present
    if has_request_context():
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                context['user_id'] = current_user.id
                context['username'] = current_user.username
        except:
            pass
            
    logger.log(level, message, extra=context)


def log_action(action, resource_type, source='SERVER'):
    """
    Decorator to log administrative actions.
    Usage:
        @log_action(action="update", resource_type="user")
        def update_user(id): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get user info before execution
            username = None
            if has_request_context():
                try:
                    from flask_login import current_user
                    if current_user and current_user.is_authenticated:
                        username = current_user.username
                except:
                    pass
            
            try:
                result = f(*args, **kwargs)
                
                # Log Success
                status = 200
                # Try to extract status from response tuple (json, status)
                if isinstance(result, tuple) and len(result) > 1:
                    status = result[1]
                
                if status < 400:
                    # Log to main logger
                    current_app.logger.info(
                        f"Action {action} on {resource_type} successful",
                        extra={
                            'action': action,
                            'resource_type': resource_type,
                            'status': 'success',
                            'route_args': kwargs
                        }
                    )
                    # Log to activity logger (compact format)
                    resource_id = kwargs.get(f'{resource_type}_id') or kwargs.get('realm_name') or kwargs.get('id', '')
                    log_activity(
                        f"performed {action} on {resource_type}" + (f" '{resource_id}'" if resource_id else ''),
                        source=source,
                        username=username
                    )
                
                return result
                
            except Exception as e:
                # Log Failure
                current_app.logger.error(
                    f"Action {action} on {resource_type} failed",
                    extra={
                        'action': action,
                        'resource_type': resource_type,
                        'status': 'failure',
                        'error': str(e)
                    }
                )
                log_activity(
                    f"failed {action} on {resource_type}: {str(e)}",
                    source=source,
                    level=logging.ERROR,
                    username=username
                )
                raise e
                
        return decorated_function
    return decorator
