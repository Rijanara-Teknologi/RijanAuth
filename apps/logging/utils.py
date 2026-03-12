
import logging
from functools import wraps
from flask import current_app, request, g, has_request_context

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

def log_action(action, resource_type):
    """
    Decorator to log administrative actions.
    Usage:
        @log_action(action="update", resource_type="user")
        def update_user(id): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Log action start? Or only success?
            # Typically success/failure after execution.
            
            try:
                result = f(*args, **kwargs)
                
                # Log Success
                status = 200
                # Try to extract status from response tuple (json, status)
                if isinstance(result, tuple) and len(result) > 1:
                    status = result[1]
                
                if status < 400:
                    current_app.logger.info(
                        f"Action {action} on {resource_type} successful",
                        extra={
                            'action': action,
                            'resource_type': resource_type,
                            'status': 'success',
                            'route_args': kwargs
                        }
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
                raise e
                
        return decorated_function
    return decorator
