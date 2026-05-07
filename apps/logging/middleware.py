
import time
import uuid
from flask import request, g, current_app

class LoggingMiddleware:
    """
    Middleware to log requests and inject Request ID.
    """
    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self.before_request)
        app.after_request(self.after_request)

    def before_request(self):
        # Generate Request ID
        g.request_id = str(uuid.uuid4())
        g.start_time = time.time()
        
        from flask import session
        
        request_context = {
            'session_id': session.get('_id', 'NEW_OR_NONE'),
            'session_keys': list(session.keys()),
            'remote_addr': request.remote_addr,
            'user_agent': request.user_agent.string,
            'url': request.url,
            'full_path': request.full_path,
            'endpoint': request.endpoint,
            'query_string': request.query_string.decode('utf-8', errors='ignore') if request.query_string else '',
        }
        
        current_app.logger.info(
            f"Request started: {request.method} {request.url}",
            extra={'context': request_context}
        )

    def after_request(self, response):
        if hasattr(g, 'start_time'):
            duration = int((time.time() - g.start_time) * 1000)
            
            # Log request completion
            status_code = response.status_code
            log_level = 'info'
            
            if status_code >= 500:
                log_level = 'error'
            elif status_code >= 400:
                log_level = 'warning'
                
            log_message = f"Request completed: {request.method} {request.url} {status_code}"
            
            extra = {
                'duration_ms': duration,
                'status': status_code,
                'method': request.method,
                'path': request.path,
                'url': request.url,
                'endpoint': request.endpoint,
                'query_string': request.query_string.decode('utf-8', errors='ignore') if request.query_string else '',
            }
            
            getattr(current_app.logger, log_level)(log_message, extra={'context': extra})
            
            # Add Request ID header to response
            response.headers['X-Request-ID'] = g.request_id
            
        return response
