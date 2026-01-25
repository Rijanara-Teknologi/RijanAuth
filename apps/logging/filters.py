
import logging
from flask import has_request_context, request, g, current_app

class SensitiveDataFilter(logging.Filter):
    """
    Masks sensitive data in log records context.
    """
    def __init__(self, sensitive_fields=None, mask_char='*', mask_length=4):
        super().__init__()
        self.sensitive_fields = sensitive_fields or ['password', 'token', 'secret', 'key']
        self.mask_char = mask_char
        self.mask_length = mask_length

    def filter(self, record):
        if hasattr(record, 'context') and isinstance(record.context, dict):
            self._mask_dict(record.context)
        return True

    def _mask_dict(self, data):
        for key, value in data.items():
            if isinstance(value, dict):
                self._mask_dict(value)
            elif isinstance(value, str):
                if any(field in key.lower() for field in self.sensitive_fields):
                    data[key] = self.mask_char * self.mask_length
                    
class ContextFilter(logging.Filter):
    """
    Injects request and user context into log records.
    """
    def filter(self, record):
        if not hasattr(record, 'context'):
            record.context = {}
            
        if has_request_context():
            # Inject Request ID
            if hasattr(g, 'request_id'):
                record.context['request_id'] = g.request_id
            
            # Inject User if authenticated
            try:
                from flask_login import current_user
                if current_user and current_user.is_authenticated:
                    record.context['user_id'] = current_user.id
                    record.context['username'] = current_user.username
            except Exception:
                pass
                
            # Inject basic request info
            record.context['ip'] = request.remote_addr
            record.context['method'] = request.method
            record.context['path'] = request.path
            
        return True
