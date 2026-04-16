
import logging
import json
import os
from datetime import datetime


class ActivityFormatter(logging.Formatter):
    """
    Compact single-line formatter for activity logs.
    Format: [HH:MM:SS] [SOURCE] message
    """
    
    def __init__(self, source='LOG'):
        super().__init__()
        self.source = source
    
    def format(self, record):
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        source = getattr(record, 'source', self.source)
        
        parts = [f"[{timestamp}]", f"[{source}]"]
        
        if hasattr(record, 'username') and record.username:
            parts.append(f"{record.username}")
        
        message = record.getMessage()
        parts.append(message)
        
        return ' '.join(parts)


class LaravelFormatter(logging.Formatter):
    """
    Formatter that mimics Laravel's log format:
    [YYYY-MM-DD HH:mm:ss] Environment.LEVEL: Message {context}
    """
    
    def __init__(self, environment='production', fmt=None, datefmt=None):
        super().__init__(fmt, datefmt)
        self.environment = environment

    def format(self, record):
        # Format timestamp
        record.asctime = self.formatTime(record, self.datefmt or '%Y-%m-%d %H:%M:%S')
        
        # Ensure context exists
        if not hasattr(record, 'context'):
            record.context = {}
            
        # Serialize context to JSON
        context_json = ''
        if record.context:
            try:
                context_json = ' ' + json.dumps(record.context, default=str)
            except Exception:
                context_json = ' {"error": "Failed to serialize context"}'
                
        # Main message
        message = record.getMessage()
        
        # Add exception info if present
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        
        if record.exc_text:
             # If context has exception object, it might be redundant, but standard.
             # Laravel puts exception stack trace properly formatted.
             # We'll append it to context or message.
             # Implementation choice: Append to message for readability
             message += '\n' + record.exc_text

        # Construct final string
        # [2026-01-25 14:30:45] production.INFO: User authentication successful {"user_id":"abc"}
        return f"[{record.asctime}] {self.environment}.{record.levelname}: {message}{context_json}"
