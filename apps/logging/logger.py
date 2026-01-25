
import logging
import os
import sys
from .handlers import DailyRotatingFileHandler
from .formatters import LaravelFormatter
from .filters import SensitiveDataFilter, ContextFilter

def setup_logging(app):
    """
    Initialize application logging with Daily Rotation and Laravel-style formatting.
    """
    config = app.config.get('LOGGING', {})
    
    log_level_name = config.get('level', 'INFO')
    log_level = getattr(logging, log_level_name.upper(), logging.INFO)
    
    log_path = config.get('path', 'storage/logs')
    log_prefix = 'rija-auth'
    
    # Ensure log directory exists
    try:
        os.makedirs(log_path, exist_ok=True)
    except OSError:
        # Fallback to stderr provided by WSGI usually, or just print
        print(f"Warning: Could not create log directory {log_path}. Logging to console only.", file=sys.stderr)
        return

    # Create Handler
    handler = DailyRotatingFileHandler(
        log_directory=log_path,
        filename_prefix=log_prefix,
        retention_days=config.get('max_files', 7)
    )
    handler.setLevel(log_level)
    
    # Create Formatter
    environment = 'production' # Default
    if app.debug:
        environment = 'local'
    elif app.testing:
        environment = 'testing'
        
    formatter = LaravelFormatter(environment=environment)
    handler.setFormatter(formatter)
    
    # Add Filters
    sensitive_filter = SensitiveDataFilter(
        sensitive_fields=config.get('sensitive_fields'),
        mask_char=config.get('mask_char', '*'),
        mask_length=config.get('mask_length', 4)
    )
    context_filter = ContextFilter()
    
    handler.addFilter(context_filter) # Add context first
    handler.addFilter(sensitive_filter) # Then mask it
    
    # Configure App Logger
    app.logger.setLevel(log_level)
    
    # Remove default handlers to avoid duplication if running in production
    # In Debug mode, Flask adds a StreamHandler. We might want to keep it or replace it.
    if not app.debug:
        del app.logger.handlers[:]
    
    app.logger.addHandler(handler)
    
    # Also log startup message
    app.logger.info(f"Logging initialized. Level: {log_level_name}")

    return handler
