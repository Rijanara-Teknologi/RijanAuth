
import logging
import os
import sys
from .handlers import DailyRotatingFileHandler, ConsoleActivityHandler
from .formatters import LaravelFormatter, ActivityFormatter
from .filters import SensitiveDataFilter, ContextFilter


_activity_logger = None


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
    app.logger.propagate = False
    
    # Remove default handlers to avoid duplication if running in production
    if not app.debug:
        del app.logger.handlers[:]
    
    app.logger.addHandler(handler)
    
    # Mirror logs to console in runtime so errors and info appear immediately
    if config.get('enable_console', True):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(context_filter)
        console_handler.addFilter(sensitive_filter)
        app.logger.addHandler(console_handler)
    
    # Setup console activity logging if enabled
    if config.get('enable_activity_console', True):
        setup_activity_logger(app)
    
    # Also log startup message
    app.logger.info(f"Logging initialized. Level: {log_level_name}")

    return handler


def setup_activity_logger(app):
    """
    Setup separate activity logger that outputs to console/stdout.
    This logger captures user actions, page loads, button clicks, etc.
    """
    global _activity_logger
    
    config = app.config.get('LOGGING', {})
    activity_level_name = config.get('activity_log_level', 'INFO')
    activity_level = getattr(logging, activity_level_name.upper(), logging.INFO)
    
    _activity_logger = logging.getLogger('activity')
    _activity_logger.setLevel(activity_level)
    _activity_logger.propagate = False
    
    console_handler = ConsoleActivityHandler(level=activity_level)
    console_handler.setFormatter(ActivityFormatter())
    
    _activity_logger.addHandler(console_handler)
    
    return _activity_logger


def get_activity_logger():
    """
    Get the activity logger instance.
    """
    global _activity_logger
    if _activity_logger is None:
        _activity_logger = logging.getLogger('activity')
    return _activity_logger
