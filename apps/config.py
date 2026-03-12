# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os, random, string

class Config(object):

    basedir = os.path.abspath(os.path.dirname(__file__))

    # Assets Management
    ASSETS_ROOT = os.getenv('ASSETS_ROOT', '/static/assets')
    
    # Media upload directory for customization
    MEDIA_ROOT = os.path.join(basedir, 'static', 'media')  
    
    # Set up the App SECRET_KEY
    SECRET_KEY  = os.getenv('SECRET_KEY', None)
    if not SECRET_KEY:
        SECRET_KEY = ''.join(random.choice( string.ascii_lowercase  ) for i in range( 32 ))


    # Secure Session Defaults
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600

    # Logging Configuration
    LOGGING = {
        'level': os.getenv('LOG_LEVEL', 'INFO'),
        'path': os.getenv('LOG_PATH', 'storage/logs'),
        'max_files': 7,
        'max_size': 100 * 1024 * 1024,  # 100MB
        'format': '[%(asctime)s] %(environment)s.%(levelname)s: %(message)s %(context)s',
        'sensitive_fields': ['password', 'token', 'secret', 'key', 'ssn', 'credit_card', 'authorization'],
        'mask_char': '*',
        'mask_length': 4
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_RECORD_QUERIES = True

    # Default location is inside the app package folder, but can be
    # overridden with the DB_PATH environment variable so that the file
    # can be placed on a Docker volume (or any host-mounted directory)
    # and survive container rebuilds.
    _sqlite_path = os.getenv('DB_PATH', os.path.join(basedir, 'db.sqlite3'))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + _sqlite_path
    
class ProductionConfig(Config):
    DEBUG = False

    # Security
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600

class DebugConfig(Config):
    DEBUG = True
    # Fixed key for development to maintain sessions across restarts
    SECRET_KEY = 'Fixed_Debug_Secret_Key_For_RijanAuth_Dev'
    
    # Session configuration
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_DOMAIN = None
    SESSION_COOKIE_PATH = '/'
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_NAME = 'rijanauth_session'
    
    # Permanent session lifetime (31 days)
    from datetime import timedelta
    PERMANENT_SESSION_LIFETIME = timedelta(days=31)
    
    # Remember cookie settings
    REMEMBER_COOKIE_SECURE = False
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'

# Load all possible configurations
config_dict = {
    'Production': ProductionConfig,
    'Debug'     : DebugConfig
}
