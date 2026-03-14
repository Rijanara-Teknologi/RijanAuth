# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os

bind = '0.0.0.0:' + os.environ.get('PORT', '5085')
workers = int(os.environ.get('WORKERS', '1'))
worker_class = 'gthread'
threads = int(os.environ.get('THREADS', '4'))
# Allow up to 10 minutes for large synchronous CSV imports.
timeout = int(os.environ.get('TIMEOUT', '600'))
keepalive = int(os.environ.get('KEEPALIVE', '5'))
accesslog = '-'
loglevel = 'debug'
capture_output = True
enable_stdio_inheritance = True
