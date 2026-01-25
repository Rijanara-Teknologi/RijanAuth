# -*- encoding: utf-8 -*-
"""
RijanAuth - Admin Blueprint
Administration console routes for realm management
"""

from flask import Blueprint

admin_bp = Blueprint(
    'admin',
    __name__,
    url_prefix='/admin',
    template_folder='../../templates/admin'
)

from apps.blueprints.admin import routes
from apps.blueprints.admin import api
