# -*- encoding: utf-8 -*-
"""
RijanAuth - OIDC Blueprint
OpenID Connect Protocol Endpoints
"""

from flask import Blueprint

oidc_bp = Blueprint(
    'oidc',
    __name__,
    url_prefix='/auth/realms'
)

from apps.blueprints.oidc import routes
