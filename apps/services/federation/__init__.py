# -*- encoding: utf-8 -*-
"""
RijanAuth - User Federation Services
Provides external identity source integration (LDAP, MySQL, PostgreSQL)
"""

from apps.services.federation.base import BaseFederationProvider, FederationError
from apps.services.federation.federation_service import FederationService
from apps.services.federation.sync_service import SyncService
from apps.services.federation.role_sync_service import RoleSyncService, RoleFormatDetector

__all__ = [
    'BaseFederationProvider',
    'FederationError',
    'FederationService',
    'SyncService',
    'RoleSyncService',
    'RoleFormatDetector',
]
