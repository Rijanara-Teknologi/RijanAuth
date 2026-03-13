# -*- encoding: utf-8 -*-
"""
RijanAuth - Realm Service
Business logic for realm management
"""

from typing import Optional, List, Dict, Any
from apps import db
from apps.models.realm import Realm, RealmAttribute
from apps.models.role import Role
from apps.models.client import Client, ClientScope


class RealmService:
    """Service class for realm operations"""
    
    @staticmethod
    def create_realm(name: str, display_name: str = None, **kwargs) -> Realm:
        """
        Create a new realm.
        
        Args:
            name: Unique realm name (used in URLs)
            display_name: Human-readable display name
            **kwargs: Additional realm settings
        
        Returns:
            The created Realm instance
        """
        realm = Realm(
            name=name,
            display_name=display_name or name.title(),
            **kwargs
        )
        realm.save()
        
        # Create default roles
        RealmService._create_default_roles(realm)
        
        # Create default client scopes with protocol mappers
        from apps.seeders.client_scopes_seeder import seed_client_scopes
        seed_client_scopes(realm.id)
        
        # Create admin-cli client for API access
        RealmService._create_admin_cli_client(realm)
        
        return realm
    
    @staticmethod
    def _create_default_roles(realm: Realm) -> None:
        """Create default realm roles"""
        default_roles = [
            ('default-roles-' + realm.name, 'Default roles for realm'),
            ('offline_access', 'Grants access to offline tokens'),
            ('uma_authorization', 'Grants permission for User-Managed Access'),
        ]
        
        for role_name, description in default_roles:
            role = Role(
                realm_id=realm.id,
                name=role_name,
                description=description,
                composite=False,
                client_role=False
            )
            db.session.add(role)
        
        db.session.commit()
    
    @staticmethod
    def _create_default_client_scopes(realm: Realm) -> None:
        """Create default client scopes for OIDC"""
        scopes = [
            ('openid', 'OpenID Connect scope'),
            ('profile', 'User profile information'),
            ('email', 'User email address'),
            ('address', 'User address'),
            ('phone', 'User phone number'),
            ('roles', 'User roles'),
            ('web-origins', 'Web origins for CORS'),
            ('microprofile-jwt', 'MicroProfile JWT scope'),
            ('offline_access', 'Offline access scope'),
        ]
        
        for scope_name, description in scopes:
            scope = ClientScope(
                realm_id=realm.id,
                name=scope_name,
                description=description,
                protocol='openid-connect'
            )
            db.session.add(scope)
        
        db.session.commit()
    
    @staticmethod
    def _create_admin_cli_client(realm: Realm) -> None:
        """Create the admin-cli client for API access"""
        client = Client(
            realm_id=realm.id,
            client_id='admin-cli',
            name='Admin CLI',
            description='Admin CLI client for realm administration',
            public_client=True,
            standard_flow_enabled=False,
            implicit_flow_enabled=False,
            direct_access_grants_enabled=True,
            service_accounts_enabled=False,
            enabled=True
        )
        db.session.add(client)
        db.session.commit()
    
    @staticmethod
    def get_realm(realm_id: str) -> Optional[Realm]:
        """Get a realm by ID"""
        return Realm.find_by_id(realm_id)
    
    @staticmethod
    def get_realm_by_name(name: str) -> Optional[Realm]:
        """Get a realm by name"""
        return Realm.find_by_name(name)
    
    @staticmethod
    def get_all_realms() -> List[Realm]:
        """Get all realms"""
        return Realm.query.all()
    
    @staticmethod
    def update_realm(realm: Realm, **kwargs) -> Realm:
        """Update realm settings"""
        return realm.update(**kwargs)
    
    @staticmethod
    def delete_realm(realm: Realm) -> None:
        """Delete a realm and all its data"""
        realm.delete()
    
    @staticmethod
    def get_realm_attribute(realm: Realm, name: str) -> Optional[str]:
        """Get a realm attribute value"""
        attr = RealmAttribute.query.filter_by(realm_id=realm.id, name=name).first()
        return attr.value if attr else None
    
    @staticmethod
    def set_realm_attribute(realm: Realm, name: str, value: str) -> None:
        """Set a realm attribute"""
        attr = RealmAttribute.query.filter_by(realm_id=realm.id, name=name).first()
        if attr:
            attr.value = value
        else:
            attr = RealmAttribute(realm_id=realm.id, name=name, value=value)
            db.session.add(attr)
        db.session.commit()
    
    @staticmethod
    def ensure_master_realm() -> Realm:
        """
        Ensure the master realm exists.
        Creates it with default settings if it doesn't exist.
        """
        master = Realm.get_master_realm()
        if master is None:
            master = RealmService.create_realm(
                name='master',
                display_name='Master Realm',
                registration_allowed=False,
                reset_password_allowed=True,
                verify_email=False,
                login_with_email_allowed=True,
                brute_force_protected=True
            )
        return master
    
    @staticmethod
    def get_realm_statistics(realm: Realm) -> Dict[str, Any]:
        """Get statistics for a realm"""
        from apps.models.user import User
        from apps.models.client import Client
        from apps.models.group import Group
        from apps.models.session import UserSession
        
        return {
            'users': User.query.filter_by(realm_id=realm.id).count(),
            'clients': Client.query.filter_by(realm_id=realm.id).count(),
            'groups': Group.query.filter_by(realm_id=realm.id).count(),
            'activeSessions': UserSession.query.filter_by(realm_id=realm.id, state='ACTIVE').count(),
        }
