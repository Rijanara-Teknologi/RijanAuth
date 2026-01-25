# -*- encoding: utf-8 -*-
"""
RijanAuth - Client Scopes Seeder
Creates default OIDC client scopes with their protocol mappers
"""

import logging
from apps import db
from apps.models.realm import Realm
from apps.models.client import ClientScope, ProtocolMapper

logger = logging.getLogger(__name__)


def seed_client_scopes(realm_id: str = None):
    """
    Seed default OIDC client scopes for a realm.
    If realm_id is None, seeds for all realms.
    """
    if realm_id:
        realms = [Realm.query.get(realm_id)]
    else:
        realms = Realm.query.all()
    
    for realm in realms:
        if realm:
            _seed_realm_client_scopes(realm)
    
    logger.info("Client scopes seeding completed")


def _seed_realm_client_scopes(realm: Realm):
    """Seed client scopes for a specific realm"""
    logger.info(f"Seeding client scopes for realm: {realm.name}")
    
    # Define default scopes
    default_scopes = [
        {
            'name': 'openid',
            'description': 'OpenID Connect scope',
            'protocol': 'openid-connect',
            'mappers': []  # Basic scope, no additional mappers needed
        },
        {
            'name': 'profile',
            'description': 'OpenID Connect built-in scope: profile',
            'protocol': 'openid-connect',
            'mappers': [
                {
                    'name': 'username',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'username',
                        'claim.name': 'preferred_username',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'full name',
                    'protocol_mapper': 'oidc-full-name-mapper',
                    'config': {
                        'claim.name': 'name',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'given name',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'first_name',
                        'claim.name': 'given_name',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'family name',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'last_name',
                        'claim.name': 'family_name',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'locale',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'locale',
                        'claim.name': 'locale',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        },
        {
            'name': 'email',
            'description': 'OpenID Connect built-in scope: email',
            'protocol': 'openid-connect',
            'mappers': [
                {
                    'name': 'email',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'email',
                        'claim.name': 'email',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'email verified',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'email_verified',
                        'claim.name': 'email_verified',
                        'jsonType.label': 'boolean',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        },
        {
            'name': 'roles',
            'description': 'OpenID Connect scope for role mappings',
            'protocol': 'openid-connect',
            'mappers': [
                {
                    'name': 'realm roles',
                    'protocol_mapper': 'oidc-usermodel-realm-role-mapper',
                    'config': {
                        'claim.name': 'realm_access.roles',
                        'multivalued': 'true',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'false',
                    }
                },
                {
                    'name': 'client roles',
                    'protocol_mapper': 'oidc-usermodel-client-role-mapper',
                    'config': {
                        'claim.name': 'resource_access',
                        'multivalued': 'true',
                        'access.token.claim': 'true',
                        'id.token.claim': 'false',
                        'userinfo.token.claim': 'false',
                    }
                },
                {
                    'name': 'audience resolve',
                    'protocol_mapper': 'oidc-audience-mapper',
                    'config': {
                        'included.client.audience': '',
                        'add.to.access.token': 'true',
                        'add.to.id.token': 'false',
                    }
                },
            ]
        },
        {
            'name': 'groups',
            'description': 'Group membership scope',
            'protocol': 'openid-connect',
            'mappers': [
                {
                    'name': 'groups',
                    'protocol_mapper': 'oidc-group-membership-mapper',
                    'config': {
                        'claim.name': 'groups',
                        'full.path': 'true',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        },
        {
            'name': 'address',
            'description': 'OpenID Connect built-in scope: address',
            'protocol': 'openid-connect',
            'mappers': [
                {
                    'name': 'address',
                    'protocol_mapper': 'oidc-address-mapper',
                    'config': {
                        'claim.name': 'address',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        },
        {
            'name': 'phone',
            'description': 'OpenID Connect built-in scope: phone',
            'protocol': 'openid-connect',
            'mappers': [
                {
                    'name': 'phone number',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'phone_number',
                        'claim.name': 'phone_number',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'phone number verified',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'phone_number_verified',
                        'claim.name': 'phone_number_verified',
                        'jsonType.label': 'boolean',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        },
        {
            'name': 'offline_access',
            'description': 'Enables offline access tokens',
            'protocol': 'openid-connect',
            'mappers': []
        },
        {
            'name': 'microprofile-jwt',
            'description': 'Microprofile JWT scope',
            'protocol': 'openid-connect',
            'mappers': [
                {
                    'name': 'upn',
                    'protocol_mapper': 'oidc-usermodel-attribute-mapper',
                    'config': {
                        'user.attribute': 'username',
                        'claim.name': 'upn',
                        'jsonType.label': 'String',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
                {
                    'name': 'groups',
                    'protocol_mapper': 'oidc-usermodel-realm-role-mapper',
                    'config': {
                        'claim.name': 'groups',
                        'multivalued': 'true',
                        'access.token.claim': 'true',
                        'id.token.claim': 'true',
                        'userinfo.token.claim': 'true',
                    }
                },
            ]
        },
    ]
    
    for scope_data in default_scopes:
        _create_scope_if_not_exists(realm, scope_data)


def _create_scope_if_not_exists(realm: Realm, scope_data: dict):
    """Create a client scope if it doesn't exist"""
    existing = ClientScope.query.filter_by(
        realm_id=realm.id,
        name=scope_data['name']
    ).first()
    
    if existing:
        logger.debug(f"Client scope '{scope_data['name']}' already exists for realm {realm.name}")
        return existing
    
    # Create the scope
    scope = ClientScope(
        realm_id=realm.id,
        name=scope_data['name'],
        description=scope_data.get('description', ''),
        protocol=scope_data.get('protocol', 'openid-connect'),
        attributes=scope_data.get('attributes', {})
    )
    db.session.add(scope)
    db.session.flush()  # Get the ID
    
    # Create mappers for this scope
    for idx, mapper_data in enumerate(scope_data.get('mappers', [])):
        mapper = ProtocolMapper(
            name=mapper_data['name'],
            protocol='openid-connect',
            protocol_mapper=mapper_data['protocol_mapper'],
            client_scope_id=scope.id,
            config=mapper_data.get('config', {}),
            priority=idx * 10
        )
        db.session.add(mapper)
    
    db.session.commit()
    logger.info(f"Created client scope '{scope_data['name']}' with {len(scope_data.get('mappers', []))} mappers")
    
    return scope


def assign_default_scopes_to_client(client, scope_names=None):
    """
    Assign default client scopes to a client.
    
    Args:
        client: The client to assign scopes to
        scope_names: List of scope names to assign as default. If None, assigns standard scopes.
    """
    from apps.models.client import ClientScopeMapping
    
    if scope_names is None:
        scope_names = ['openid', 'profile', 'email']
    
    # Get realm scopes
    scopes = ClientScope.query.filter(
        ClientScope.realm_id == client.realm_id,
        ClientScope.name.in_(scope_names)
    ).all()
    
    default_scope_ids = []
    
    for scope in scopes:
        # Check if mapping exists
        existing = ClientScopeMapping.query.filter_by(
            client_id=client.id,
            scope_id=scope.id
        ).first()
        
        if not existing:
            mapping = ClientScopeMapping(
                client_id=client.id,
                scope_id=scope.id,
                default_scope=True
            )
            db.session.add(mapping)
        
        default_scope_ids.append(scope.id)
    
    # Update client's default_client_scopes list
    client.default_client_scopes = default_scope_ids
    db.session.commit()
    
    logger.info(f"Assigned {len(scope_names)} default scopes to client {client.client_id}")
