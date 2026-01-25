# -*- encoding: utf-8 -*-
"""
RijanAuth - Client Service
Business logic for OAuth/OIDC client management
"""

from typing import Optional, List
from apps import db
from apps.models.client import Client, ClientScope, ClientScopeMapping, ProtocolMapper
from apps.utils.crypto import generate_secret


class ClientService:
    """Service class for client operations"""
    
    @staticmethod
    def create_client(realm_id: str, client_id: str, name: str = None,
                      protocol: str = 'openid-connect', public_client: bool = False,
                      **kwargs) -> Client:
        """
        Create a new OAuth/OIDC client.
        
        Args:
            realm_id: The realm ID
            client_id: Client identifier (OAuth client_id)
            name: Display name
            protocol: 'openid-connect' or 'saml'
            public_client: True for public clients (no secret)
            **kwargs: Additional client settings
        
        Returns:
            The created Client instance
        """
        client = Client(
            realm_id=realm_id,
            client_id=client_id,
            name=name or client_id,
            protocol=protocol,
            public_client=public_client,
            **kwargs
        )
        
        # Generate secret for confidential clients
        if not public_client:
            client.secret = generate_secret()
        
        client.save()
        
        # Assign default client scopes
        ClientService._assign_default_scopes(client)
        
        return client
    
    @staticmethod
    def _assign_default_scopes(client: Client) -> None:
        """Assign default client scopes to a new client"""
        if client.protocol != 'openid-connect':
            return
        
        default_scopes = ['openid', 'profile', 'email', 'roles', 'web-origins']
        optional_scopes = ['address', 'phone', 'offline_access', 'microprofile-jwt']
        
        for scope_name in default_scopes:
            scope = ClientScope.query.filter_by(
                realm_id=client.realm_id,
                name=scope_name
            ).first()
            if scope:
                mapping = ClientScopeMapping(
                    client_id=client.id,
                    scope_id=scope.id,
                    default_scope=True
                )
                db.session.add(mapping)
        
        for scope_name in optional_scopes:
            scope = ClientScope.query.filter_by(
                realm_id=client.realm_id,
                name=scope_name
            ).first()
            if scope:
                mapping = ClientScopeMapping(
                    client_id=client.id,
                    scope_id=scope.id,
                    default_scope=False
                )
                db.session.add(mapping)
        
        db.session.commit()
    
    @staticmethod
    def get_client(client_id: str) -> Optional[Client]:
        """Get a client by internal ID"""
        return Client.find_by_id(client_id)
    
    @staticmethod
    def get_client_by_client_id(realm_id: str, client_id: str) -> Optional[Client]:
        """Get a client by OAuth client_id within a realm"""
        return Client.find_by_client_id(realm_id, client_id)
    
    @staticmethod
    def get_clients(realm_id: str, first: int = 0, max_results: int = 100,
                    search: str = None) -> List[Client]:
        """Get all clients in a realm"""
        query = Client.query.filter_by(realm_id=realm_id)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                db.or_(
                    Client.client_id.ilike(search_pattern),
                    Client.name.ilike(search_pattern)
                )
            )
        
        return query.offset(first).limit(max_results).all()
    
    @staticmethod
    def count_clients(realm_id: str) -> int:
        """Count clients in a realm"""
        return Client.query.filter_by(realm_id=realm_id).count()
    
    @staticmethod
    def update_client(client: Client, **kwargs) -> Client:
        """Update client settings"""
        return client.update(**kwargs)
    
    @staticmethod
    def delete_client(client: Client) -> None:
        """Delete a client"""
        client.delete()
    
    @staticmethod
    def regenerate_secret(client: Client) -> str:
        """Regenerate client secret"""
        client.secret = generate_secret()
        db.session.commit()
        return client.secret
    
    @staticmethod
    def validate_credentials(realm_id: str, client_id: str, client_secret: str) -> Optional[Client]:
        """
        Validate client credentials.
        
        Returns the client if credentials are valid, None otherwise.
        """
        client = Client.find_by_client_id(realm_id, client_id)
        if not client:
            return None
        if not client.enabled:
            return None
        if client.validate_secret(client_secret):
            return client
        return None
    
    @staticmethod
    def get_client_scopes(client: Client, default_only: bool = False) -> List[ClientScope]:
        """Get scopes assigned to a client"""
        query = ClientScopeMapping.query.filter_by(client_id=client.id)
        if default_only:
            query = query.filter_by(default_scope=True)
        
        return [mapping.scope for mapping in query.all()]
    
    @staticmethod
    def add_client_scope(client: Client, scope: ClientScope, default: bool = True) -> None:
        """Add a scope to a client"""
        existing = ClientScopeMapping.query.filter_by(
            client_id=client.id,
            scope_id=scope.id
        ).first()
        
        if existing:
            existing.default_scope = default
        else:
            mapping = ClientScopeMapping(
                client_id=client.id,
                scope_id=scope.id,
                default_scope=default
            )
            db.session.add(mapping)
        
        db.session.commit()
    
    @staticmethod
    def remove_client_scope(client: Client, scope: ClientScope) -> None:
        """Remove a scope from a client"""
        ClientScopeMapping.query.filter_by(
            client_id=client.id,
            scope_id=scope.id
        ).delete()
        db.session.commit()
    
    @staticmethod
    def get_protocol_mappers(client: Client) -> List[ProtocolMapper]:
        """Get protocol mappers for a client"""
        return client.protocol_mappers.all()
    
    @staticmethod
    def create_protocol_mapper(client: Client, name: str, protocol_mapper: str,
                               config: dict = None) -> ProtocolMapper:
        """Create a protocol mapper for a client"""
        mapper = ProtocolMapper(
            client_id=client.id,
            name=name,
            protocol=client.protocol,
            protocol_mapper=protocol_mapper,
            config=config or {}
        )
        db.session.add(mapper)
        db.session.commit()
        return mapper
    
    @staticmethod
    def get_effective_scopes(client: Client, requested_scopes: str = None) -> List[ClientScope]:
        """
        Get effective scopes for a token request.
        
        Args:
            client: The client
            requested_scopes: Space-separated scope string from request
        
        Returns:
            List of ClientScope objects to include in token
        """
        # Get default scopes
        default_scopes = {s.name: s for s in ClientService.get_client_scopes(client, default_only=True)}
        
        # If no scopes requested, return defaults
        if not requested_scopes:
            return list(default_scopes.values())
        
        # Get optional scopes
        optional_scopes = {s.name: s for s in ClientService.get_client_scopes(client, default_only=False)}
        optional_scopes = {k: v for k, v in optional_scopes.items() if k not in default_scopes}
        
        # Parse requested scopes
        requested = set(requested_scopes.split())
        
        # Start with defaults
        result = list(default_scopes.values())
        
        # Add requested optional scopes
        for scope_name in requested:
            if scope_name in optional_scopes:
                result.append(optional_scopes[scope_name])
        
        return result
