# -*- encoding: utf-8 -*-
"""
RijanAuth - Event Model
Login events and admin events for auditing
"""

from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from apps.models.base import generate_uuid
from apps import db


class Event(db.Model):
    """
    Event - Login/authentication events for auditing.
    Mirrors Keycloak's event model.
    """
    __tablename__ = 'events'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Realm
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Event type (e.g., 'LOGIN', 'LOGIN_ERROR', 'LOGOUT', 'REGISTER', etc.)
    type = Column(String(100), nullable=False, index=True)
    
    # User info
    user_id = Column(String(36), nullable=True, index=True)
    session_id = Column(String(36), nullable=True)
    
    # Client info
    client_id = Column(String(255), nullable=True, index=True)
    
    # IP address
    ip_address = Column(String(45), nullable=True)
    
    # Error info (for error events)
    error = Column(String(255), nullable=True)
    
    # Additional details (JSON)
    details = Column(JSON, default=dict)
    
    # Timestamp
    time = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    __table_args__ = (
        db.Index('ix_event_realm_time', 'realm_id', 'time'),
        db.Index('ix_event_realm_user', 'realm_id', 'user_id'),
        db.Index('ix_event_realm_type', 'realm_id', 'type'),
    )
    
    def __repr__(self):
        return f'<Event {self.type} at {self.time}>'
    
    @classmethod
    def log_event(cls, realm_id, event_type, user_id=None, client_id=None, 
                  session_id=None, ip_address=None, error=None, details=None):
        """Create and save a new event"""
        event = cls(
            realm_id=realm_id,
            type=event_type,
            user_id=user_id,
            client_id=client_id,
            session_id=session_id,
            ip_address=ip_address,
            error=error,
            details=details or {}
        )
        db.session.add(event)
        db.session.commit()
        return event
    
    @classmethod
    def get_events(cls, realm_id, event_types=None, user_id=None, client_id=None,
                   date_from=None, date_to=None, first=0, max_results=100):
        """Query events with filters"""
        query = cls.query.filter_by(realm_id=realm_id)
        
        if event_types:
            query = query.filter(cls.type.in_(event_types))
        if user_id:
            query = query.filter_by(user_id=user_id)
        if client_id:
            query = query.filter_by(client_id=client_id)
        if date_from:
            query = query.filter(cls.time >= date_from)
        if date_to:
            query = query.filter(cls.time <= date_to)
        
        return query.order_by(cls.time.desc()).offset(first).limit(max_results).all()
    
    @classmethod
    def delete_old_events(cls, realm_id, before_time):
        """Delete events older than specified time"""
        cls.query.filter(
            cls.realm_id == realm_id,
            cls.time < before_time
        ).delete()
        db.session.commit()
    
    def to_dict(self):
        return {
            'time': int(self.time.timestamp() * 1000) if self.time else None,
            'type': self.type,
            'realmId': self.realm_id,
            'clientId': self.client_id,
            'userId': self.user_id,
            'sessionId': self.session_id,
            'ipAddress': self.ip_address,
            'error': self.error,
            'details': self.details or {},
        }


class AdminEvent(db.Model):
    """
    Admin Event - Administrative actions for auditing.
    Tracks changes made through the admin console or API.
    """
    __tablename__ = 'admin_events'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Realm
    realm_id = Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Operation type: CREATE, UPDATE, DELETE, ACTION
    operation_type = Column(String(50), nullable=False, index=True)
    
    # Resource type (e.g., 'USER', 'CLIENT', 'REALM', 'GROUP', etc.)
    resource_type = Column(String(100), nullable=False, index=True)
    
    # Resource path (e.g., 'users/123', 'clients/456')
    resource_path = Column(String(1024), nullable=True)
    
    # Admin user info
    auth_realm_id = Column(String(36), nullable=True)
    auth_user_id = Column(String(36), nullable=True, index=True)
    auth_client_id = Column(String(255), nullable=True)
    auth_ip_address = Column(String(45), nullable=True)
    
    # Representation (JSON) - the data that was sent/modified
    representation = Column(Text, nullable=True)
    
    # Error info
    error = Column(String(255), nullable=True)
    
    # Timestamp
    time = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    __table_args__ = (
        db.Index('ix_admin_event_realm_time', 'realm_id', 'time'),
        db.Index('ix_admin_event_realm_resource', 'realm_id', 'resource_type'),
    )
    
    def __repr__(self):
        return f'<AdminEvent {self.operation_type} {self.resource_type} at {self.time}>'
    
    @classmethod
    def log_admin_event(cls, realm_id, operation_type, resource_type, resource_path=None,
                       auth_realm_id=None, auth_user_id=None, auth_client_id=None,
                       auth_ip_address=None, representation=None, error=None):
        """Create and save a new admin event"""
        event = cls(
            realm_id=realm_id,
            operation_type=operation_type,
            resource_type=resource_type,
            resource_path=resource_path,
            auth_realm_id=auth_realm_id,
            auth_user_id=auth_user_id,
            auth_client_id=auth_client_id,
            auth_ip_address=auth_ip_address,
            representation=representation,
            error=error
        )
        db.session.add(event)
        db.session.commit()
        return event
    
    @classmethod
    def get_events(cls, realm_id, operation_types=None, resource_types=None,
                   auth_user_id=None, date_from=None, date_to=None,
                   first=0, max_results=100):
        """Query admin events with filters"""
        query = cls.query.filter_by(realm_id=realm_id)
        
        if operation_types:
            query = query.filter(cls.operation_type.in_(operation_types))
        if resource_types:
            query = query.filter(cls.resource_type.in_(resource_types))
        if auth_user_id:
            query = query.filter_by(auth_user_id=auth_user_id)
        if date_from:
            query = query.filter(cls.time >= date_from)
        if date_to:
            query = query.filter(cls.time <= date_to)
        
        return query.order_by(cls.time.desc()).offset(first).limit(max_results).all()
    
    def to_dict(self):
        return {
            'time': int(self.time.timestamp() * 1000) if self.time else None,
            'realmId': self.realm_id,
            'operationType': self.operation_type,
            'resourceType': self.resource_type,
            'resourcePath': self.resource_path,
            'authDetails': {
                'realmId': self.auth_realm_id,
                'clientId': self.auth_client_id,
                'userId': self.auth_user_id,
                'ipAddress': self.auth_ip_address,
            },
            'representation': self.representation,
            'error': self.error,
        }
