# -*- encoding: utf-8 -*-
"""
RijanAuth - Role Model
Role-based access control (RBAC) with realm and client roles
"""

from sqlalchemy import Column, String, Boolean, Text
from sqlalchemy.orm import relationship
from apps.models.base import RealmScopedModel, generate_uuid
from apps import db


class Role(RealmScopedModel):
    """
    Role - Defines permissions within a realm.
    Can be a realm role (client_id is None) or client role (associated with a client).
    Mirrors Keycloak's role model.
    """
    __tablename__ = 'roles'
    
    # Basic Info
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Client association (None for realm roles)
    client_id = Column(String(36), db.ForeignKey('clients.id', ondelete='CASCADE'), nullable=True, index=True)
    
    # Composite role flag
    composite = Column(Boolean, default=False)
    
    # Client role flag (redundant with client_id but matches Keycloak API)
    client_role = Column(Boolean, default=False)
    
    # Relationships
    realm = relationship('Realm', back_populates='roles')
    client = relationship('Client', back_populates='roles')
    role_mappings = relationship('RoleMapping', back_populates='role', cascade='all, delete-orphan', lazy='dynamic')
    
    # Composite role relationships (self-referential many-to-many)
    composite_roles = relationship(
        'Role',
        secondary='composite_roles',
        primaryjoin='Role.id == composite_roles.c.composite_id',
        secondaryjoin='Role.id == composite_roles.c.child_id',
        backref='composite_parents',
        lazy='dynamic'
    )
    
    # Unique constraint: role name unique within realm + client scope
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'client_id', 'name', name='uq_role_name'),
    )
    
    def __repr__(self):
        if self.client_id:
            return f'<Role {self.name} (client)>'
        return f'<Role {self.name} (realm)>'
    
    @classmethod
    def find_realm_role(cls, realm_id, role_name):
        """Find a realm role by name"""
        return cls.query.filter_by(
            realm_id=realm_id,
            client_id=None,
            name=role_name
        ).first()
    
    @classmethod
    def find_client_role(cls, client_id, role_name):
        """Find a client role by name"""
        return cls.query.filter_by(
            client_id=client_id,
            name=role_name
        ).first()
    
    @classmethod
    def get_realm_roles(cls, realm_id):
        """Get all realm roles"""
        return cls.query.filter_by(realm_id=realm_id, client_id=None).all()
    
    @classmethod
    def get_client_roles(cls, client_id):
        """Get all roles for a client"""
        return cls.query.filter_by(client_id=client_id).all()
    
    def get_effective_roles(self):
        """Get this role plus all composite child roles (recursive)"""
        roles = {self}
        if self.composite:
            for child in self.composite_roles:
                roles.update(child.get_effective_roles())
        return roles
    
    def to_dict(self):
        """Serialize role to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'composite': self.composite,
            'clientRole': self.client_role,
            'containerId': self.client_id or self.realm_id,
        }


# Association table for composite roles
composite_roles = db.Table(
    'composite_roles',
    Column('composite_id', String(36), db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('child_id', String(36), db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
)


class RoleMapping(db.Model):
    """
    Mapping of roles to users or groups.
    """
    __tablename__ = 'role_mappings'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Role being mapped
    role_id = Column(String(36), db.ForeignKey('roles.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # User or group (one must be set)
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)
    group_id = Column(String(36), db.ForeignKey('groups.id', ondelete='CASCADE'), nullable=True, index=True)
    
    # Relationships
    role = relationship('Role', back_populates='role_mappings')
    user = relationship('User', back_populates='role_mappings')
    group = relationship('Group', back_populates='role_mappings')
    
    __table_args__ = (
        # Ensure at least one of user_id or group_id is set
        db.CheckConstraint(
            '(user_id IS NOT NULL AND group_id IS NULL) OR (user_id IS NULL AND group_id IS NOT NULL)',
            name='ck_role_mapping_target'
        ),
        # Unique constraint to prevent duplicate mappings
        db.UniqueConstraint('role_id', 'user_id', name='uq_role_user_mapping'),
        db.UniqueConstraint('role_id', 'group_id', name='uq_role_group_mapping'),
    )
    
    def __repr__(self):
        target = f'user:{self.user_id}' if self.user_id else f'group:{self.group_id}'
        return f'<RoleMapping {self.role_id} -> {target}>'
