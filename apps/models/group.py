# -*- encoding: utf-8 -*-
"""
RijanAuth - Group Model
Hierarchical group management with role inheritance
"""

from sqlalchemy import Column, String, Text
from sqlalchemy.orm import relationship
from apps.models.base import RealmScopedModel, generate_uuid
from apps import db


class Group(RealmScopedModel):
    """
    Group - Organizes users with shared attributes and roles.
    Supports hierarchical structure (groups can have parent groups).
    Mirrors Keycloak's group model.
    """
    __tablename__ = 'groups'
    
    # Basic Info
    name = Column(String(255), nullable=False, index=True)
    
    # Parent group for hierarchy (None for top-level groups)
    parent_id = Column(String(36), db.ForeignKey('groups.id', ondelete='CASCADE'), nullable=True, index=True)
    
    # Full path including parent groups (e.g., "/parent/child/grandchild")
    # Limited to 500 chars so the composite UNIQUE index (realm_id, path) stays
    # within MySQL InnoDB's 3072-byte key limit when using utf8mb4 (4 bytes/char):
    #   36 * 4 + 500 * 4 = 2144 bytes < 3072 bytes
    path = Column(String(500), nullable=False, index=True)
    
    # Relationships
    realm = relationship('Realm', back_populates='groups')
    parent = relationship('Group', remote_side='Group.id', backref='subgroups')
    members = relationship('GroupMembership', back_populates='group', cascade='all, delete-orphan', lazy='dynamic')
    role_mappings = relationship('RoleMapping', back_populates='group', cascade='all, delete-orphan', lazy='dynamic')
    attributes = relationship('GroupAttribute', back_populates='group', cascade='all, delete-orphan', lazy='dynamic')
    
    # Unique constraint: path must be unique within realm
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'path', name='uq_group_path'),
    )
    
    def __repr__(self):
        return f'<Group {self.path}>'
    
    @classmethod
    def find_by_path(cls, realm_id, path):
        """Find a group by its full path"""
        return cls.query.filter_by(realm_id=realm_id, path=path).first()
    
    @classmethod
    def get_top_level_groups(cls, realm_id):
        """Get all top-level groups (no parent) in a realm"""
        return cls.query.filter_by(realm_id=realm_id, parent_id=None).all()
    
    def get_all_subgroups(self):
        """Get all subgroups recursively"""
        result = list(self.subgroups)
        for child in self.subgroups:
            result.extend(child.get_all_subgroups())
        return result
    
    def get_all_members(self):
        """Get all users including those in subgroups"""
        from apps.models.user import User
        user_ids = set()
        
        # Direct members
        for membership in self.members:
            user_ids.add(membership.user_id)
        
        # Members from subgroups
        for subgroup in self.get_all_subgroups():
            for membership in subgroup.members:
                user_ids.add(membership.user_id)
        
        return User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    
    def get_effective_roles(self):
        """Get all roles including inherited from parent groups"""
        from apps.models.role import Role
        roles = set()
        
        # Roles assigned to this group
        for mapping in self.role_mappings:
            roles.add(mapping.role)
            # Include composite roles
            if mapping.role.composite:
                roles.update(mapping.role.get_effective_roles())
        
        # Roles inherited from parent
        if self.parent:
            roles.update(self.parent.get_effective_roles())
        
        return roles
    
    def update_path(self):
        """Update the path based on parent hierarchy"""
        if self.parent:
            self.path = f'{self.parent.path}/{self.name}'
        else:
            self.path = f'/{self.name}'
        
        # Update all subgroups recursively
        for subgroup in self.subgroups:
            subgroup.update_path()
    
    def to_dict(self, include_subgroups=False):
        """Serialize group to dictionary"""
        data = {
            'id': self.id,
            'name': self.name,
            'path': self.path,
            'parentId': self.parent_id,
            'realmId': self.realm_id,
        }
        if include_subgroups:
            data['subGroups'] = [g.to_dict(include_subgroups=True) for g in self.subgroups]
        return data


class GroupMembership(db.Model):
    """
    Mapping of users to groups.
    """
    __tablename__ = 'group_memberships'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    group_id = Column(String(36), db.ForeignKey('groups.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Relationships
    user = relationship('User', back_populates='group_memberships')
    group = relationship('Group', back_populates='members')
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'group_id', name='uq_group_membership'),
    )
    
    def __repr__(self):
        return f'<GroupMembership user:{self.user_id} -> group:{self.group_id}>'


class GroupAttribute(db.Model):
    """
    Key-value attributes for groups.
    """
    __tablename__ = 'group_attributes'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    group_id = Column(String(36), db.ForeignKey('groups.id', ondelete='CASCADE'), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    value = Column(Text, nullable=True)
    
    # Relationship
    group = relationship('Group', back_populates='attributes')
    
    __table_args__ = (
        db.Index('ix_group_attr_name', 'group_id', 'name'),
    )
    
    def __repr__(self):
        return f'<GroupAttribute {self.name}={self.value}>'


class GroupRoleMapping(db.Model):
    """
    Direct mapping of group to role (for inline role representation).
    This is an alias table for consistency with Keycloak's API.
    """
    __tablename__ = 'group_role_mappings'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    group_id = Column(String(36), db.ForeignKey('groups.id', ondelete='CASCADE'), nullable=False, index=True)
    role_id = Column(String(36), db.ForeignKey('roles.id', ondelete='CASCADE'), nullable=False, index=True)
    
    __table_args__ = (
        db.UniqueConstraint('group_id', 'role_id', name='uq_group_role'),
    )
