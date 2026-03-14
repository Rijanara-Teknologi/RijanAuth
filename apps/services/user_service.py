# -*- encoding: utf-8 -*-
"""
RijanAuth - User Service
Business logic for user management
"""

from typing import Optional, List, Dict, Any, Union
from apps import db
from apps.models.user import User, UserAttribute, Credential
from apps.models.role import Role, RoleMapping
from apps.models.group import Group, GroupMembership
from apps.utils.crypto import hash_password, verify_password


class UserService:
    """Service class for user operations"""
    
    @staticmethod
    def create_user(realm_id: str, username: str, email: str = None,
                    password: str = None, first_name: str = None,
                    last_name: str = None, enabled: bool = True,
                    email_verified: bool = False, **kwargs) -> User:
        """
        Create a new user.
        
        Args:
            realm_id: The realm ID
            username: Username (unique within realm)
            email: Email address
            password: Plain text password (will be hashed)
            first_name: First name
            last_name: Last name
            enabled: Whether the user is enabled
            email_verified: Whether email is verified
            **kwargs: Additional user attributes
        
        Returns:
            The created User instance
        """
        user = User(
            realm_id=realm_id,
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            enabled=enabled,
            email_verified=email_verified
        )
        user.save()
        
        # Set password if provided
        if password:
            UserService.set_password(user, password)
        
        # Set additional attributes
        for key, value in kwargs.items():
            if not hasattr(User, key):
                UserService.set_attribute(user, key, value)
        
        return user
    
    @staticmethod
    def get_user(user_id: str) -> Optional[User]:
        """Get a user by ID"""
        return User.find_by_id(user_id)
    
    @staticmethod
    def get_user_by_username(realm_id: str, username: str) -> Optional[User]:
        """Get a user by username within a realm"""
        return User.find_by_username(realm_id, username)
    
    @staticmethod
    def get_user_by_email(realm_id: str, email: str) -> Optional[User]:
        """Get a user by email within a realm"""
        return User.find_by_email(realm_id, email)
    
    @staticmethod
    def search_users(realm_id: str, search: str = None, first: int = 0,
                     max_results: int = 100, **filters) -> List[User]:
        """
        Search users in a realm.
        
        Args:
            realm_id: The realm ID
            search: Search string (matches username, email, first/last name)
            first: First result index (for pagination)
            max_results: Maximum results to return
            **filters: Additional filters (email, username, firstName, lastName, enabled)
        """
        query = User.query.filter_by(realm_id=realm_id)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                db.or_(
                    User.username.ilike(search_pattern),
                    User.email.ilike(search_pattern),
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern)
                )
            )
        
        # Apply filters
        if 'email' in filters:
            query = query.filter_by(email=filters['email'])
        if 'username' in filters:
            query = query.filter_by(username=filters['username'])
        if 'firstName' in filters:
            query = query.filter_by(first_name=filters['firstName'])
        if 'lastName' in filters:
            query = query.filter_by(last_name=filters['lastName'])
        if 'enabled' in filters:
            query = query.filter_by(enabled=filters['enabled'])
        
        return query.offset(first).limit(max_results).all()
    
    @staticmethod
    def count_users(realm_id: str) -> int:
        """Count total users in a realm"""
        return User.query.filter_by(realm_id=realm_id).count()
    
    @staticmethod
    def update_user(user: User, **kwargs) -> User:
        """Update user attributes"""
        return user.update(**kwargs)
    
    @staticmethod
    def delete_user(user: User) -> None:
        """Delete a user"""
        user.delete()
    
    @staticmethod
    def set_password(user: User, password: str) -> None:
        """Set or update user password"""
        hashed = hash_password(password)
        
        # Remove existing password credential
        Credential.query.filter_by(user_id=user.id, type='password').delete()
        
        # Create new credential
        credential = Credential.create_password(user.id, hashed)
        db.session.add(credential)
        db.session.commit()
    
    @staticmethod
    def verify_password(user: User, password: str) -> bool:
        """Verify user password"""
        credential = user.get_password_credential()
        if not credential or not credential.secret_data:
            return False
        return verify_password(password, credential.secret_data)
    
    @staticmethod
    def get_attribute(user: User, name: str) -> Optional[str]:
        """Get a user attribute"""
        return user.get_attribute(name)
    
    @staticmethod
    def get_attributes(user: User) -> Dict[str, List[str]]:
        """Get all user attributes as a dictionary"""
        attrs = {}
        for attr in user.attributes:
            if attr.name not in attrs:
                attrs[attr.name] = []
            attrs[attr.name].append(attr.value)
        return attrs
    
    @staticmethod
    def set_attribute(user: User, name: str, value: str) -> None:
        """Set a user attribute"""
        user.set_attribute(name, value)
    
    @staticmethod
    def set_attributes(user: User, attributes: Dict[str, Union[str, List[str]]]) -> None:
        """Set multiple user attributes (replaces existing).

        ``attributes`` may map each name to either a list of values
        (e.g. ``{'phone': ['555-1234']}``) or a single scalar value
        (e.g. ``{'photo': 'https://…'}``).  Both forms are handled
        transparently so that callers – in particular federation sync
        code – do not need to pre-wrap scalars.
        """
        # Remove existing attributes
        UserAttribute.query.filter_by(user_id=user.id).delete()
        
        # Add new attributes
        for name, values in attributes.items():
            # Accept both scalar values and lists of values
            if not isinstance(values, (list, tuple)):
                values = [values]
            for value in values:
                if value is None:
                    continue
                attr = UserAttribute(user_id=user.id, name=name, value=str(value))
                db.session.add(attr)
        
        db.session.commit()
    
    @staticmethod
    def get_user_roles(user: User, client_id: str = None) -> List[Role]:
        """Get roles assigned to a user"""
        query = RoleMapping.query.filter_by(user_id=user.id).join(Role)
        if client_id:
            query = query.filter(Role.client_id == client_id)
        else:
            query = query.filter(Role.client_id.is_(None))
        
        return [rm.role for rm in query.all()]
    
    @staticmethod
    def assign_role(user: User, role: Role) -> None:
        """Assign a role to a user"""
        existing = RoleMapping.query.filter_by(user_id=user.id, role_id=role.id).first()
        if not existing:
            mapping = RoleMapping(user_id=user.id, role_id=role.id)
            db.session.add(mapping)
            db.session.commit()
    
    @staticmethod
    def remove_role(user: User, role: Role) -> None:
        """Remove a role from a user"""
        RoleMapping.query.filter_by(user_id=user.id, role_id=role.id).delete()
        db.session.commit()
    
    @staticmethod
    def get_user_groups(user: User) -> List[Group]:
        """Get groups a user belongs to"""
        return [gm.group for gm in user.group_memberships]
    
    @staticmethod
    def join_group(user: User, group: Group) -> None:
        """Add user to a group"""
        existing = GroupMembership.query.filter_by(user_id=user.id, group_id=group.id).first()
        if not existing:
            membership = GroupMembership(user_id=user.id, group_id=group.id)
            db.session.add(membership)
            db.session.commit()
    
    @staticmethod
    def leave_group(user: User, group: Group) -> None:
        """Remove user from a group"""
        GroupMembership.query.filter_by(user_id=user.id, group_id=group.id).delete()
        db.session.commit()
    
    @staticmethod
    def get_effective_roles(user: User) -> List[Role]:
        """
        Get all effective roles for a user, including:
        - Directly assigned roles
        - Roles inherited from groups
        - Composite role children
        """
        roles = set()
        
        # Direct roles
        for mapping in user.role_mappings:
            roles.update(mapping.role.get_effective_roles())
        
        # Group roles
        for membership in user.group_memberships:
            roles.update(membership.group.get_effective_roles())
        
        return list(roles)
    
    @staticmethod
    def add_required_action(user: User, action: str) -> None:
        """Add a required action to user"""
        actions = user.required_actions or []
        if action not in actions:
            actions.append(action)
            user.required_actions = actions
            db.session.commit()
    
    @staticmethod
    def remove_required_action(user: User, action: str) -> None:
        """Remove a required action from user"""
        actions = user.required_actions or []
        if action in actions:
            actions.remove(action)
            user.required_actions = actions
            db.session.commit()
