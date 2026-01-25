# -*- encoding: utf-8 -*-
"""
RijanAuth - Admin User Seeder
Creates the initial superadmin user with full system privileges
"""

from datetime import datetime, timedelta
from apps import db
from apps.models.user import User, Credential
from apps.models.role import Role, RoleMapping
from apps.models.base import generate_uuid
from apps.utils.crypto import hash_password
from config.seeding import SeedingConfig


class InitialSetupToken(db.Model):
    """Temporary storage for initial setup tokens"""
    __tablename__ = 'initial_setup_tokens'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    token = db.Column(db.String(255), nullable=False, unique=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)


def seed_admin_user(realm):
    """
    Create the initial superadmin user with full system privileges.
    
    Security measures:
    - Password is auto-generated or from environment variable
    - Password change is required on first login
    - Setup token is generated for initial access
    """
    print(f'[SEEDER] Creating admin user: {SeedingConfig.ADMIN_USERNAME}')
    
    # Check if admin already exists
    existing = User.find_by_username(realm.id, SeedingConfig.ADMIN_USERNAME)
    if existing:
        print(f'[SEEDER] Admin user already exists, skipping...')
        return {'user': existing, 'password': None, 'setup_token': None}
    
    # Generate or get password
    if SeedingConfig.ADMIN_PASSWORD:
        password = SeedingConfig.ADMIN_PASSWORD
        password_source = 'environment variable'
    else:
        password = SeedingConfig.generate_secure_password()
        password_source = 'auto-generated'
    
    # Create admin user
    admin_user = User(
        realm_id=realm.id,
        username=SeedingConfig.ADMIN_USERNAME,
        email=SeedingConfig.ADMIN_EMAIL,
        email_verified=True,
        first_name='System',
        last_name='Administrator',
        enabled=True,
        required_actions=['UPDATE_PASSWORD'],  # Force password change
    )
    db.session.add(admin_user)
    db.session.flush()  # Get user ID
    
    # Create password credential
    hashed_password = hash_password(password)
    credential = Credential.create_password(
        user_id=admin_user.id,
        hashed_password=hashed_password,
        algorithm='bcrypt'
    )
    db.session.add(credential)
    
    # Create admin roles
    admin_role = create_admin_role(realm)
    create_realm_role = create_create_realm_role(realm)
    
    # Assign roles to admin
    admin_mapping = RoleMapping(user_id=admin_user.id, role_id=admin_role.id)
    realm_mapping = RoleMapping(user_id=admin_user.id, role_id=create_realm_role.id)
    db.session.add(admin_mapping)
    db.session.add(realm_mapping)
    
    # Generate setup token
    setup_token = SeedingConfig.generate_setup_token()
    token_expires = datetime.utcnow() + timedelta(hours=SeedingConfig.SETUP_TOKEN_VALIDITY_HOURS)
    
    setup_token_record = InitialSetupToken(
        token=setup_token,
        user_id=admin_user.id,
        expires_at=token_expires
    )
    db.session.add(setup_token_record)
    
    db.session.commit()
    
    # Log credentials (only display this once!)
    print(f'[SEEDER] Admin user created successfully')
    print(f'[SEEDER]   - Username: {SeedingConfig.ADMIN_USERNAME}')
    print(f'[SEEDER]   - Email: {SeedingConfig.ADMIN_EMAIL}')
    print(f'[SEEDER]   - Password ({password_source}): {password}')
    print(f'[SEEDER]   - Setup token: {setup_token}')
    print(f'[SEEDER]   - Token expires: {token_expires.isoformat()}')
    print(f'[SEEDER] ')
    print(f'[SEEDER] ⚠️  SAVE THESE CREDENTIALS NOW - They will not be shown again!')
    
    return {
        'user': admin_user,
        'password': password,
        'setup_token': setup_token,
        'expires_at': token_expires
    }


def create_admin_role(realm):
    """Create the admin role with full permissions"""
    existing = Role.query.filter_by(realm_id=realm.id, name='admin', client_id=None).first()
    if existing:
        return existing
    
    admin_role = Role(
        realm_id=realm.id,
        name='admin',
        description='Full administrative access to the realm',
        composite=True,
        client_role=False
    )
    db.session.add(admin_role)
    db.session.flush()
    
    print(f'[SEEDER]   - Created role: admin')
    return admin_role


def create_create_realm_role(realm):
    """Create the create-realm role"""
    existing = Role.query.filter_by(realm_id=realm.id, name='create-realm', client_id=None).first()
    if existing:
        return existing
    
    create_realm_role = Role(
        realm_id=realm.id,
        name='create-realm',
        description='Permission to create new realms',
        composite=False,
        client_role=False
    )
    db.session.add(create_realm_role)
    db.session.flush()
    
    print(f'[SEEDER]   - Created role: create-realm')
    return create_realm_role
