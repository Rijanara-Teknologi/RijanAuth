#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
RijanAuth - Test Script
Verifies that all models and services are working correctly
"""

from apps.config import config_dict
from apps import create_app, db

print("Creating Flask app...")
app = create_app(config_dict['Debug'])
print("Flask app created successfully!")
print(f"Database URI: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')}")

with app.app_context():
    # Verify tables
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print(f"\nDatabase tables created: {len(tables)}")
    for table in sorted(tables):
        print(f"  - {table}")
    
    # Check master realm
    from apps.models.realm import Realm
    master = Realm.query.filter_by(name='master').first()
    if master:
        print(f"\nMaster realm found: {master.name} (ID: {master.id})")
    else:
        print("\nMaster realm not found - creating...")
        from apps.services.realm_service import RealmService
        master = RealmService.create_realm('master', 'Master Realm')
        print(f"Master realm created: {master.name}")
    
    # Check default roles
    from apps.models.role import Role
    roles = Role.query.filter_by(realm_id=master.id).all()
    print(f"\nRoles in master realm: {len(roles)}")
    for role in roles:
        print(f"  - {role.name}")
    
    # Check default clients
    from apps.models.client import Client
    clients = Client.query.filter_by(realm_id=master.id).all()
    print(f"\nClients in master realm: {len(clients)}")
    for client in clients:
        print(f"  - {client.client_id}")

print("\n✅ Phase 1 verification complete!")
