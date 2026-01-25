# -*- encoding: utf-8 -*-
"""
RijanAuth - Database Seeders
Initial database seeding for fresh installations
"""

from apps.models.realm import Realm


def needs_seeding():
    """Check if the database needs initial seeding"""
    return Realm.query.count() == 0


def run_initial_seed():
    """
    Run all initial seeders in proper dependency order.
    This should only be called when the database is empty.
    """
    from config.seeding import SeedingConfig
    
    if SeedingConfig.SKIP_INITIAL_SEED:
        print('[SEEDER] Skipping initial seed (RIJANAUTH_SKIP_INITIAL_SEED=true)')
        return None
    
    print('[SEEDER] Starting initial database seeding...')
    print('[SEEDER] ' + '=' * 50)
    
    # 1. Create master realm
    from apps.seeders.master_realm_seeder import seed_master_realm
    realm = seed_master_realm()
    
    # 2. Create authentication flows
    from apps.seeders.auth_flows_seeder import seed_authentication_flows
    seed_authentication_flows(realm)
    
    # 3. Create default clients
    from apps.seeders.default_clients_seeder import seed_default_clients
    seed_default_clients(realm)
    
    # 4. Create admin user (requires realm and flows)
    from apps.seeders.admin_user_seeder import seed_admin_user
    admin_info = seed_admin_user(realm)
    
    # 5. Configure system events
    from apps.seeders.system_events_seeder import seed_system_events
    seed_system_events(realm)
    
    print('[SEEDER] ' + '=' * 50)
    print('[SEEDER] Initial setup complete!')
    print('[SEEDER] ')
    print('[SEEDER] ⚠️  IMPORTANT SECURITY NOTICE ⚠️')
    print('[SEEDER] Please change the admin password immediately after first login.')
    print('[SEEDER] The initial password will expire in 24 hours.')
    print('[SEEDER] ' + '=' * 50)
    
    return admin_info
