# -*- encoding: utf-8 -*-
"""
RijanAuth - Seeder Unit Tests
"""

import unittest
from apps import create_app, db
from apps.config import config_dict
from apps.models.realm import Realm
from apps.models.user import User
from apps.models.authentication import AuthenticationFlow
from apps.models.client import Client
from apps.seeders import needs_seeding, run_initial_seed
from config.seeding import SeedingConfig

class TestSeeders(unittest.TestCase):
    
    def setUp(self):
        # Use existing config but override DB to memory for speed/isolation
        self.app = create_app(config_dict['Debug'])
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['TESTING'] = True
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_needs_seeding(self):
        """Test detection of empty database"""
        self.assertTrue(needs_seeding())
        
        # Create a realm
        realm = Realm(name='test', enabled=True)
        db.session.add(realm)
        db.session.commit()
        
        self.assertFalse(needs_seeding())

    def test_full_seeding_process(self):
        """Test the full seeding process execution"""
        # Run seeders
        admin_info = run_initial_seed()
        
        # 1. Verify Master Realm
        master = Realm.find_by_name('master')
        self.assertIsNotNone(master)
        self.assertTrue(master.enabled)
        self.assertTrue(master.brute_force_protected)
        self.assertEqual(master.access_token_lifespan, SeedingConfig.ACCESS_TOKEN_LIFESPAN)
        self.assertFalse(master.registration_allowed)
        
        # 2. Verify Authentication Flows
        browser_flow = AuthenticationFlow.query.filter_by(
            realm_id=master.id, alias='browser'
        ).first()
        self.assertIsNotNone(browser_flow)
        self.assertEqual(master.browser_flow_id, browser_flow.id)
        
        # 3. Verify Default Clients
        admin_cli = Client.find_by_client_id(master.id, 'admin-cli')
        self.assertIsNotNone(admin_cli)
        self.assertTrue(admin_cli.public_client)
        
        account_console = Client.find_by_client_id(master.id, 'account-console')
        self.assertIsNotNone(account_console)
        
        # 4. Verify Admin User
        admin = User.find_by_username(master.id, SeedingConfig.ADMIN_USERNAME)
        self.assertIsNotNone(admin)
        self.assertEqual(admin.username, SeedingConfig.ADMIN_USERNAME)
        self.assertTrue(admin.enabled)
        
        # Check password change requirement
        self.assertIn('UPDATE_PASSWORD', admin.required_actions)
        
        # Check credential exists
        cred = admin.get_password_credential()
        self.assertIsNotNone(cred)
        self.assertEqual(cred.type, 'password')
        
        # Check setup token
        self.assertIsNotNone(admin_info['setup_token'])
        
        # 5. Verify System Events
        self.assertTrue(master.events_enabled)
        self.assertTrue(master.admin_events_enabled)
        self.assertIn('LOGIN', master.enabled_event_types)

    def test_idempotency(self):
        """Test that seeders can run multiple times without error"""
        run_initial_seed()
        
        # Run again
        try:
            run_initial_seed()
        except Exception as e:
            self.fail(f"Re-running seeders raised exception: {e}")
            
        # Count shouldn't double (Checking Master Realm)
        self.assertEqual(Realm.query.filter_by(name='master').count(), 1)

if __name__ == '__main__':
    unittest.main()
