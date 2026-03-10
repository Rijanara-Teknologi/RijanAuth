import pytest
from apps.models import db, User, Realm

def test_cross_realm_isolation(client, app):
    """Test that users in one realm cannot access or interfere with another realm"""
    with app.app_context():
        # Setup Realm A and User A
        realm_a = Realm(name='realm-a', display_name='Realm A')
        db.session.add(realm_a)
        db.session.commit()
        
        user_a = User(realm_id=realm_a.id, username='user_a', email='a@test.domain')
        user_a.set_password('pass123')
        db.session.add(user_a)
        
        # Setup Realm B and User B
        realm_b = Realm(name='realm-b', display_name='Realm B')
        db.session.add(realm_b)
        db.session.commit()
        
        user_b = User(realm_id=realm_b.id, username='user_b', email='b@test.domain')
        user_b.set_password('pass123')
        db.session.add(user_b)
        db.session.commit()

        # Login to Realm A
        response_a = client.post(f'/auth/realms/{realm_a.name}/login', data={
            'username': 'user_a',
            'password': 'pass123'
        })
        
        # We expect a success or redirect here depending on UI implementation
        # The key concept is that token/session for Realm A is not valid for Realm B
        
        # Attempt to access Realm B profile with Realm A session/token
        # Ensure it returns 401 or 403
        response_b_access = client.get(f'/auth/realms/{realm_b.name}/account')
        
        assert response_b_access.status_code in [401, 403, 302]  # Should deny or redirect to login
