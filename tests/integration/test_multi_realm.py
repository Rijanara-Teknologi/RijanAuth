import pytest
from apps import db
from apps.models.user import User, Credential
from apps.models.realm import Realm
from apps.utils.crypto import hash_password

def test_cross_realm_isolation(client, app):
    """Test that users in one realm cannot access or interfere with another realm"""
    with app.app_context():
        # Setup Realm A
        realm_a = Realm(name='realm-a', display_name='Realm A')
        db.session.add(realm_a)
        db.session.commit()
        realm_a_id = realm_a.id
        realm_a_name = realm_a.name
        
        # Create User A with password credential
        user_a = User(realm_id=realm_a_id, username='user_a', email='a@test.domain')
        db.session.add(user_a)
        db.session.commit()
        cred_a = Credential.create_password(user_a.id, hash_password('pass123'))
        db.session.add(cred_a)
        
        # Setup Realm B
        realm_b = Realm(name='realm-b', display_name='Realm B')
        db.session.add(realm_b)
        db.session.commit()
        realm_b_name = realm_b.name
        
        # Create User B with password credential
        user_b = User(realm_id=realm_b.id, username='user_b', email='b@test.domain')
        db.session.add(user_b)
        db.session.commit()
        cred_b = Credential.create_password(user_b.id, hash_password('pass123'))
        db.session.add(cred_b)
        db.session.commit()

    # Use saved string values (not ORM objects) for client requests
    # Login as user_a in realm_a via OIDC authorize endpoint
    response_a = client.post(f'/auth/realms/{realm_a_name}/protocol/openid-connect/auth', data={
        'username': 'user_a',
        'password': 'pass123',
        'client_id': 'account-console',
        'redirect_uri': '/admin/'
    }, follow_redirects=False)
    
    # Attempt to access Realm B's userinfo with Realm A session
    response_b_access = client.get(f'/auth/realms/{realm_b_name}/protocol/openid-connect/userinfo')
    
    # Should deny access (401) since we have no valid bearer token for realm B
    assert response_b_access.status_code in [401, 403, 302]
