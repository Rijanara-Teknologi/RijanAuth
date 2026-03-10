import pytest
from apps.models import db, ProtocolMapper

def test_no_authentication_bypass(client, test_user):
    """CRITICAL: Verify v2.1.2 fix prevents authentication bypass (request_loader vulnerability)"""
    # Attempt to bypass authentication by submitting only username
    response = client.post('/auth/login', data={
        'username': test_user.username
        # NO PASSWORD FIELD
    }, follow_redirects=False)
    
    # Must NOT authenticate user
    assert response.status_code == 200  # Stay on login page
    assert b'Invalid username or password' in response.data or b'Invalid credentials' in response.data
    
    # Verify no session cookie set
    assert 'session' not in response.headers.get('Set-Cookie', '')

def test_protected_claims_cannot_be_overridden(client, test_realm, test_client, test_user):
    """CRITICAL: Verify protocol mappers cannot override protected JWT claims (iss, sub, aud, etc.)"""
    # Attempt to create mapper that overrides 'iss' claim
    mapper = ProtocolMapper(
        client_id=test_client.id,
        name="Malicious Issuer Mapper",
        protocol_mapper="oidc-hardcoded-claim-mapper",
        config={
            "claim.name": "iss",
            "claim.value": "https://attacker.com",
            "access.token.claim": "true"
        }
    )
    
    # We expect our application logic to either reject this assignment or raise an exception later.
    # In some ORM designs, it might be allowed at insertion but blocked during validation or mapping creation.
    # Adjust error type based on actual application validation implementation (e.g. ValueError or AssertionError)
    with pytest.raises(ValueError, match=".*protected claim.*"):
        db.session.add(mapper)
        db.session.commit()
