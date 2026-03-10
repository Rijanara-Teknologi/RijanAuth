import pytest

def test_session_persistence_after_login(client, test_user):
    """Critical: Verify session cookie is properly set after login (v2.1.2 fix)"""
    response = client.post('/auth/login', data={
        'username': test_user.username,
        'password': 'testpassword123!'
    }, follow_redirects=False)
    
    # Verify 302 redirect to admin
    assert response.status_code == 302
    assert '/admin/' in response.headers.get('Location', '')
    
    # Verify session cookie was set
    assert 'session' in response.headers.get('Set-Cookie', '')
    
    # Verify subsequent request maintains authentication
    admin_response = client.get('/admin/', follow_redirects=False)
    assert admin_response.status_code == 200  # NOT 302 redirect to login

def test_login_invalid_credentials(client, test_user):
    """Verify login fails with invalid credentials"""
    response = client.post('/auth/login', data={
        'username': test_user.username,
        'password': 'wrongpassword'
    }, follow_redirects=False)
    
    # Must NOT authenticate user or redirect
    assert response.status_code == 200
    assert b'Invalid username or password' in response.data or b'Invalid credentials' in response.data
    
    # Verify no session cookie set
    assert 'session' not in response.headers.get('Set-Cookie', '')
