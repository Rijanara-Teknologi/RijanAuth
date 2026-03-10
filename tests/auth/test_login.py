import pytest

def test_session_persistence_after_login(client, admin_user):
    """Critical: Verify session cookie is properly set after login (v2.1.2 fix)"""
    response = client.post('/auth/login', data={
        'username': admin_user.username,
        'password': 'testadmin123!'
    }, follow_redirects=False)
    
    # Verify 302 redirect to admin
    assert response.status_code == 302
    assert '/admin/' in response.headers.get('Location', '')
    
    # Verify session cookie was set
    set_cookie = response.headers.get('Set-Cookie', '')
    assert 'session=' in set_cookie or 'remember_token=' in set_cookie
    
    # Verify subsequent request maintains authentication
    # Should redirect to default realm dashboard (master)
    admin_response = client.get('/admin/', follow_redirects=False)
    assert admin_response.status_code == 302
    assert '/admin/master/dashboard' in admin_response.headers.get('Location', '')

def test_login_invalid_credentials(client, admin_user):
    """Verify login fails with invalid credentials"""
    response = client.post('/auth/login', data={
        'username': admin_user.username,
        'password': 'wrongpassword'
    }, follow_redirects=False)
    
    # Must NOT authenticate user or redirect
    assert response.status_code == 200
    assert b'Invalid username or password' in response.data or b'Invalid credentials' in response.data
    
    # Verify no session cookie set
    set_cookie = response.headers.get('Set-Cookie', '')
    assert 'session=' not in set_cookie and 'remember_token=' not in set_cookie
