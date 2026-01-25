"""
Login Debugging Script
Run this script to test authentication flow independently
"""

import os
import sys
from datetime import datetime
import traceback

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from apps import create_app, db
from apps.models.user import User
from apps.models.realm import Realm
from apps.models.role import Role
from apps.services.realm_service import RealmService
from apps.config import config_dict

# Load Debug configuration
conf = config_dict['Debug']
app = create_app(conf)
app.app_context().push()

def debug_login(username, password):
    """Test login flow with detailed debugging"""
    print(f"\n{'=' * 80}")
    print(f"LOGIN DEBUG: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"TARGET USER: {username}")
    print(f"{'=' * 80}\n")
    
    # 1. Check database connectivity
    try:
        realm_count = Realm.query.count()
        user_count = User.query.count()
        print(f"✓ Database connection OK")
        print(f"  • Realms in DB: {realm_count}")
        print(f"  • Users in DB: {user_count}")
    except Exception as e:
        print(f"✗ Database connection ERROR: {str(e)}")
        return
    
    # 2. Find user
    # Check master realm first
    master = Realm.find_by_name('master')
    user = None
    if master:
        user = User.find_by_username(master.id, username)
        
    if not user:
        print(f"✗ User '{username}' NOT FOUND in master realm")
        # Try generic search
        # Show all users for reference
        print("\nAvailable users in database:")
        for u in User.query.all():
            print(f"  • {u.username} (Realm: {u.realm.name if u.realm else 'None'}, ID: {u.id})")
        return
    
    print(f"✓ User '{username}' FOUND (ID: {user.id})")
    print(f"  • Realm: {user.realm.name}")
    print(f"  • Enabled: {user.enabled}")
    print(f"  • Email verified: {user.email_verified}")
    print(f"  • Created at: {user.created_at}")
    
    # 3. Check credentials
    print(f"\nVerifying password...")
    password_valid = user.verify_password(password)
    print(f"  • Password verification: {'✓ SUCCESS' if password_valid else '✗ FAILED'}")
    
    if not password_valid:
        print(f"\nPassword debugging:")
        print(f"  • Stored hash prefix: {user.password_hash[:10]}...")
    
    # 4. Check roles and permissions
    print(f"\nUser roles and permissions:")
    from apps.services.user_service import UserService
    
    # User.role_mappings is lazy='dynamic', so we need .all() or UserService
    roles = UserService.get_user_roles(user)
    
    if roles:
        for role in roles:
            print(f"  • Role: {role.name} (Realm: {role.realm.name if role.realm else 'N/A'})")
    else:
        print(f"  • WARNING: User has NO roles assigned!")
    
    # 5. Check realm access
    print(f"\nUser realm access:")
    # user.realms? relationship? Or implicitly by realm_id?
    # User usually belongs to one realm.
    print(f"  • User Realm ID: {user.realm_id}")
    
    # 6. Session simulation
    print(f"\nSimulating session creation...")
    with app.test_client() as client:
        login_data = {
            'username': username,
            'password': password
        }
        
        response = client.post('/auth/login?next=/admin/', 
                             data=login_data, 
                             follow_redirects=False)
        
        print(f"  • Login response status: {response.status_code}")
        print(f"  • Location header: {response.headers.get('Location', 'NOT SET')}")
        
        cookies = response.headers.getlist('Set-Cookie')
        print(f"  • Set-Cookie headers: {len(cookies)}")
        for c in cookies:
            print(f"    - {c[:50]}...")
            
        session_cookie_found = any('session=' in c for c in cookies)
        print(f"  • Session cookie set: {'✓ YES' if session_cookie_found else '✗ NO'}")
        
        if response.status_code == 302:
            location = response.headers['Location']
            # Follow redirect to admin
            # We must pass cookies manually if follow_redirects=False doesn't handle cookie jar automatically in manual call
            # But test_client usually has cookie jar.
            
            print(f"  • Following redirect to: {location}")
            admin_response = client.get(location)
            print(f"  • Admin page response: {admin_response.status_code}")
            
            # Check for redirect back to login
            if admin_response.status_code == 302:
                 next_loc = admin_response.headers.get('Location')
                 print(f"  • Redirected again to: {next_loc}")
                 if 'login' in next_loc:
                     print(f"  • ✗ FAILED: Redirect loop detected (Login -> Admin -> Login)")
            elif admin_response.status_code == 200:
                print(f"  • ✓ SUCCESS: Access to admin granted!")
            else:
                 print(f"  • ? Status: {admin_response.status_code}")
        
        # Print session data
        with client.session_transaction() as sess:
            print(f"\nSession data after login attempt:")
            for key, value in sess.items():
                print(f"  • {key}: {value}")

if __name__ == '__main__':
    # Default credentials to test
    username = os.environ.get('RIJANAUTH_ADMIN_USER', 'admin')
    password = os.environ.get('RIJANAUTH_ADMIN_PASSWORD', '_osnR8GKj1Cdv6FKZ8pmwg') # Using known default
    
    print(f"Testing login with username: '{username}'")
    debug_login(username, password)
