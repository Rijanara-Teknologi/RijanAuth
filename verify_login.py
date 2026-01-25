
from apps import create_app
from apps.models.user import User
from apps.models.realm import Realm

try:
    from apps.config import config_dict
    app = create_app(config_dict['Debug'])
    
    with app.app_context():
        username = 'admin'
        password = '_osnR8GKj1Cdv6FKZ8pmwg'
        
        print(f"Testing login for {username}")
        master = Realm.find_by_name('master')
        print(f"Master realm: {master}")
        
        if master:
            user = User.find_by_username(master.id, username)
            print(f"User found: {user}")
            if user:
                print(f"Enabled: {user.enabled}")
                cred = user.get_password_credential()
                print(f"Credential: {cred}")
                if cred:
                     print(f"Hash: {cred.secret_data[:10]}...")
                     res = user.verify_password(password)
                     print(f"Verify result: {res}")
                else:
                     print("No credential found")
            else:
                print("User not found")
        else:
            print("Realm not found")
            
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
