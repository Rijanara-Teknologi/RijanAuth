import pytest
from apps import create_app, db
from apps.models import User, Realm, Client, Credential
from apps.seeders import run_initial_seed
from apps.utils.crypto import hash_password
import os
import tempfile

@pytest.fixture(scope='session')
def app():
    """Create application for the tests."""
    db_fd, db_path = tempfile.mkstemp(suffix='.sqlite3')
    os.close(db_fd)
    
    config = {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'test-secret-key',
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_SECURE': False
    }
    
    app = create_app(config)
    
    with app.app_context():
        db.create_all()
        run_initial_seed()  # Initialize with master realm and admin user
        
        # Override the random admin password with a known test password
        master_realm = Realm.query.filter_by(name='master').first()
        admin = User.query.filter_by(username='admin', realm_id=master_realm.id).first()
        if admin:
            # Delete old credentials
            for cred in admin.credentials:
                db.session.delete(cred)
            db.session.flush()
            
            # Add known credential
            pwd_hash = hash_password('testadmin123!')
            new_cred = Credential.create_password(admin.id, pwd_hash)
            db.session.add(new_cred)
            db.session.commit()
            
        yield app
    
    # Clean up database connections to avoid file lock errors on Windows
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
        
    try:
        os.unlink(db_path)
    except PermissionError:
        pass # Handle Windows file locking during teardown

@pytest.fixture
def client(app):
    """Test client for the application."""
    return app.test_client()

@pytest.fixture
def test_realm(app):
    """Create a test realm for testing."""
    from apps.services.realm_service import RealmService
    # Make sure we import RealmService from the actual location
    # If the service doesn't exist yet, we'll create the model directly:
    
    # Try looking if there's an existing test realm
    with app.app_context():
        realm = Realm.query.filter_by(name='test-realm').first()
        if not realm:
            realm = Realm(
                name='test-realm',
                display_name='Test Realm',
                enabled=True
            )
            db.session.add(realm)
            db.session.commit()
        yield realm

@pytest.fixture
def admin_user(app):
    """Get the admin user from the master realm."""
    with app.app_context():
        master = Realm.query.filter_by(name='master').first()
        admin = User.query.filter_by(username='admin', realm_id=master.id).first()
        yield admin

@pytest.fixture
def test_user(app, test_realm):
    """Create a test user in the test realm."""
    with app.app_context():
        # Check if exists
        user = User.query.filter_by(username='testuser', realm_id=test_realm.id).first()
        if not user:
            user = User(
                realm_id=test_realm.id,
                username='testuser',
                email='testuser@rijanauth.test',
                enabled=True,
                email_verified=True
            )
            db.session.add(user)
            db.session.flush() # flush to get user.id
            
            pwd_hash = hash_password('testpassword123!')
            cred = Credential.create_password(user.id, pwd_hash)
            db.session.add(cred)
            db.session.commit()
            
        yield user

@pytest.fixture
def test_client(app, test_realm):
    """Create a test OIDC client."""
    with app.app_context():
        # Check if exists
        oidc_client = Client.query.filter_by(client_id='test-client', realm_id=test_realm.id).first()
        if not oidc_client:
            oidc_client = Client(
                realm_id=test_realm.id,
                client_id='test-client',
                name='Test Client',
                enabled=True,
                client_authenticator_type='client-secret',
                protocol='openid-connect',
                redirect_uris='["http://localhost:8080/callback"]'
            )
            db.session.add(oidc_client)
            db.session.commit()
            
        yield oidc_client
