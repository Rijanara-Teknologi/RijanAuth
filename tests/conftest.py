import pytest
from apps import create_app
from apps.models import db, User, Realm, Client
from apps.seeders import run_initial_seed
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
        
        yield app
    
    os.unlink(db_path)

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
    return realm

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
            user.set_password('testpassword123!')
            db.session.add(user)
            db.session.commit()
            return user
        return user

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
            return oidc_client
        return oidc_client
