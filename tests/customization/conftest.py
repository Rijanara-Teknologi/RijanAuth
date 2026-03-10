import pytest
from apps import db
from apps.models.customization import RealmPageCustomization, MediaAsset


@pytest.fixture
def authenticated_client(client, app, admin_user):
    """A test client that is logged in as admin."""
    with app.app_context():
        client.post('/auth/login', data={
            'username': admin_user.username,
            'password': 'testadmin123!'
        }, follow_redirects=True)
        yield client


@pytest.fixture
def login_customization(app, test_realm):
    """Create a login page customization for the test realm."""
    with app.app_context():
        customization = RealmPageCustomization.get_or_create(test_realm.id, 'login')
        customization.primary_color = '#673AB7'
        customization.secondary_color = '#3F51B5'
        customization.background_type = 'color'
        customization.background_color = '#0066cc'
        customization.logo_position = 'center'
        customization.font_family = 'Inter, system-ui, -apple-system, sans-serif'
        customization.button_radius = 4
        customization.form_radius = 4
        db.session.commit()
        yield customization
