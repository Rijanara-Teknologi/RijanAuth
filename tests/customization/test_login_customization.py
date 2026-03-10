"""
Login Page Customization Tests
Verify that realm branding settings are saved, rendered, and applied correctly.
"""
import pytest
from apps import db
from apps.models.customization import RealmPageCustomization
from apps.utils.customization_renderer import (
    get_page_customization,
    get_customization_css_variables,
    get_customization_background_style,
)


class TestBrandingSave:
    """Tests that POST to /admin/<realm>/branding persists customization."""

    def test_branding_saves_colors(self, authenticated_client, app, test_realm):
        """Verify primary and secondary colors are saved correctly."""
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        authenticated_client.post(
            f'/admin/{realm_name}/branding',
            data={
                'background_type': 'color',
                'background_color': '#0066cc',
                'primary_color': '#ff6600',
                'secondary_color': '#339966',
            },
            follow_redirects=True,
        )

        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            assert c is not None
            assert c.primary_color == '#ff6600'
            assert c.secondary_color == '#339966'
            assert c.background_color == '#0066cc'

    def test_branding_saves_gradient_background(self, authenticated_client, app, test_realm):
        """Verify gradient background type is saved with colors and direction."""
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        authenticated_client.post(
            f'/admin/{realm_name}/branding',
            data={
                'background_type': 'gradient',
                'gradient_colors[]': ['#673AB7', '#3F51B5'],
                'gradient_direction': 'to right',
                'primary_color': '#673AB7',
                'secondary_color': '#3F51B5',
            },
            follow_redirects=True,
        )

        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            assert c is not None
            assert c.background_type == 'gradient'
            grad = c.get_background_gradient_dict()
            assert grad is not None
            assert '#673AB7' in grad['colors']
            assert grad['direction'] == 'to right'

    def test_branding_saves_logo_position(self, authenticated_client, app, test_realm):
        """Verify logo position is persisted."""
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        for position in ('center', 'top', 'bottom'):
            authenticated_client.post(
                f'/admin/{realm_name}/branding',
                data={
                    'background_type': 'color',
                    'primary_color': '#673AB7',
                    'secondary_color': '#3F51B5',
                    'logo_position': position,
                },
                follow_redirects=True,
            )

            with app.app_context():
                c = RealmPageCustomization.get(realm_id, 'login')
                assert c.logo_position == position

    def test_branding_saves_custom_css_sanitized(self, authenticated_client, app, test_realm):
        """Verify custom CSS is stored after sanitization."""
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        authenticated_client.post(
            f'/admin/{realm_name}/branding',
            data={
                'background_type': 'color',
                'primary_color': '#673AB7',
                'secondary_color': '#3F51B5',
                'custom_css': "body { background: url('javascript:alert(1)') }",
            },
            follow_redirects=True,
        )

        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            assert c.custom_css is not None
            assert 'javascript:' not in c.custom_css


class TestDefaultValues:
    """Tests for default customization values."""

    def test_get_or_create_returns_defaults(self, app, test_realm):
        """get_or_create should create a record with default values."""
        with app.app_context():
            c = RealmPageCustomization.get_or_create(test_realm.id, 'login')
            assert c.background_type == 'color'
            assert c.primary_color == '#673AB7'
            assert c.secondary_color == '#3F51B5'
            assert c.logo_position == 'center'
            assert c.button_radius == 4

    def test_renderer_default_customization(self, app, test_realm):
        """get_page_customization returns sensible defaults for uncustomized realms."""
        with app.app_context():
            custom = get_page_customization(test_realm.id, 'login')
            assert custom['primary_color'] == '#673AB7'
            assert custom['font_family'].startswith('Inter')


class TestRendererOutput:
    """Tests for customization_renderer utility functions."""

    def test_css_variables_output(self, app, login_customization):
        """get_customization_css_variables returns proper CSS variable declarations."""
        with app.app_context():
            custom_dict = get_page_customization(login_customization.realm_id, 'login')
            css = get_customization_css_variables(custom_dict)
            assert '--primary-color:' in css
            assert '--secondary-color:' in css
            assert '--button-radius:' in css
            assert '--font-family:' in css

    @pytest.mark.parametrize("bg_type,expected_fragment", [
        ('color', 'background-color:'),
        ('gradient', 'linear-gradient'),
    ])
    def test_background_style_output(self, bg_type, expected_fragment):
        """get_customization_background_style generates correct CSS for each type."""
        custom_dict = {
            'background_type': bg_type,
            'background_color': '#0066cc',
            'background_gradient': {
                'colors': ['#673AB7', '#3F51B5'],
                'direction': 'to right',
            },
            'background_image_url': None,
        }
        style = get_customization_background_style(custom_dict)
        assert expected_fragment in style


class TestUIRendering:
    """Tests that the customization settings are actually rendered into the HTML."""

    def test_login_page_renders_custom_css(self, client, app):
        """Verify that the login page HTML includes the customized CSS variables."""
        # Create customization for master realm since /auth/login hardcodes master realm
        from apps.models.realm import Realm
        with app.app_context():
            master_realm = Realm.find_by_name('master')
            c = RealmPageCustomization.get_or_create(master_realm.id, 'login')
            c.primary_color = '#673AB7'
            c.secondary_color = '#3F51B5'
            c.button_radius = 4
            c.background_type = 'color'
            c.background_color = '#0066cc'
            db.session.commit()

        login_response = client.get('/auth/login', follow_redirects=True)
        
        html = login_response.data.decode('utf-8')
        
        # The CSS variables should be in a style block
        assert '--primary-color: #673AB7' in html
        assert '--secondary-color: #3F51B5' in html
        assert '--button-radius: 4px' in html
        assert 'background-color: #0066cc' in html
