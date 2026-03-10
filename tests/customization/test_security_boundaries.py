"""
Security Boundary Tests for Login Page Customization
XSS prevention, realm isolation, authentication requirements.
"""
import pytest
from apps import db
from apps.models.customization import RealmPageCustomization
from apps.models.realm import Realm
from apps.utils.css_sanitizer import CSSSanitizer


class TestXSSPrevention:
    """Verify CSS sanitizer strips dangerous payloads."""

    @pytest.mark.parametrize("payload", [
        "body { background: url('javascript:alert(1)') }",
        '<script>alert(1)</script>',
        'body { -moz-binding: url("evil.xml") }',
        'div { behavior: url(xss.htc) }',
        '@import url("https://evil.com/hack.css");',
        'a { background: expression(alert(1)) }',
    ])
    def test_xss_payloads_sanitized(self, payload):
        """Dangerous patterns are removed from custom CSS."""
        sanitized, warnings = CSSSanitizer.sanitize(payload)
        assert 'javascript:' not in sanitized.lower()
        assert '<script' not in sanitized.lower()
        assert 'expression(' not in sanitized.lower()
        assert '-moz-binding' not in sanitized.lower()
        assert 'behavior:' not in sanitized.lower()
        assert '@import' not in sanitized.lower()


class TestRealmIsolation:
    """Verify customizations are scoped per realm."""

    def test_cross_realm_customization_isolation(self, app, test_realm):
        """Realm A's customization does not leak into Realm B."""
        with app.app_context():
            # Create customization for test realm
            c_a = RealmPageCustomization.get_or_create(test_realm.id, 'login')
            c_a.primary_color = '#ff0000'
            db.session.commit()

            # Create another realm
            realm_b = Realm(name='branding-test-b', display_name='Realm B')
            db.session.add(realm_b)
            db.session.commit()
            realm_b_id = realm_b.id

            # Realm B should have default (no customization)
            c_b = RealmPageCustomization.get(realm_b_id, 'login')
            assert c_b is None  # No customization has been set


class TestAuthRequired:
    """Verify branding routes require authentication."""

    def test_branding_requires_auth(self, client, app, test_realm):
        """Unauthenticated access to branding page should redirect to login."""
        with app.app_context():
            realm_name = test_realm.name

        response = client.get(f'/admin/{realm_name}/branding', follow_redirects=False)
        # Should redirect to login (302) or return 401
        assert response.status_code in (302, 401)

    def test_branding_post_requires_auth(self, client, app, test_realm):
        """Unauthenticated POST to branding should be rejected."""
        with app.app_context():
            realm_name = test_realm.name

        response = client.post(
            f'/admin/{realm_name}/branding',
            data={'primary_color': '#ff0000'},
            follow_redirects=False,
        )
        assert response.status_code in (302, 401)


class TestRealmNameProtection:
    """Verify realm identity cannot be spoofed through branding."""

    def test_branding_ignores_realm_name_field(self, authenticated_client, app, test_realm):
        """POST with realm_name field should not change the realm's display name."""
        with app.app_context():
            realm_name = test_realm.name
            original_display = test_realm.display_name

        authenticated_client.post(
            f'/admin/{realm_name}/branding',
            data={
                'realm_name': 'Hacked Realm',
                'display_name': 'Hacked Realm',
                'background_type': 'color',
                'primary_color': '#673AB7',
                'secondary_color': '#3F51B5',
            },
            follow_redirects=True,
        )

        with app.app_context():
            realm = Realm.query.filter_by(name=realm_name).first()
            assert realm.display_name == original_display
            assert realm.display_name != 'Hacked Realm'
