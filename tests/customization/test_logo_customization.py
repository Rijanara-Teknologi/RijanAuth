"""
Logo Customization Tests
Validate logo and background upload handlers, position persistence, and model constraints.
"""
import io
import pytest
from apps import db
from apps.models.customization import RealmPageCustomization, MediaAsset


def get_test_image():
    """Returns a valid 1x1 transparent PNG in-memory file for testing uploads."""
    # 1x1 transparent PNG
    png_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
    return io.BytesIO(png_data)


def test_logo_position_options(app, test_realm):
    """Verify that valid logo positions are stored correctly."""
    with app.app_context():
        for position in ('center', 'top', 'bottom'):
            c = RealmPageCustomization.get_or_create(test_realm.id, 'login')
            c.logo_position = position
            db.session.commit()

            refreshed = RealmPageCustomization.get(test_realm.id, 'login')
            assert refreshed.logo_position == position


def test_logo_customization_to_dict(app, test_realm):
    """Verify to_dict includes logo fields."""
    with app.app_context():
        c = RealmPageCustomization.get_or_create(test_realm.id, 'login')
        d = c.to_dict()
        assert 'logo_id' in d
        assert 'logo_position' in d
        assert d['logo_position'] in ('center', 'top', 'bottom')


class TestLogoUploads:
    """Verifies the /admin/<realm>/branding/upload-logo functionality."""

    def test_upload_valid_logo(self, authenticated_client, app, test_realm):
        """Uploading a valid PNG should create a MediaAsset and link it."""
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        data = {
            'logo': (get_test_image(), 'test_logo.png'),
            'page_type': 'login'
        }

        response = authenticated_client.post(
            f'/admin/{realm_name}/branding/upload-logo',
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True
        )

        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            assert c.logo_id is not None
            asset = MediaAsset.find_by_id(c.logo_id)
            assert asset is not None
            assert asset.asset_type == 'logo'
            assert asset.original_filename == 'test_logo.png'

    def test_remove_logo(self, authenticated_client, app, test_realm):
        """Removing a logo should clear the logo_id and delete the asset."""
        # Setup: upload a logo first
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        authenticated_client.post(
            f'/admin/{realm_name}/branding/upload-logo',
            data={'logo': (get_test_image(), 'test_logo.png')},
            content_type='multipart/form-data',
            follow_redirects=True
        )

        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            asset_id = c.logo_id
            assert asset_id is not None

        # Action: Remove logo
        authenticated_client.post(
            f'/admin/{realm_name}/branding/remove-logo',
            data={'page_type': 'login'},
            follow_redirects=True
        )

        # Verification
        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            assert c.logo_id is None
            # Ensure asset is deleted from db
            assert MediaAsset.find_by_id(asset_id) is None


class TestBackgroundUploads:
    """Verifies the /admin/<realm>/branding/upload-background functionality."""

    def test_upload_valid_background(self, authenticated_client, app, test_realm):
        """Uploading a valid PNG background should update background_type to 'image'."""
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        data = {
            'background': (get_test_image(), 'bg.png'),
            'page_type': 'login'
        }

        authenticated_client.post(
            f'/admin/{realm_name}/branding/upload-background',
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True
        )

        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            assert c.background_image_id is not None
            assert c.background_type == 'image'
            asset = MediaAsset.find_by_id(c.background_image_id)
            assert asset is not None
            assert asset.asset_type == 'background'

    def test_remove_background(self, authenticated_client, app, test_realm):
        """Removing background should reset background_type to 'color'."""
        with app.app_context():
            realm_name = test_realm.name
            realm_id = test_realm.id

        authenticated_client.post(
            f'/admin/{realm_name}/branding/upload-background',
            data={'background': (get_test_image(), 'bg.png')},
            content_type='multipart/form-data',
            follow_redirects=True
        )

        authenticated_client.post(
            f'/admin/{realm_name}/branding/remove-background',
            data={'page_type': 'login'},
            follow_redirects=True
        )

        with app.app_context():
            c = RealmPageCustomization.get(realm_id, 'login')
            assert c.background_image_id is None
            assert c.background_type == 'color'
