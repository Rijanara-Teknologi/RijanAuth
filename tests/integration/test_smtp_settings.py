"""
Tests for SMTP Email settings in Realm settings page.

Verifies that:
- All SMTP fields are saved when the settings form is submitted
- Existing SMTP password is preserved when a blank password is submitted
- Test-email route rejects missing SMTP host gracefully
"""
import pytest
from apps import db
from apps.models.realm import Realm
from apps.services.realm_service import RealmService


def _login_admin(client):
    client.post('/auth/login', data={
        'username': 'admin',
        'password': 'testadmin123!',
    }, follow_redirects=True)


def _settings_url(realm_name):
    return f'/admin/{realm_name}/settings'


def _base_form(realm):
    """Return minimum valid settings form data."""
    return {
        'display_name': realm.display_name or '',
        'enabled': 'on',
    }


class TestSmtpSettings:

    def test_all_smtp_fields_saved(self, client, app):
        """Submitting all SMTP fields persists every field to the database."""
        with app.app_context():
            realm = RealmService.create_realm('smtp-test-realm1', 'SMTP Test 1')
            realm_name = realm.name

        try:
            _login_admin(client)
            with app.app_context():
                realm = Realm.find_by_name(realm_name)
                form = _base_form(realm)

            form.update({
                'smtp_host': 'smtp.example.com',
                'smtp_port': '587',
                'smtp_from': 'noreply@example.com',
                'smtp_from_display_name': 'My App',
                'smtp_reply_to': 'support@example.com',
                'smtp_reply_to_display_name': 'Support Team',
                'smtp_ssl': 'on',
                'smtp_starttls': 'on',
                'smtp_auth': 'on',
                'smtp_user': 'smtpuser@example.com',
                'smtp_password': 's3cr3t',
            })

            resp = client.post(_settings_url(realm_name), data=form, follow_redirects=False)
            assert resp.status_code == 302

            with app.app_context():
                r = Realm.find_by_name(realm_name)
                assert r.smtp_server == 'smtp.example.com'
                assert r.smtp_port == '587'
                assert r.smtp_from == 'noreply@example.com'
                assert r.smtp_from_display_name == 'My App'
                assert r.smtp_reply_to == 'support@example.com'
                assert r.smtp_reply_to_display_name == 'Support Team'
                assert r.smtp_ssl is True
                assert r.smtp_starttls is True
                assert r.smtp_auth is True
                assert r.smtp_user == 'smtpuser@example.com'
                assert r.smtp_password == 's3cr3t'
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_blank_password_preserves_existing(self, client, app):
        """Submitting an empty password field must NOT overwrite an existing password."""
        with app.app_context():
            realm = RealmService.create_realm('smtp-test-realm2', 'SMTP Test 2')
            realm_name = realm.name
            realm.smtp_server = 'smtp.example.com'
            realm.smtp_auth = True
            realm.smtp_user = 'user@example.com'
            realm.smtp_password = 'original_pass'
            db.session.commit()

        try:
            _login_admin(client)
            with app.app_context():
                realm = Realm.find_by_name(realm_name)
                form = _base_form(realm)

            form.update({
                'smtp_host': 'smtp.example.com',
                'smtp_port': '25',
                'smtp_from': 'noreply@example.com',
                'smtp_auth': 'on',
                'smtp_user': 'user@example.com',
                'smtp_password': '',   # blank — should keep existing
            })

            client.post(_settings_url(realm_name), data=form, follow_redirects=True)

            with app.app_context():
                r = Realm.find_by_name(realm_name)
                assert r.smtp_password == 'original_pass', (
                    "Empty password submission must not erase the existing password"
                )
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_smtp_checkboxes_off_when_unchecked(self, client, app):
        """SSL/STARTTLS/Auth toggles must be saved as False when not submitted."""
        with app.app_context():
            realm = RealmService.create_realm('smtp-test-realm3', 'SMTP Test 3')
            realm_name = realm.name
            realm.smtp_ssl = True
            realm.smtp_starttls = True
            realm.smtp_auth = True
            db.session.commit()

        try:
            _login_admin(client)
            with app.app_context():
                realm = Realm.find_by_name(realm_name)
                form = _base_form(realm)
            # Deliberately omit smtp_ssl, smtp_starttls, smtp_auth checkboxes
            form.update({'smtp_host': '', 'smtp_port': '25', 'smtp_from': ''})
            client.post(_settings_url(realm_name), data=form, follow_redirects=True)

            with app.app_context():
                r = Realm.find_by_name(realm_name)
                assert r.smtp_ssl is False
                assert r.smtp_starttls is False
                assert r.smtp_auth is False
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_test_email_no_smtp_host_flashes_error(self, client, app):
        """Sending a test email when SMTP host is not set must redirect with no crash."""
        with app.app_context():
            realm = RealmService.create_realm('smtp-test-realm4', 'SMTP Test 4')
            realm_name = realm.name

        try:
            _login_admin(client)
            resp = client.post(
                f'/admin/{realm_name}/settings/test-email',
                data={'test_email_recipient': 'someone@example.com'},
                follow_redirects=False,
            )
            # Must redirect (not 500) and stay on the settings page
            assert resp.status_code == 302
            assert f'/admin/{realm_name}/settings' in resp.headers.get('Location', '')
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_test_email_no_recipient_flashes_error(self, client, app):
        """Sending a test email without a recipient must redirect with no crash."""
        with app.app_context():
            realm = RealmService.create_realm('smtp-test-realm5', 'SMTP Test 5')
            realm_name = realm.name

        try:
            _login_admin(client)
            resp = client.post(
                f'/admin/{realm_name}/settings/test-email',
                data={'test_email_recipient': ''},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert f'/admin/{realm_name}/settings' in resp.headers.get('Location', '')
        finally:
            with app.app_context():
                r = Realm.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()
