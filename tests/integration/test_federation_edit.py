"""
Integration tests for the user federation edit page.

Verifies that:
- The edit page for all 3 provider types (ldap, mysql, postgresql) renders with
  correct CSS (ASSETS_ROOT is not shadowed by the provider_config variable).
- All provider-specific fields are present and pre-populated with stored values.
- Saving from the edit form with an empty password field preserves the
  existing encrypted password.
"""
import os
import tempfile
import pytest
from apps import create_app, db as _db
from apps.models.realm import Realm
from apps.models.user import User, Credential
from apps.models.federation import UserFederationProvider
from apps.services.federation import FederationService
from apps.seeders import run_initial_seed
from apps.utils.crypto import hash_password


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def fed_app():
    """App instance with ASSETS_ROOT configured for CSS-specific federation tests."""
    db_fd, db_path = tempfile.mkstemp(suffix='.fed_test.sqlite3')
    os.close(db_fd)

    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'fed-test-secret',
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_SECURE': False,
        'ASSETS_ROOT': '/static/assets',
    })

    with app.app_context():
        _db.create_all()
        run_initial_seed()

        master_realm = Realm.query.filter_by(name='master').first()
        admin = User.query.filter_by(username='admin', realm_id=master_realm.id).first()
        for cred in admin.credentials:
            _db.session.delete(cred)
        _db.session.flush()
        new_cred = Credential.create_password(admin.id, hash_password('testadmin123!'))
        _db.session.add(new_cred)
        _db.session.commit()

    yield app

    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture()
def fed_client(fed_app):
    return fed_app.test_client()


def _login_admin(client_fixture):
    client_fixture.post('/auth/login', data={
        'username': 'admin',
        'password': 'testadmin123!',
    }, follow_redirects=True)


# ---------------------------------------------------------------------------
# CSS asset path
# ---------------------------------------------------------------------------

class TestFederationEditCss:
    """The edit page must not break CSS by shadowing Flask's config variable."""

    def _get_edit_html(self, fed_client, fed_app, provider_type, form_data):
        """Create a provider and return the edit page HTML."""
        _login_admin(fed_client)
        r = fed_client.post(
            f'/admin/master/user-federation/create/{provider_type}',
            data=form_data,
            follow_redirects=False,
        )
        assert r.status_code == 302
        provider_id = r.headers['Location'].split('/')[-1]
        r2 = fed_client.get(f'/admin/master/user-federation/{provider_id}')
        return r2, provider_id

    @pytest.fixture(autouse=True)
    def cleanup(self, fed_app):
        self._ids_to_delete = []
        yield
        with fed_app.app_context():
            for pid in self._ids_to_delete:
                p = UserFederationProvider.find_by_id(pid)
                if p:
                    _db.session.delete(p)
            _db.session.commit()

    @pytest.mark.parametrize("provider_type,form_data", [
        ("postgresql", {
            'name': 'postgresql',
            'host': 'localhost', 'port': '5432', 'database': 'db',
            'db_username': 'user', 'db_password': 'pass',
            'user_table': 'users', 'full_sync_period': '-1',
            'changed_sync_period': '-1', 'enabled': 'on', 'import_enabled': 'on',
        }),
        ("mysql", {
            'name': 'mysql',
            'host': 'localhost', 'port': '3306', 'database': 'db',
            'db_username': 'user', 'db_password': 'pass',
            'user_table': 'users', 'full_sync_period': '-1',
            'changed_sync_period': '-1', 'enabled': 'on', 'import_enabled': 'on',
        }),
        ("ldap", {
            'name': 'ldap-test',
            'connection_url': 'ldap://localhost',
            'bind_dn': '', 'bind_credential': '',
            'users_dn': 'ou=users,dc=example,dc=com',
            'full_sync_period': '-1', 'changed_sync_period': '-1',
            'enabled': 'on', 'import_enabled': 'on',
        }),
    ])
    def test_edit_page_has_correct_css_path(self, fed_client, fed_app,
                                             provider_type, form_data):
        """CSS paths must include /static/assets prefix, not be bare /css/..."""
        r, provider_id = self._get_edit_html(fed_client, fed_app,
                                              provider_type, form_data)
        self._ids_to_delete.append(provider_id)
        assert r.status_code == 200
        html = r.data.decode('utf-8')

        # The CSS link must use the configured ASSETS_ROOT
        assert 'href="/static/assets/css/style.css"' in html, (
            f"Expected '/static/assets/css/style.css' in edit page for "
            f"'{provider_type}' provider. Got bare /css/style.css path instead, "
            "which means Flask's 'config' template variable was shadowed by "
            "the provider_config dict."
        )


# ---------------------------------------------------------------------------
# Provider-specific fields
# ---------------------------------------------------------------------------

class TestFederationEditFields:
    """All provider-specific fields must be present and pre-populated."""

    def _create_and_get_html(self, client, app, provider_type, form_data, field_checks):
        """Helper: create a provider via the create form, then GET the edit page."""
        _login_admin(client)
        r = client.post(
            f'/admin/master/user-federation/create/{provider_type}',
            data=form_data,
            follow_redirects=False,
        )
        assert r.status_code == 302, f"Create failed with {r.status_code}"
        provider_id = r.headers['Location'].split('/')[-1]

        try:
            r2 = client.get(f'/admin/master/user-federation/{provider_id}')
            assert r2.status_code == 200
            html = r2.data.decode('utf-8')
            for field_name, expected_value, label in field_checks:
                assert f'name="{field_name}"' in html, (
                    f"Field '{field_name}' ({label}) not found in edit form"
                )
                if expected_value is not None:
                    assert expected_value in html, (
                        f"Expected value '{expected_value}' for field '{field_name}' "
                        f"({label}) not found in edit form"
                    )
        finally:
            with app.app_context():
                p = UserFederationProvider.find_by_id(provider_id)
                if p:
                    _db.session.delete(p)
                    _db.session.commit()

    def test_postgresql_fields_present_and_populated(self, client, app):
        self._create_and_get_html(
            client, app, 'postgresql',
            form_data={
                'name': 'postgresql',
                'display_name': 'Test PG',
                'host': 'db.example.com', 'port': '5432',
                'database': 'mydb', 'db_username': 'pguser', 'db_password': 'pgpass',
                'schema': 'myschema', 'sslmode': 'require',
                'user_table': 'accounts',
                'id_column': 'acct_id', 'username_column': 'login',
                'email_column': 'mail', 'password_column': 'pwd',
                'first_name_column': 'fname', 'last_name_column': 'lname',
                'enabled_column': 'active', 'attributes_column': 'meta',
                'password_hash_algorithm': 'sha256', 'batch_size': '50',
                'role_sync_enabled': 'on', 'role_source': 'jsonb',
                'role_column': 'data', 'role_jsonb_path': 'user.roles',
                'realm_match_field': 'username', 'external_match_column': 'login',
                'full_sync_period': '-1', 'changed_sync_period': '-1',
                'enabled': 'on', 'import_enabled': 'on',
            },
            field_checks=[
                ('schema', 'myschema', 'Schema'),
                ('sslmode', 'require', 'SSL Mode'),
                ('id_column', 'acct_id', 'ID Column'),
                ('username_column', 'login', 'Username Column'),
                ('email_column', 'mail', 'Email Column'),
                ('password_column', 'pwd', 'Password Column'),
                ('first_name_column', 'fname', 'First Name Column'),
                ('last_name_column', 'lname', 'Last Name Column'),
                ('enabled_column', 'active', 'Enabled Column'),
                ('attributes_column', 'meta', 'Attributes Column'),
                ('password_hash_algorithm', 'sha256', 'Password Hash Algorithm'),
                ('batch_size', '50', 'Batch Size'),
                ('role_sync_enabled', None, 'Role Sync Enabled'),
                ('role_jsonb_path', 'user.roles', 'JSONB Path'),
                ('external_match_column', 'login', 'External Match Column'),
            ],
        )

    def test_mysql_fields_present_and_populated(self, client, app):
        self._create_and_get_html(
            client, app, 'mysql',
            form_data={
                'name': 'mysql',
                'display_name': 'Test MySQL',
                'host': 'db.example.com', 'port': '3306',
                'database': 'mydb', 'db_username': 'mysqluser', 'db_password': 'mysqlpass',
                'user_table': 'members',
                'id_column': 'member_id', 'username_column': 'login',
                'email_column': 'mail', 'password_column': 'pwd',
                'first_name_column': 'fname', 'last_name_column': 'lname',
                'enabled_column': 'active',
                'password_hash_algorithm': 'sha512', 'batch_size': '75',
                'role_sync_enabled': 'on', 'role_source': 'table',
                'role_table': 'user_roles', 'role_user_id_column': 'uid',
                'role_name_column': 'role', 'role_delimiter': ',',
                'realm_match_field': 'username', 'external_match_column': 'login',
                'full_sync_period': '-1', 'changed_sync_period': '-1',
                'enabled': 'on', 'import_enabled': 'on',
            },
            field_checks=[
                ('id_column', 'member_id', 'ID Column'),
                ('username_column', 'login', 'Username Column'),
                ('email_column', 'mail', 'Email Column'),
                ('password_column', 'pwd', 'Password Column'),
                ('first_name_column', 'fname', 'First Name Column'),
                ('last_name_column', 'lname', 'Last Name Column'),
                ('enabled_column', 'active', 'Enabled Column'),
                ('password_hash_algorithm', 'sha512', 'Password Hash Algorithm'),
                ('batch_size', '75', 'Batch Size'),
                ('role_sync_enabled', None, 'Role Sync Enabled'),
                ('role_table', 'user_roles', 'Role Table'),
                ('role_user_id_column', 'uid', 'Role User ID Column'),
                ('role_name_column', 'role', 'Role Name Column'),
                ('external_match_column', 'login', 'External Match Column'),
            ],
        )

    def test_ldap_fields_present_and_populated(self, client, app):
        self._create_and_get_html(
            client, app, 'ldap',
            form_data={
                'name': 'ldap-test',
                'display_name': 'Test LDAP',
                'connection_url': 'ldap://ldap.example.com:389',
                'bind_dn': 'cn=admin,dc=example,dc=com',
                'bind_credential': 'ldappass',
                'use_ssl': '',
                'use_starttls': 'on',
                'connection_timeout': '45',
                'vendor': 'ad',
                'users_dn': 'ou=users,dc=example,dc=com',
                'search_scope': 'one',
                'user_object_classes': 'person,user',
                'username_ldap_attribute': 'sAMAccountName',
                'email_ldap_attribute': 'mail',
                'first_name_ldap_attribute': 'givenName',
                'last_name_ldap_attribute': 'sn',
                'batch_size': '200',
                'role_sync_enabled': 'on',
                'role_source': 'memberOf',
                'role_attribute': 'memberOf',
                'full_sync_period': '-1', 'changed_sync_period': '-1',
                'enabled': 'on', 'import_enabled': 'on',
            },
            field_checks=[
                ('use_ssl', None, 'SSL checkbox'),
                ('use_starttls', None, 'StartTLS checkbox'),
                ('connection_timeout', '45', 'Connection Timeout'),
                ('vendor', 'ad', 'Vendor'),
                ('search_scope', 'one', 'Search Scope'),
                ('user_object_classes', 'person,user', 'User Object Classes'),
                ('username_ldap_attribute', 'sAMAccountName', 'Username Attribute'),
                ('email_ldap_attribute', 'mail', 'Email Attribute'),
                ('first_name_ldap_attribute', 'givenName', 'First Name Attribute'),
                ('last_name_ldap_attribute', 'sn', 'Last Name Attribute'),
                ('batch_size', '200', 'Batch Size'),
                ('role_sync_enabled', None, 'Role Sync Enabled'),
                ('role_attribute', 'memberOf', 'Role Attribute'),
            ],
        )


# ---------------------------------------------------------------------------
# Password preservation
# ---------------------------------------------------------------------------

class TestFederationEditPasswordPreservation:
    """Saving from the edit form with an empty password field must not erase
    the stored password."""

    def test_empty_db_password_preserves_existing(self, client, app):
        _login_admin(client)
        r = client.post(
            '/admin/master/user-federation/create/postgresql',
            data={
                'name': 'postgresql',
                'display_name': 'PG Password Test',
                'host': 'localhost', 'port': '5432',
                'database': 'db', 'db_username': 'user',
                'db_password': 'original_secret',
                'user_table': 'users',
                'full_sync_period': '-1', 'changed_sync_period': '-1',
                'enabled': 'on', 'import_enabled': 'on',
            },
            follow_redirects=False,
        )
        assert r.status_code == 302
        provider_id = r.headers['Location'].split('/')[-1]

        try:
            # Save from edit page with blank password
            client.post(
                f'/admin/master/user-federation/{provider_id}',
                data={
                    'action': 'save',
                    'display_name': 'PG Password Test Updated',
                    'host': 'localhost', 'port': '5432',
                    'database': 'db', 'db_username': 'user',
                    'db_password': '',  # intentionally blank
                    'user_table': 'users',
                    'full_sync_period': '-1', 'changed_sync_period': '-1',
                    'enabled': 'on', 'import_enabled': 'on',
                },
            )

            with app.app_context():
                provider = UserFederationProvider.find_by_id(provider_id)
                decrypted = FederationService._decrypt_config(
                    provider.config, 'postgresql'
                )
                assert decrypted.get('password') == 'original_secret', (
                    "Password was overwritten when edit form field was left blank"
                )
        finally:
            with app.app_context():
                p = UserFederationProvider.find_by_id(provider_id)
                if p:
                    _db.session.delete(p)
                    _db.session.commit()

    def test_new_db_password_updates_existing(self, client, app):
        _login_admin(client)
        r = client.post(
            '/admin/master/user-federation/create/mysql',
            data={
                'name': 'mysql',
                'display_name': 'MySQL Password Test',
                'host': 'localhost', 'port': '3306',
                'database': 'db', 'db_username': 'root',
                'db_password': 'old_pass',
                'user_table': 'users',
                'full_sync_period': '-1', 'changed_sync_period': '-1',
                'enabled': 'on', 'import_enabled': 'on',
            },
            follow_redirects=False,
        )
        assert r.status_code == 302
        provider_id = r.headers['Location'].split('/')[-1]

        try:
            client.post(
                f'/admin/master/user-federation/{provider_id}',
                data={
                    'action': 'save',
                    'display_name': 'MySQL Password Test',
                    'host': 'localhost', 'port': '3306',
                    'database': 'db', 'db_username': 'root',
                    'db_password': 'new_pass',  # explicitly changed
                    'user_table': 'users',
                    'full_sync_period': '-1', 'changed_sync_period': '-1',
                    'enabled': 'on', 'import_enabled': 'on',
                },
            )

            with app.app_context():
                provider = UserFederationProvider.find_by_id(provider_id)
                decrypted = FederationService._decrypt_config(
                    provider.config, 'mysql'
                )
                assert decrypted.get('password') == 'new_pass', (
                    "Password was not updated when a new value was provided"
                )
        finally:
            with app.app_context():
                p = UserFederationProvider.find_by_id(provider_id)
                if p:
                    _db.session.delete(p)
                    _db.session.commit()

