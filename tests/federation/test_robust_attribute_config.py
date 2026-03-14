# -*- coding: utf-8 -*-
"""
Tests for robust user-attribute configuration across all provider types.

Covers the changes made to make the attribute_columns pipeline work end-to-end
for PostgreSQL, MySQL, and LDAP federation providers:

1. _build_provider_config() saves attribute_columns for all three provider types.
2. LdapProvider._get_user_attributes() includes attribute_columns in the fetch list.
3. LdapProvider._parse_user_entry() only stores attribute_columns-specified
   attributes (not all LDAP system attributes).
4. User Attributes tab: api_update_user() handles individual attribute add/delete
   correctly (no data loss for untouched attributes).
"""

import pytest
from unittest.mock import MagicMock, patch

from apps import db
from apps.models.user import User, UserAttribute
from apps.models.realm import Realm
from apps.services.federation.ldap_provider import LDAPFederationProvider
from apps.services.user_service import UserService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ldap_provider(attribute_columns=''):
    """Return a minimal LDAPFederationProvider with the given config."""
    config = {
        'connection_url': 'ldap://localhost',
        'bind_dn': 'cn=admin,dc=example,dc=com',
        'bind_credential': 'secret',
        'users_dn': 'ou=users,dc=example,dc=com',
        'username_ldap_attribute': 'uid',
        'email_ldap_attribute': 'mail',
        'first_name_ldap_attribute': 'givenName',
        'last_name_ldap_attribute': 'sn',
        'full_name_ldap_attribute': 'cn',
        'attribute_columns': attribute_columns,
        'role_sync_enabled': False,
    }
    provider = MagicMock()
    provider.config = config
    provider.id = 'test-provider'
    instance = LDAPFederationProvider.__new__(LDAPFederationProvider)
    instance.provider = provider
    instance.config = config
    return instance


# ---------------------------------------------------------------------------
# 1. _build_provider_config — attribute_columns saved for all provider types
# ---------------------------------------------------------------------------

class TestBuildProviderConfig:
    """Ensure _build_provider_config() persists attribute_columns from the form."""

    def _call(self, provider_type, extra_form=None):
        from apps.blueprints.admin.routes import _build_provider_config
        form = {
            'host': 'localhost',
            'port': str(3306 if provider_type == 'mysql' else 5432),
            'database': 'testdb',
            'db_username': 'user',
            'db_password': 'pass',
            'connection_url': 'ldap://localhost',
            'bind_dn': 'cn=admin',
            'bind_credential': 'secret',
            'users_dn': 'ou=users',
            'username_ldap_attribute': 'uid',
            'email_ldap_attribute': 'mail',
            'first_name_ldap_attribute': 'givenName',
            'last_name_ldap_attribute': 'sn',
        }
        if extra_form:
            form.update(extra_form)
        return _build_provider_config(provider_type, form)

    def test_postgresql_attribute_columns_saved(self):
        cfg = self._call('postgresql', {'attribute_columns': 'photo,phone,department'})
        assert cfg['attribute_columns'] == 'photo,phone,department'

    def test_postgresql_attributes_column_saved(self):
        """JSONB column key should also be preserved."""
        cfg = self._call('postgresql', {'attributes_column': 'extra_attrs'})
        assert cfg['attributes_column'] == 'extra_attrs'

    def test_mysql_attribute_columns_saved(self):
        cfg = self._call('mysql', {'attribute_columns': 'photo,job_title'})
        assert cfg['attribute_columns'] == 'photo,job_title'

    def test_mysql_attribute_columns_empty_by_default(self):
        cfg = self._call('mysql')
        assert cfg.get('attribute_columns', '') == ''

    def test_ldap_attribute_columns_saved(self):
        cfg = self._call('ldap', {'attribute_columns': 'jpegPhoto,telephoneNumber'})
        assert cfg['attribute_columns'] == 'jpegPhoto,telephoneNumber'

    def test_ldap_attribute_columns_empty_by_default(self):
        cfg = self._call('ldap')
        assert cfg.get('attribute_columns', '') == ''


# ---------------------------------------------------------------------------
# 2. LdapProvider._get_user_attributes — includes attribute_columns
# ---------------------------------------------------------------------------

class TestLdapGetUserAttributes:
    """Ensure custom attribute_columns are requested from LDAP."""

    def test_no_custom_columns_has_standard_attrs(self):
        p = _ldap_provider('')
        attrs = p._get_user_attributes()
        assert 'uid' in attrs
        assert 'mail' in attrs
        assert 'givenName' in attrs

    def test_custom_columns_added_to_fetch_list(self):
        p = _ldap_provider('jpegPhoto,telephoneNumber,department')
        attrs = p._get_user_attributes()
        assert 'jpegPhoto' in attrs
        assert 'telephoneNumber' in attrs
        assert 'department' in attrs

    def test_duplicate_columns_not_added_twice(self):
        # 'mail' is already in standard attrs; adding it via attribute_columns
        # must not create a duplicate.
        p = _ldap_provider('mail,department')
        attrs = p._get_user_attributes()
        assert attrs.count('mail') == 1
        assert 'department' in attrs

    def test_whitespace_trimmed_in_column_list(self):
        p = _ldap_provider(' jpegPhoto , telephoneNumber ')
        attrs = p._get_user_attributes()
        assert 'jpegPhoto' in attrs
        assert 'telephoneNumber' in attrs


# ---------------------------------------------------------------------------
# 3. LdapProvider._parse_user_entry — only stores attribute_columns attrs
# ---------------------------------------------------------------------------

class TestLdapParseUserEntryAttributes:
    """Only attribute_columns-specified LDAP attributes end up in 'attributes'."""

    def _make_entry(self, extra_attrs=None):
        """Build a minimal mock LDAP entry."""
        base = {
            'uid': ['jdoe'],
            'entryUUID': ['uuid-123'],
            'mail': ['jdoe@example.com'],
            'givenName': ['John'],
            'sn': ['Doe'],
            'cn': ['John Doe'],
            'objectClass': ['inetOrgPerson', 'top'],
            'userAccountControl': ['512'],
        }
        if extra_attrs:
            base.update(extra_attrs)

        entry = MagicMock()
        entry.entry_attributes_as_dict = base
        entry.entry_dn = 'uid=jdoe,ou=users,dc=example,dc=com'
        return entry

    def test_no_attribute_columns_stores_nothing(self):
        """When attribute_columns is empty, no custom attrs are stored."""
        p = _ldap_provider('')
        entry = self._make_entry({'jpegPhoto': ['base64data']})
        result = p._parse_user_entry(entry, include_roles=False)
        assert result['attributes'] == {}

    def test_specified_columns_stored(self):
        p = _ldap_provider('jpegPhoto,telephoneNumber')
        entry = self._make_entry({
            'jpegPhoto': ['https://example.com/photo.jpg'],
            'telephoneNumber': ['+62811234567'],
        })
        result = p._parse_user_entry(entry, include_roles=False)
        assert result['attributes']['jpegPhoto'] == 'https://example.com/photo.jpg'
        assert result['attributes']['telephoneNumber'] == '+62811234567'

    def test_system_attrs_not_stored(self):
        """objectClass, userAccountControl, etc. must not leak into attributes."""
        p = _ldap_provider('jpegPhoto')
        entry = self._make_entry({'jpegPhoto': ['url']})
        result = p._parse_user_entry(entry, include_roles=False)
        assert 'objectClass' not in result['attributes']
        assert 'userAccountControl' not in result['attributes']
        assert 'uid' not in result['attributes']

    def test_missing_column_ignored_gracefully(self):
        """A column listed in attribute_columns but absent in LDAP response is ignored."""
        p = _ldap_provider('nonexistent_attr')
        entry = self._make_entry()
        result = p._parse_user_entry(entry, include_roles=False)
        assert 'nonexistent_attr' not in result['attributes']

    def test_multi_value_ldap_attr_stored_as_list(self):
        """Multi-value LDAP attributes should be stored as a list."""
        p = _ldap_provider('memberOfCustom')
        entry = self._make_entry({'memberOfCustom': ['group1', 'group2']})
        result = p._parse_user_entry(entry, include_roles=False)
        assert result['attributes']['memberOfCustom'] == ['group1', 'group2']


# ---------------------------------------------------------------------------
# 4. UserService — individual attribute add/delete via API
# ---------------------------------------------------------------------------

class TestUserServiceAttributeAddDelete:
    """Validate the add/delete pattern the Attributes tab JS uses."""

    def test_add_new_attribute_preserves_existing(self, app):
        """Adding a new attribute via set_attributes must not delete existing ones."""
        with app.app_context():
            realm = Realm(name='test-attr-realm', display_name='Test')
            db.session.add(realm)
            db.session.flush()

            user = User(
                username='attrtest',
                email='attrtest@example.com',
                realm_id=realm.id,
            )
            db.session.add(user)
            db.session.flush()

            # Start with two attributes (simulating what federation sync stored)
            UserService.set_attributes(user, {'photo': 'https://example.com/p.jpg', 'phone': '123'})

            # Simulate the JS reading current attrs and adding 'department'
            current = UserService.get_attributes(user)
            current['department'] = ['Engineering']
            UserService.set_attributes(user, current)

            result = UserService.get_attributes(user)
            assert 'photo' in result
            assert 'phone' in result
            assert 'department' in result

            db.session.rollback()

    def test_delete_single_attribute_preserves_rest(self, app):
        """Deleting one attribute via set_attributes keeps all others."""
        with app.app_context():
            realm = Realm(name='test-attr-del-realm', display_name='Test')
            db.session.add(realm)
            db.session.flush()

            user = User(
                username='attrdel',
                email='attrdel@example.com',
                realm_id=realm.id,
            )
            db.session.add(user)
            db.session.flush()

            UserService.set_attributes(user, {
                'photo': 'https://example.com/p.jpg',
                'phone': '123',
                'department': 'Engineering',
            })

            # Simulate JS: read, delete 'phone', write back
            current = UserService.get_attributes(user)
            del current['phone']
            UserService.set_attributes(user, current)

            result = UserService.get_attributes(user)
            assert 'photo' in result
            assert 'department' in result
            assert 'phone' not in result

            db.session.rollback()
