# -*- coding: utf-8 -*-
"""
Regression tests for custom user attribute federation sync bugs.

Covers four bugs that collectively prevented custom attributes (e.g. "photo")
set in the external database from ever appearing in userinfo / JWT tokens:

Bug 1: federation_service called UserService.set_attributes(user.id, …) instead
       of UserService.set_attributes(user, …) — passing a string UUID where a
       User object was expected, causing an AttributeError on every sync.

Bug 2: UserService.set_attributes() iterated scalar string values character-by-
       character instead of treating the whole string as a single value.

Bug 3: base.map_user_attributes() initialised mapped['attributes'] = {} and
       therefore discarded all attributes that the DB / LDAP provider had already
       placed in external_user['attributes'] via attribute_columns / LDAP mapping.

Bug 4: base.map_user_attributes() only checked external_attr in the top-level of
       external_user, so an explicit UserFederationMapper with external_attribute
       equal to a column name was silently ignored for DB providers where the
       column value had been placed in external_user['attributes'] by _parse_row.
"""

import pytest
from unittest.mock import MagicMock, patch

from apps import db
from apps.models.user import User, UserAttribute
from apps.models.realm import Realm
from apps.services.user_service import UserService
from apps.services.federation.base import BaseFederationProvider


# ---------------------------------------------------------------------------
# Helpers / minimal concrete provider for testing map_user_attributes
# ---------------------------------------------------------------------------

class _ConcreteProvider(BaseFederationProvider):
    """Minimal concrete subclass that satisfies BaseFederationProvider's ABCs."""

    PROVIDER_TYPE = 'test'

    def connect(self):
        return True

    def disconnect(self):
        pass

    def test_connection(self):
        return True, 'ok'

    def get_user_by_username(self, username):
        return None

    def get_user_by_email(self, email):
        return None

    def validate_credentials(self, external_user, password):
        return False

    def get_all_users(self, batch_size=100):
        return iter([])


def _make_provider(config=None):
    return _ConcreteProvider('provider-id', 'realm-id', config or {})


# ---------------------------------------------------------------------------
# Bug 3: pre-existing attributes must be preserved by map_user_attributes
# ---------------------------------------------------------------------------

class TestMapUserAttributesPreservesExistingAttrs:
    """Bug 3: attributes already in external_user['attributes'] must not be dropped."""

    def test_no_mappers_preserves_attribute_columns(self):
        """With an empty mapper list, all pre-parsed attributes must be kept."""
        provider = _make_provider()
        external_user = {
            'external_id': '1',
            'username': 'teguh02',
            'email': 'teguh@example.com',
            'first_name': 'Teguh',
            'last_name': 'Doe',
            'enabled': True,
            'attributes': {
                'photo': 'https://example.com/photo.jpg',
                'department': 'Engineering',
            },
        }

        result = provider.map_user_attributes(external_user, mappers=[])

        assert result['attributes'].get('photo') == 'https://example.com/photo.jpg', (
            "photo attribute from external_user['attributes'] must be preserved "
            "even when no explicit mappers are configured"
        )
        assert result['attributes'].get('department') == 'Engineering'

    def test_mapper_can_override_preserved_attribute(self):
        """An explicit mapper should be able to override a pre-parsed attribute."""
        provider = _make_provider()
        external_user = {
            'external_id': '2',
            'username': 'alice',
            'email': 'alice@example.com',
            'first_name': 'Alice',
            'last_name': 'Smith',
            'enabled': True,
            'attributes': {'department': 'OldDept'},
        }
        mappers = [
            {
                'mapper_type': 'user-attribute-db-mapper',
                'external_attribute': 'dept_override',
                'internal_attribute': 'department',
                'config': {},
            }
        ]
        # dept_override is at the top level of external_user
        external_user['dept_override'] = 'NewDept'

        result = provider.map_user_attributes(external_user, mappers)

        assert result['attributes']['department'] == 'NewDept', (
            "An explicit mapper targeting 'department' must override the "
            "pre-parsed value"
        )


# ---------------------------------------------------------------------------
# Bug 4: explicit mapper must find attributes in nested external_user['attributes']
# ---------------------------------------------------------------------------

class TestMapUserAttributesNestedLookup:
    """Bug 4: mapper with external_attribute must search nested attributes too."""

    def test_db_mapper_finds_nested_attribute(self):
        """
        user-attribute-db-mapper must find its external_attribute in
        external_user['attributes'] when it is not present at the top level.
        """
        provider = _make_provider()
        external_user = {
            'external_id': '3',
            'username': 'bob',
            'email': 'bob@example.com',
            'first_name': 'Bob',
            'last_name': 'Jones',
            'enabled': True,
            # DB _parse_row puts attribute_columns values here:
            'attributes': {'photo': 'https://example.com/photo.jpg'},
        }
        mappers = [
            {
                'mapper_type': 'user-attribute-db-mapper',
                'external_attribute': 'photo',   # the DB column name
                'internal_attribute': 'picture', # rename to internal name
                'config': {},
            }
        ]

        result = provider.map_user_attributes(external_user, mappers)

        assert result['attributes'].get('picture') == 'https://example.com/photo.jpg', (
            "user-attribute-db-mapper must locate the external attribute in "
            "external_user['attributes'] when it is not at the top level"
        )

    def test_ldap_mapper_finds_nested_attribute(self):
        """user-attribute-ldap-mapper must also search the nested attributes."""
        provider = _make_provider()
        external_user = {
            'external_id': '4',
            'username': 'carol',
            'email': 'carol@example.com',
            'first_name': 'Carol',
            'last_name': 'White',
            'enabled': True,
            'attributes': {'jpegPhoto': 'base64data'},
        }
        mappers = [
            {
                'mapper_type': 'user-attribute-ldap-mapper',
                'external_attribute': 'jpegPhoto',
                'internal_attribute': 'photo',
                'config': {},
            }
        ]

        result = provider.map_user_attributes(external_user, mappers)

        assert result['attributes'].get('photo') == 'base64data'

    def test_top_level_attribute_still_found(self):
        """Top-level external_user keys must continue to work for mappers."""
        provider = _make_provider()
        external_user = {
            'external_id': '5',
            'username': 'dave',
            'email': 'dave@example.com',
            'first_name': 'Dave',
            'last_name': 'Brown',
            'enabled': True,
            'phone': '+1-555-0100',
            'attributes': {},
        }
        mappers = [
            {
                'mapper_type': 'user-attribute-db-mapper',
                'external_attribute': 'phone',
                'internal_attribute': 'phone_number',
                'config': {},
            }
        ]

        result = provider.map_user_attributes(external_user, mappers)

        assert result['attributes'].get('phone_number') == '+1-555-0100'


# ---------------------------------------------------------------------------
# Bug 2: set_attributes must handle scalar string values
# ---------------------------------------------------------------------------

class TestSetAttributesScalarValues:
    """Bug 2: set_attributes must accept scalar string values, not just lists."""

    def test_scalar_string_stored_as_single_value(self, app):
        with app.app_context():
            realm = Realm.query.filter_by(name='master').first()
            user = User(realm_id=realm.id, username='test_scalar_attr',
                        email='scalar@test.com', enabled=True)
            db.session.add(user)
            db.session.flush()

            # Pass scalar strings (as federation sync does)
            UserService.set_attributes(user, {
                'photo': 'https://example.com/photo.jpg',
                'department': 'Engineering',
            })

            attrs = {a.name: a.value for a in user.attributes.all()}
            assert attrs.get('photo') == 'https://example.com/photo.jpg', (
                "scalar photo value must be stored as a single complete string, "
                "not as individual characters"
            )
            assert attrs.get('department') == 'Engineering'

            # Cleanup
            db.session.delete(user)
            db.session.commit()

    def test_list_values_still_work(self, app):
        with app.app_context():
            realm = Realm.query.filter_by(name='master').first()
            user = User(realm_id=realm.id, username='test_list_attr',
                        email='list@test.com', enabled=True)
            db.session.add(user)
            db.session.flush()

            # Pass list values (existing contract)
            UserService.set_attributes(user, {
                'role': ['admin', 'user'],
                'photo': ['https://example.com/photo.jpg'],
            })

            attr_rows = user.attributes.all()
            role_vals = sorted(a.value for a in attr_rows if a.name == 'role')
            photo_vals = [a.value for a in attr_rows if a.name == 'photo']

            assert role_vals == ['admin', 'user']
            assert photo_vals == ['https://example.com/photo.jpg']

            # Cleanup
            db.session.delete(user)
            db.session.commit()

    def test_none_values_are_skipped(self, app):
        with app.app_context():
            realm = Realm.query.filter_by(name='master').first()
            user = User(realm_id=realm.id, username='test_none_attr',
                        email='none@test.com', enabled=True)
            db.session.add(user)
            db.session.flush()

            UserService.set_attributes(user, {'photo': None, 'department': 'HR'})

            attrs = {a.name: a.value for a in user.attributes.all()}
            assert 'photo' not in attrs, "None values must not create attribute rows"
            assert attrs.get('department') == 'HR'

            # Cleanup
            db.session.delete(user)
            db.session.commit()


# ---------------------------------------------------------------------------
# Bug 1: federation_service must pass User object, not user.id string
# ---------------------------------------------------------------------------

class TestFederationServicePassesUserObject:
    """Bug 1: set_attributes must receive a User object, not a string ID."""

    def test_create_federated_user_stores_attributes(self, app):
        """
        FederationService._create_federated_user must store custom attributes
        so that they are visible via user.attributes after sync.
        """
        from apps.services.federation.federation_service import FederationService

        with app.app_context():
            realm = Realm.query.filter_by(name='master').first()

            # Simulate what the PostgreSQL provider returns after _parse_row
            external_user = {
                'external_id': 'ext-001',
                'username': 'fed_photo_user',
                'email': 'fed_photo@test.com',
                'first_name': 'Fed',
                'last_name': 'Photo',
                'enabled': True,
                'attributes': {
                    'photo': 'https://example.com/federated_photo.jpg',
                    'employee_id': 'EMP-42',
                },
            }

            try:
                # No provider_instance → map_user_attributes won't be called,
                # attributes come straight from external_user['attributes']
                user = FederationService._create_federated_user(
                    realm_id=realm.id,
                    external_user=external_user,
                    provider_instance=None,
                )

                assert user is not None, (
                    "_create_federated_user returned None – the user was not created"
                )

                attrs = {a.name: a.value for a in user.attributes.all()}
                assert attrs.get('photo') == 'https://example.com/federated_photo.jpg', (
                    "photo attribute must be stored in user_attributes after federation sync"
                )
                assert attrs.get('employee_id') == 'EMP-42'

            finally:
                created = User.query.filter_by(
                    realm_id=realm.id, username='fed_photo_user'
                ).first()
                if created:
                    db.session.delete(created)
                    db.session.commit()

    def test_update_user_from_external_stores_attributes(self, app):
        """
        FederationService._update_user_from_external must update custom
        attributes in user_attributes on every sync.
        """
        from apps.services.federation.federation_service import FederationService

        with app.app_context():
            realm = Realm.query.filter_by(name='master').first()

            # Create a user to update
            user = User(realm_id=realm.id, username='fed_update_user',
                        email='fed_update@test.com', first_name='Old',
                        last_name='Name', enabled=True)
            db.session.add(user)
            db.session.commit()

            external_user = {
                'external_id': 'ext-002',
                'username': 'fed_update_user',
                'email': 'fed_update@test.com',
                'first_name': 'New',
                'last_name': 'Name',
                'enabled': True,
                'attributes': {
                    'photo': 'https://example.com/updated_photo.jpg',
                },
            }

            try:
                FederationService._update_user_from_external(
                    user=user,
                    external_user=external_user,
                    provider_instance=None,
                )

                db.session.refresh(user)
                attrs = {a.name: a.value for a in user.attributes.all()}
                assert attrs.get('photo') == 'https://example.com/updated_photo.jpg', (
                    "photo attribute must be updated in user_attributes after "
                    "_update_user_from_external"
                )

            finally:
                db.session.delete(user)
                db.session.commit()


# ---------------------------------------------------------------------------
# End-to-end: custom attribute → userinfo token
# ---------------------------------------------------------------------------

class TestCustomAttributeAppearsInUserinfo:
    """
    Integration test: a custom attribute stored in user_attributes via
    set_attributes must appear in the userinfo response when a matching
    ProtocolMapper is configured for the profile scope.
    """

    def test_photo_attribute_in_userinfo(self, client, app):
        from apps.services.realm_service import RealmService
        from apps.services.client_service import ClientService
        from apps.models.client import ClientScope, ProtocolMapper
        from apps.utils.crypto import hash_password
        from apps.models.user import Credential

        with app.app_context():
            realm = RealmService.create_realm('photo-test-realm', 'Photo Test Realm')
            realm_id = realm.id
            realm_name = realm.name

            oidc_client = ClientService.create_client(
                realm_id=realm_id,
                client_id='photo-test-client',
                name='Photo Test Client',
                direct_access_grants_enabled=True,
            )

            user = User(
                realm_id=realm_id,
                username='photouser',
                email='photouser@example.com',
                first_name='Photo',
                last_name='User',
                enabled=True,
                email_verified=True,
            )
            db.session.add(user)
            db.session.flush()

            cred = Credential.create_password(user.id, hash_password('testpass123!'))
            db.session.add(cred)
            db.session.flush()

            # Store the custom photo attribute (simulating what federation sync
            # now correctly does after the Bug 1 + 2 fixes)
            UserService.set_attributes(user, {
                'photo': 'https://example.com/photo.jpg',
            })

            # Add a ProtocolMapper to the profile scope for the photo attribute
            profile_scope = ClientScope.query.filter_by(
                realm_id=realm_id, name='profile'
            ).first()
            assert profile_scope is not None, "profile scope must exist"

            photo_mapper = ProtocolMapper(
                client_scope_id=profile_scope.id,
                name='photo',
                protocol='openid-connect',
                protocol_mapper='oidc-usermodel-attribute-mapper',
                config={
                    'user.attribute': 'photo',
                    'claim.name': 'picture',
                    'jsonType.label': 'String',
                    'access.token.claim': 'true',
                    'id.token.claim': 'true',
                    'userinfo.token.claim': 'true',
                },
            )
            db.session.add(photo_mapper)
            db.session.commit()

            # Capture credentials before leaving the app context
            client_id_str = oidc_client.client_id
            client_secret = oidc_client.secret

        try:
            # Obtain an access token
            token_resp = client.post(
                f'/auth/realms/{realm_name}/protocol/openid-connect/token',
                data={
                    'grant_type': 'password',
                    'client_id': client_id_str,
                    'client_secret': client_secret,
                    'username': 'photouser',
                    'password': 'testpass123!',
                    'scope': 'openid profile',
                },
            )
            assert token_resp.status_code == 200, (
                f"Token request failed: {token_resp.get_data(as_text=True)}"
            )
            access_token = token_resp.json['access_token']

            # Call userinfo
            userinfo_resp = client.get(
                f'/auth/realms/{realm_name}/protocol/openid-connect/userinfo',
                headers={'Authorization': f'Bearer {access_token}'},
            )
            assert userinfo_resp.status_code == 200, (
                f"UserInfo request failed: {userinfo_resp.get_data(as_text=True)}"
            )
            info = userinfo_resp.json

            assert 'picture' in info, (
                "The 'picture' claim must appear in userinfo when a "
                "ProtocolMapper maps the 'photo' user attribute to 'picture'"
            )
            assert info['picture'] == 'https://example.com/photo.jpg'

        finally:
            with app.app_context():
                from apps.models.realm import Realm as RealmModel
                r = RealmModel.find_by_name(realm_name)
                if r:
                    db.session.delete(r)
                    db.session.commit()
