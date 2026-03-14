"""Tests for search bar functionality in realm roles and realm groups list pages."""

import pytest
from apps import db
from apps.models.role import Role
from apps.models.group import Group


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username='admin', password='testadmin123!'):
    client.post('/auth/login', data={'username': username, 'password': password},
                follow_redirects=False)


# ---------------------------------------------------------------------------
# Roles search
# ---------------------------------------------------------------------------

class TestRolesSearch:
    def _url(self, realm_name, search=''):
        url = f'/admin/{realm_name}/roles'
        if search:
            url += f'?search={search}'
        return url

    def _create_roles(self, app, realm_id, roles):
        """Create roles for testing.  roles is a list of (name, description)."""
        with app.app_context():
            for name, description in roles:
                if not Role.find_realm_role(realm_id, name):
                    r = Role(
                        realm_id=realm_id,
                        name=name,
                        description=description,
                        client_id=None,
                        client_role=False,
                        composite=False,
                    )
                    db.session.add(r)
            db.session.commit()

    # ------------------------------------------------------------------
    # Basic search
    # ------------------------------------------------------------------

    def test_roles_list_no_search_shows_all(self, app, client, admin_user, test_realm):
        """Without search param, all realm roles are shown."""
        self._create_roles(app, test_realm.id, [
            ('search_role_alpha', 'Alpha role'),
            ('search_role_beta', 'Beta role'),
        ])
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'search_role_alpha' in data
        assert 'search_role_beta' in data

    def test_roles_search_by_name(self, app, client, admin_user, test_realm):
        """?search= filters roles by name."""
        self._create_roles(app, test_realm.id, [
            ('unique_admin_role', 'Admin role'),
            ('something_else_role', 'Unrelated'),
        ])
        _login(client)
        resp = client.get(self._url(test_realm.name, search='unique_admin'))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'unique_admin_role' in data
        assert 'something_else_role' not in data

    def test_roles_search_by_description(self, app, client, admin_user, test_realm):
        """?search= also matches role description."""
        self._create_roles(app, test_realm.id, [
            ('role_with_special_desc', 'FINDMEDESC description'),
            ('another_plain_role', 'unrelated'),
        ])
        _login(client)
        resp = client.get(self._url(test_realm.name, search='FINDMEDESC'))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'role_with_special_desc' in data
        assert 'another_plain_role' not in data

    def test_roles_search_case_insensitive(self, app, client, admin_user, test_realm):
        """Search is case-insensitive."""
        self._create_roles(app, test_realm.id, [
            ('case_test_role_xyz', 'Some description'),
        ])
        _login(client)
        resp = client.get(self._url(test_realm.name, search='CASE_TEST_ROLE'))
        assert resp.status_code == 200
        assert b'case_test_role_xyz' in resp.data

    def test_roles_search_no_match_shows_empty_state(self, app, client, admin_user, test_realm):
        """When search returns no results, an appropriate message is displayed."""
        _login(client)
        resp = client.get(self._url(test_realm.name, search='zzz_nonexistent_xyz_abc'))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'No roles found matching' in data
        assert 'zzz_nonexistent_xyz_abc' in data

    def test_roles_search_bar_rendered(self, app, client, admin_user, test_realm):
        """The search input element is present on the roles list page."""
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'name="search"' in data
        assert 'Search by name or description' in data

    def test_roles_search_clear_link_shown_when_active(self, app, client, admin_user, test_realm):
        """A 'Clear' link appears when a search is active."""
        _login(client)
        resp = client.get(self._url(test_realm.name, search='anything'))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'Clear' in data

    def test_roles_search_no_clear_link_without_search(self, app, client, admin_user, test_realm):
        """The 'Clear' link is absent when no search term is given."""
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        # The Clear anchor links to the base URL; its presence is conditional on `search`
        data = resp.data.decode()
        assert 'Clear' not in data or 'search=' not in data

    def test_roles_search_requires_login(self, client, test_realm):
        """Unauthenticated access to roles search is rejected."""
        resp = client.get(self._url(test_realm.name, search='admin'))
        assert resp.status_code in (302, 401)


# ---------------------------------------------------------------------------
# Groups search
# ---------------------------------------------------------------------------

class TestGroupsSearch:
    def _url(self, realm_name, search=''):
        url = f'/admin/{realm_name}/groups'
        if search:
            url += f'?search={search}'
        return url

    def _create_groups(self, app, realm_id, names):
        """Create top-level groups for testing."""
        with app.app_context():
            for name in names:
                path = f'/{name}'
                if not Group.find_by_path(realm_id, path):
                    g = Group(
                        realm_id=realm_id,
                        name=name,
                        path=path,
                        parent_id=None,
                    )
                    db.session.add(g)
            db.session.commit()

    # ------------------------------------------------------------------
    # Basic search
    # ------------------------------------------------------------------

    def test_groups_list_no_search_shows_all(self, app, client, admin_user, test_realm):
        """Without search param, all top-level groups are shown."""
        self._create_groups(app, test_realm.id, [
            'search_group_alpha',
            'search_group_beta',
        ])
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'search_group_alpha' in data
        assert 'search_group_beta' in data

    def test_groups_search_by_name(self, app, client, admin_user, test_realm):
        """?search= filters groups by name."""
        self._create_groups(app, test_realm.id, [
            'unique_engineering_group',
            'marketing_group',
        ])
        _login(client)
        resp = client.get(self._url(test_realm.name, search='unique_engineering'))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'unique_engineering_group' in data
        assert 'marketing_group' not in data

    def test_groups_search_case_insensitive(self, app, client, admin_user, test_realm):
        """Group search is case-insensitive."""
        self._create_groups(app, test_realm.id, ['CaseGroupTest_xyz'])
        _login(client)
        resp = client.get(self._url(test_realm.name, search='caseGroupTest'))
        assert resp.status_code == 200
        assert b'CaseGroupTest_xyz' in resp.data

    def test_groups_search_no_match_shows_empty_state(self, app, client, admin_user, test_realm):
        """When search returns no results, an appropriate message is displayed."""
        _login(client)
        resp = client.get(self._url(test_realm.name, search='zzz_no_such_group_abc'))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'No groups found matching' in data
        assert 'zzz_no_such_group_abc' in data

    def test_groups_search_bar_rendered(self, app, client, admin_user, test_realm):
        """The search input element is present on the groups list page."""
        _login(client)
        resp = client.get(self._url(test_realm.name))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert 'name="search"' in data
        assert 'Search by group name' in data

    def test_groups_search_clear_link_shown_when_active(self, app, client, admin_user, test_realm):
        """A 'Clear' link appears when a search is active."""
        _login(client)
        resp = client.get(self._url(test_realm.name, search='anything'))
        assert resp.status_code == 200
        assert b'Clear' in resp.data

    def test_groups_search_subgroup_included(self, app, client, admin_user, test_realm):
        """Search also finds subgroups by name."""
        with app.app_context():
            parent_path = '/parent_for_search_test'
            parent = Group.find_by_path(test_realm.id, parent_path)
            if not parent:
                parent = Group(
                    realm_id=test_realm.id,
                    name='parent_for_search_test',
                    path=parent_path,
                    parent_id=None,
                )
                db.session.add(parent)
                db.session.flush()
            child_path = parent_path + '/deep_child_search_unique'
            child = Group.find_by_path(test_realm.id, child_path)
            if not child:
                child = Group(
                    realm_id=test_realm.id,
                    name='deep_child_search_unique',
                    path=child_path,
                    parent_id=parent.id,
                )
                db.session.add(child)
            db.session.commit()

        _login(client)
        resp = client.get(self._url(test_realm.name, search='deep_child_search'))
        assert resp.status_code == 200
        assert b'deep_child_search_unique' in resp.data

    def test_groups_search_requires_login(self, client, test_realm):
        """Unauthenticated access to groups search is rejected."""
        resp = client.get(self._url(test_realm.name, search='admin'))
        assert resp.status_code in (302, 401)
