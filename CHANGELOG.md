# Change Log

## [2.5.1] 2026-01-25 - User Role & Group Management

### New Features

- **User Role Management in Admin UI**:
  - Assign realm roles to users from the user detail page
  - Remove roles from users with confirmation dialog
  - Display available roles that can be assigned
  - Roles automatically appear in JWT `realm_access.roles` claim when `roles` scope is requested

- **User Group Management in Admin UI**:
  - Add users to groups from the user detail page
  - Remove users from groups with confirmation dialog
  - Display available groups that can be joined
  - Groups appear in JWT `groups` claim when `groups` scope is requested

- **Realm Roles Edit/Delete**:
  - Edit role name and description via modal form
  - Delete roles with confirmation (protected system roles cannot be deleted)
  - System roles (`default-roles-*`, `offline_access`, `uma_authorization`) are protected

- **OIDC UserInfo Endpoint Enhancement**:
  - Updated `/auth/realms/{realm}/protocol/openid-connect/userinfo` endpoint
  - Response now matches exactly with claims in decoded JWT access token
  - Returns all user claims from JWT (excluding protected system claims like `iss`, `aud`, `exp`, `iat`, etc.)
  - Ensures consistency between JWT token claims and UserInfo API response

### Bug Fixes

- Fixed missing `mapper_form.html` template for client scopes
- Fixed JavaScript error in dark-mode.js when theme elements are not present
- Fixed roles scope seeding to include realm role mapper for JWT claims

### Database Migrations

- Added `priority` and `consent_text` columns to `protocol_mappers` table
- Added `seed_roles_scope()` function to ensure roles scope exists with proper mapper

---

## [2.5.0] 2026-01-25 - Federated Role Synchronization

### New Features

- **Federated Role Synchronization**: Comprehensive role sync between external identity sources and RijanAuth
  - **Intelligent Format Detection**: Auto-detect role data formats (string, array, JSON, custom)
  - **Role Mapping Engine**: Map external roles to internal RijanAuth roles
  - **Fallback Mechanisms**: Graceful handling of varying role data formats

- **Role Mapping Configuration**:
  - Direct mapping (exact match)
  - Prefix matching (role name starts with pattern)
  - Regex matching (pattern-based matching)
  - Priority ordering for conflict resolution
  - Auto-create missing roles option
  - Default role assignment if no roles found
  - Protected roles that cannot be overridden

- **Provider-Specific Role Extraction**:
  - **LDAP/AD**: Extract roles from memberOf attribute or group search
    - CN extraction from DN strings
    - Configurable group object classes
    - Nested group support
  - **MySQL/MariaDB**: Extract roles from column or separate table
    - Support for delimiter-separated strings
    - Separate role table with user-role relationships
  - **PostgreSQL**: Extract roles from column, table, or JSONB fields
    - Array type support for PostgreSQL TEXT[]
    - JSONB path navigation for nested role data
    - Support for complex JSON structures

- **Admin UI**:
  - Role mapping configuration in provider create/edit forms
  - Dedicated Role Mappings management page
  - Role mapping CRUD with modal forms
  - Recent role sync history display
  - Available realm roles reference

- **REST API**:
  - `GET/POST /api/{realm}/user-federation/{provider}/role-mappings` - List/create mappings
  - `GET/PUT/DELETE /api/{realm}/user-federation/{provider}/role-mappings/{id}` - Mapping CRUD
  - `GET/PUT /api/{realm}/user-federation/{provider}/role-format` - Format config
  - `POST /api/{realm}/user-federation/{provider}/test-role-format` - Test format detection
  - `GET /api/{realm}/user-federation/{provider}/role-sync-history` - Provider sync history
  - `GET /api/{realm}/users/{user}/role-sync-history` - User sync history

### New Files

- `apps/services/federation/role_sync_service.py` - RoleSyncService and RoleFormatDetector
- `apps/templates/admin/federation/role_mappings.html` - Role mappings management UI

### Updated Files

- `apps/models/federation.py` - Added FederationRoleMapping, FederationRoleFormatConfig, FederatedRoleSync models
- `apps/models/__init__.py` - Export new federation models
- `apps/services/federation/__init__.py` - Export RoleSyncService, RoleFormatDetector
- `apps/services/federation/federation_service.py` - Integrated role sync into user import
- `apps/services/federation/ldap_provider.py` - Added role extraction methods
- `apps/services/federation/mysql_provider.py` - Added role extraction methods
- `apps/services/federation/postgresql_provider.py` - Added role extraction methods
- `apps/blueprints/admin/routes.py` - Added role mapping routes and _build_provider_config updates
- `apps/blueprints/admin/api.py` - Added role mapping API endpoints
- `apps/templates/admin/federation/create_ldap.html` - Added role mapping settings
- `apps/templates/admin/federation/create_mysql.html` - Added role mapping settings
- `apps/templates/admin/federation/create_postgresql.html` - Added role mapping settings

---

## [2.4.0] 2026-01-25 - Custom JWT Claims & Protocol Mappers

### New Features

- **Protocol Mapper System**: Complete JWT token customization mirroring Keycloak's mapper functionality
  - **User Attribute Mapper**: Maps user attributes to token claims
  - **Hardcoded Claim Mapper**: Adds fixed values to tokens
  - **Realm Role Mapper**: Maps realm roles to token claims
  - **Client Role Mapper**: Maps client roles to token claims
  - **Group Membership Mapper**: Maps user groups to token claims
  - **Audience Mapper**: Adds additional audiences to tokens
  - **Full Name Mapper**: Combines first/last name
  - **Address Mapper**: Maps address attributes

- **Client Scopes**: Reusable sets of protocol mappers
  - Default scopes: openid, profile, email, roles, groups, address, phone, offline_access
  - Client scope assignment to clients
  - Inherited mappers from assigned scopes

- **Token Customization Features**:
  - Per-token-type configuration (access, ID, userinfo)
  - Priority ordering for mappers
  - Nested claim support (dot notation)
  - JSON type conversion (String, int, boolean, JSON)
  - Multivalued claim support
  - Protected claim validation (prevents overriding iss, sub, aud, exp, etc.)

- **Admin UI**:
  - Client mappers management page (Clients > [client] > Mappers tab)
  - Client scopes list and detail pages
  - Mapper creation/edit forms with type-specific fields
  - Inherited mappers display from assigned scopes

- **REST API**:
  - `GET/POST /api/{realm}/clients/{client}/protocol-mappers` - List/create client mappers
  - `GET/PUT/DELETE /api/{realm}/clients/{client}/protocol-mappers/{id}` - Mapper CRUD
  - `GET /api/{realm}/client-scopes` - List client scopes
  - `GET/POST /api/{realm}/client-scopes/{id}/protocol-mappers` - Scope mapper management
  - `GET /api/{realm}/clients/{client}/token-preview` - Preview token with mappers

### New Files

- `apps/services/mapper_service.py` - MapperService for token claim processing
- `apps/seeders/client_scopes_seeder.py` - Default client scopes with mappers
- `apps/templates/admin/clients/mappers.html` - Client mappers list page
- `apps/templates/admin/clients/mapper_form.html` - Mapper create/edit form
- `apps/templates/admin/client_scopes/list.html` - Client scopes list
- `apps/templates/admin/client_scopes/detail.html` - Client scope detail with mappers

### Updated Files

- `apps/models/client.py` - Enhanced ProtocolMapper model with priority, validation
- `apps/blueprints/oidc/routes.py` - Token generation uses MapperService
- `apps/blueprints/admin/routes.py` - Client mapper and scope routes
- `apps/blueprints/admin/api.py` - Protocol mapper API endpoints
- `apps/templates/includes/admin_sidebar.html` - Added Client Scopes menu
- `apps/seeders/__init__.py` - Includes client scopes seeding

---

## [2.3.0] 2026-01-25 - User Federation & SSO Session Management

### New Features

- **User Federation System**: Comprehensive external identity source integration
  - **LDAP/Active Directory Provider**: Full LDAP support with connection pooling
  - **MySQL/MariaDB Provider**: Database federation with configurable column mappings
  - **PostgreSQL Provider**: PostgreSQL support with JSONB attributes and array groups
  - **Extensible Architecture**: Abstract base class for future provider implementations

- **Federation Features**:
  - Attribute mappers for custom field mapping
  - Multiple password hash algorithm support (bcrypt, SHA256, SHA512, MD5)
  - Full sync and changed sync capabilities
  - APScheduler integration for scheduled background synchronization
  - Credential encryption for sensitive configuration data

- **SSO Session Management**: User sessions now tracked during OIDC flows
  - `UserSession` created on OIDC authorization login
  - `AuthenticatedClientSession` tracks client authentications
  - Session state included in token responses
  - Session refresh on token exchange and refresh

- **Admin UI - User Federation**:
  - Provider list with status, sync info, and priority
  - Create forms for LDAP, MySQL, PostgreSQL providers
  - Edit provider settings and configuration
  - Attribute mapper management
  - Sync status and history viewing
  - Manual sync trigger (full/changed)
  - Connection test functionality

### New Files

- `apps/models/federation.py` - Federation data models (Provider, Mapper, Link, SyncLog)
- `apps/services/federation/` - Federation service package
  - `base.py` - Abstract BaseFederationProvider class
  - `ldap_provider.py` - LDAP/AD implementation
  - `mysql_provider.py` - MySQL/MariaDB implementation
  - `postgresql_provider.py` - PostgreSQL implementation
  - `federation_service.py` - Central orchestration service
  - `sync_service.py` - Synchronization and scheduling service
- `apps/templates/admin/federation/` - Federation UI templates
  - `list.html` - Provider listing
  - `create_ldap.html`, `create_mysql.html`, `create_postgresql.html` - Create forms
  - `edit.html` - Edit provider settings
  - `mappers.html` - Attribute mapper management
  - `sync_status.html` - Sync status and history

### Updated Files

- `apps/__init__.py` - Import federation models for table creation
- `apps/models/__init__.py` - Export federation models
- `apps/blueprints/oidc/routes.py` - SSO session creation and tracking
- `apps/blueprints/admin/routes.py` - Federation admin routes
- `apps/blueprints/admin/api.py` - Federation REST API endpoints
- `apps/blueprints/auth/routes.py` - Federation auth integration
- `apps/templates/includes/admin_sidebar.html` - User Federation menu item
- `apps/utils/crypto.py` - Added encrypt_data/decrypt_data functions
- `requirements.txt` - Added ldap3, pymysql, psycopg2-binary, APScheduler

### Bug Fixes

- **SSO Sessions Not Created**: Fixed OIDC authorization flow not creating user sessions
- **Federation UI Icons**: Fixed missing database icons using Font Awesome

---

## [2.2.0] 2026-01-25 - OpenID Connect Implementation & Admin UI Fixes

### New Features

- **OpenID Connect Protocol**: Full OIDC 1.0 implementation compatible with Keycloak
  - **Discovery Endpoint**: `/.well-known/openid-configuration` returns provider metadata
  - **Authorization Endpoint**: `/protocol/openid-connect/auth` with login UI
  - **Token Endpoint**: `/protocol/openid-connect/token` supporting multiple grant types
  - **UserInfo Endpoint**: `/protocol/openid-connect/userinfo` returns user claims
  - **Logout Endpoint**: `/protocol/openid-connect/logout` with redirect support
  - **JWKS Endpoint**: `/protocol/openid-connect/certs` for token verification
  - **Introspection Endpoint**: `/protocol/openid-connect/token/introspect` (RFC 7662)
  - **Revocation Endpoint**: `/protocol/openid-connect/revoke` (RFC 7009)

- **Supported OAuth 2.0 Grant Types**:
  - Authorization Code (with optional PKCE support)
  - Password Grant (Direct Access)
  - Client Credentials Grant
  - Refresh Token Grant

- **OIDC Login Page**: Modern responsive login form at `/auth/realms/{realm}/protocol/openid-connect/auth`

### Bug Fixes

- **Admin UI Create Operations**: Fixed 405 Method Not Allowed errors
  - Added POST handler for Create Client (`/<realm_name>/clients/create`)
  - Added POST handler for Create Role (`/<realm_name>/roles`)
  - Added POST handler for Create Group (`/<realm_name>/groups`)
  - Added POST handler for Realm Settings save (`/<realm_name>/settings`)
  - Fixed form action URLs in all modal forms

- **Sidebar Icon**: Fixed missing icon for "Realm Roles" menu (changed from `icon-key` to `icon-award`)

### New Files

- `apps/blueprints/oidc/__init__.py` - OIDC Blueprint registration
- `apps/blueprints/oidc/routes.py` - Complete OIDC protocol implementation (800+ lines)
- `apps/templates/oidc/login.html` - OIDC authorization login page

### Updated Files

- `apps/__init__.py` - Register OIDC blueprint
- `apps/blueprints/admin/routes.py` - Added POST handlers for admin operations
- `apps/templates/admin/clients/list.html` - Fixed form action URL
- `apps/templates/admin/roles/list.html` - Fixed form action URL, updated icons
- `apps/templates/admin/groups/list.html` - Fixed form action URL
- `apps/templates/admin/realms/settings.html` - Fixed form action URL
- `apps/templates/includes/admin_sidebar.html` - Fixed Realm Roles icon

### Documentation

- **Postman Collection**: Comprehensive OIDC testing collection with all grant types
  - Authorization Code Flow (with and without PKCE)
  - Password Grant Flow
  - Client Credentials Flow
  - Refresh Token Flow
  - Token operations (UserInfo, Introspect, Revoke)
- **Environment Variables**: Updated Postman environment with OIDC variables

---

## [2.1.2] 2026-01-25 - Security Fix: Login Authentication Bug
### Bug Fixes

- **Critical: Login Session Not Persisting**: Fixed bug where login would redirect to admin but session cookie was never set, causing immediate redirect back to login page
- **Security: Removed Vulnerable `request_loader`**: The `request_loader` function was authenticating users based ONLY on form username without password verification - a critical security vulnerability that allowed bypassing authentication
- **Root Cause**: `request_loader` in `apps/blueprints/auth/__init__.py` was returning user object when form contained username, causing Flask-Login to mark user as authenticated before password verification in the login route

### Changes

- Removed insecure `request_loader` from `apps/blueprints/auth/__init__.py`
- Added session cookie configuration in `apps/config.py` (SESSION_COOKIE_NAME, PERMANENT_SESSION_LIFETIME, REMEMBER_COOKIE_* settings)
- Cleaned up login route with proper Flask-Login flow using `login_user(user, remember=True)`

### Security Impact

Before fix: Any attacker could access admin panel by simply submitting a form with a valid username (no password required)
After fix: Proper authentication flow requires valid username AND password verification

---

## [2.1.0] 2026-01-25 - RijanAuth Phase 2.1: Admin UI Foundation
### New Features

- **Admin Console Blueprint**: Complete admin UI at `/admin/` with 26 routes
- **Realm Navigation**: Realm selector dropdown with context-aware navigation
- **Keycloak-style Theme**: Purple (#673ab7) theme with modern card-based design
- **Admin Dashboard**: Statistics cards, realm info, recent events, quick actions
- **User Management UI**: List, create, detail pages with tabs (credentials, roles, groups, sessions)
- **Client Management UI**: List and detail pages with settings, credentials, roles tabs
- **Role/Group Management**: Listing pages with create modals
- **Events & Sessions**: Event log viewer and active session management

### New Files

- `apps/blueprints/admin/__init__.py` - Admin blueprint registration
- `apps/blueprints/admin/routes.py` - 15 web routes for admin pages
- `apps/blueprints/admin/api.py` - 11 REST API endpoints
- `apps/templates/layouts/admin_base.html` - Admin theme base layout
- `apps/templates/includes/admin_sidebar.html` - Realm selector + navigation
- `apps/templates/admin/dashboard.html` - Admin dashboard
- `apps/templates/admin/users/` - list.html, create.html, detail.html
- `apps/templates/admin/clients/` - list.html, detail.html
- `apps/templates/admin/roles/list.html` - Realm roles listing
- `apps/templates/admin/groups/list.html` - Groups with hierarchy
- `apps/templates/admin/events/list.html` - Login events
- `apps/templates/admin/sessions/list.html` - Active sessions
- `apps/templates/admin/realms/` - settings.html, create.html

### Changes

- Updated `apps/__init__.py` to register admin blueprint
- Added `find_by_id()` method to User model

## [2.1.1] 2026-01-25 - RijanAuth Phase 2.1.1: Database Seeding & Bug Fixes
### New Features

- **Automated Database Seeding**: Automatic initialization mechanism (`apps/seeders/`)
  - **Master Realm**: Auto-created with Keycloak defaults
  - **Auth Flows**: Browser, Registration, Direct Grant, Clients flows
  - **Admin User**: Secure admin user creation with password reset requirement
  - **System Events**: Audit logging configuration

### Bug Fixes

- **Login Authentication**: Fixed login logic to authenticate against RijanAuth `User` model instead of legacy `Users` table
- **Admin Access**: Fixed 403 Forbidden error on admin pages by correcting `unauthorized_handler` redirect
- **User Loading**: Updated Flask-Login `user_loader` to support new `User` model UUIDs
- **Password Verification**: Added bcrypt verification support to `User` model

### New Files

- `apps/seeders/` - Seeder implementation files
- `docs/initial_setup.md` - Setup and seeding documentation
- `SEEDING.md` - Developer guide for seeders
- `reset_admin.py` - Utility to reset admin password

### Cleanup
- **Legacy Removal**: Removed original Datta Able authentication blueprints (`authentication`, `home`)
- **Template Cleanup**: Deleted unused demo templates, sample pages, and legacy layouts
- **Asset Optimization**: Removed demo images, sliders, and unused JS plugins
- **Architectural Shift**: Replaced monolithic structure with clean `auth` and `admin` blueprints

### Documentation
- **Postman Collection**: Comprehensive API collection (`RijanAuth.postman_collection.json`)
- **API Guide**: Detailed usage guide (`API_GUIDE.md`)
- **Environment config**: Postman environment preset (`RijanAuth-Environment.postman_environment.json`)

### Enhancements
- **System Health**: Added `/api/health` endpoint for monitoring
- **Login Debugging**: Enhanced logging for authentication troubleshooting

---

## [2.0.0] 2026-01-25 - RijanAuth Phase 1: Foundation
### New Features

- **RijanAuth Core Architecture**: Complete Keycloak-compatible identity platform foundation
- **Multi-Tenancy**: Realm-based isolation with automatic master realm creation
- **Database Schema**: 31 SQLite tables mirroring Keycloak's data model
  - Realms, Users, Credentials, User Attributes
  - Roles (realm/client), Role Mappings, Composite Roles
  - Groups with hierarchy, Group Memberships
  - OAuth/OIDC Clients, Client Scopes, Protocol Mappers
  - User Sessions, Refresh Tokens, Authorization Codes
  - Identity Providers, Federated Identities
  - Authentication Flows, Executions, Required Actions
  - Login Events, Admin Events (audit logging)

### New Files

- `apps/models/` - 9 model files with 20+ database models
- `apps/services/` - RealmService, UserService, ClientService
- `apps/utils/crypto.py` - Password hashing (bcrypt), PKCE, TOTP utilities
- `apps/middleware/realm.py` - Realm context middleware for multi-tenancy

### Dependencies Added

- `bcrypt==4.1.2` - Password hashing
- `PyJWT==2.8.0` - JWT token handling
- `cryptography==41.0.7` - Cryptographic operations

### Changes

- Updated `apps/__init__.py` with model imports and master realm initialization
- Renamed legacy `Users` table to `legacy_users` to avoid conflict

---

## [1.0.17] 2024-03-05
### Changes

- Update [Custom Development](https://appseed.us/custom-development/) Section
  - New Pricing: `$3,999`

## [1.0.16] 2023-02-14
### Changes

- Update [Custom Development](https://appseed.us/custom-development/) Section
- Minor Changes (readme)

## [1.0.15] 2023-10-08
### Changes

- Docs Update (readme)
- Added infos for [Flask Datta PRO](https://appseed.us/product/datta-able-pro/flask/)

## [1.0.14] 2023-10-08
### Changes

- Update Dependencies

## [1.0.13] 2023-01-02
### Changes

- `DOCS Update` (readme)
  - [Flask Datta Able - Go LIVE](https://www.youtube.com/watch?v=ZpKy2j9UU84) (`video presentation`)

## [1.0.12] 2022-12-31
### Changes

- Deployment-ready for Render (CI/CD)
  - `render.yaml`
  - `build.sh`
- `DB Management` Improvement
  - `Silent fallback` to **SQLite**

## [1.0.11] 2022-09-07
### Improvements

- Added OAuth via Github
- Improved Auth Pages
- Profile page (minor update) 

## [1.0.10] 2022-06-28
### Improvements

- Bump UI: `v1.0.0-enh1`
  - Added `dark-mode`
  - User profile page 

## [1.0.9] 2022-06-23
### Improvements

- Built with [Datta Able Generator](https://appseed.us/generator/datta-able/)
  - Timestamp: `2022-06-23 18:20`

## [1.0.8] 2022-06-13
### Improvements

- Improved `Auth UX`
- Built with [Datta Able Generator](https://appseed.us/generator/datta-able/)
  - Timestamp: `2022-05-30 21:10`

## [1.0.7] 2022-05-30
### Improvements

- Built with [Datta Able Generator](https://appseed.us/generator/datta-able/)
  - Timestamp: `2022-05-30 21:10`

## [1.0.6] 2022-03-30
### Fixes

- **Patch ImportError**: [cannot import name 'safe_str_cmp' from 'werkzeug.security'](https://docs.appseed.us/content/how-to-fix/importerror-cannot-import-name-safe_str_cmp-from-werkzeug.security)
  - `Werkzeug` deprecation of `safe_str_cmp` starting with version `2.1.0`
    - https://github.com/pallets/werkzeug/issues/2359

## [1.0.5] 2022-01-16
### Improvements

- Bump Flask Codebase to [v2stable.0.1](https://github.com/app-generator/boilerplate-code-flask-dashboard/releases)
- Dependencies update (all packages) 
  - Flask==2.0.2 (latest stable version)
  - flask_wtf==1.0.0
  - jinja2==3.0.3
  - flask-restx==0.5.1
- Forms Update:
  - Replace `TextField` (deprecated) with `StringField`

## Unreleased
### Fixes

- 2021-11-08 - `v1.0.5-rc1`
  - ImportError: cannot import name 'TextField' from 'wtforms'
    - Problem caused by `WTForms-3.0.0`
    - Fix: use **WTForms==2.3.3**

## [1.0.4] 2021-11-06
### Improvements

- Bump Codebase: [Flask Dashboard](https://github.com/app-generator/boilerplate-code-flask-dashboard) v2.0.0
  - Dependencies update (all packages) 
    - Flask==2.0.1 (latest stable version)
- Better Code formatting
- Improved Files organization
- Optimize imports
- Docker Scripts Update

## [1.0.3] 2021-05-16
### Dependencies Update

- Bump Codebase: [Flask Dashboard](https://github.com/app-generator/boilerplate-code-flask-dashboard) v1.0.6
- Freeze used versions in `requirements.txt`
    - jinja2 = 2.11.3

## [1.0.2] 2021-03-18
### Improvements

- Bump Codebase: [Flask Dashboard](https://github.com/app-generator/boilerplate-code-flask-dashboard) v1.0.5
- Freeze used versions in `requirements.txt`
    - flask_sqlalchemy = 2.4.4
    - sqlalchemy = 1.3.23
    
## [1.0.1] 2020-01-17
### Improvements

- Bump UI: [Jinja Datta Able](https://github.com/app-generator/jinja-datta-able/releases) v1.0.1
- UI: [Datta Able](https://github.com/codedthemes/datta-able-bootstrap-dashboard) 2021-01-01 snapshot
- Codebase: [Flask Dashboard](https://github.com/app-generator/boilerplate-code-flask-dashboard/releases) v1.0.3

## [1.0.0] 2020-02-07
### Initial Release
