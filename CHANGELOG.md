# Change Log

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
