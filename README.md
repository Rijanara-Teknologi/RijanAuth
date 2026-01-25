# RijanAuth

**RijanAuth** is a lightweight OpenID Connect and SSO server built with Python/Flask, designed as a Keycloak alternative with lower memory footprint. 

## ✨ Features

### Identity Management
- ✅ **Multi-Tenancy**: Realm-based isolation (like Keycloak)
- ✅ **User Management**: CRUD, attributes, credentials
- ✅ **Role-Based Access Control**: Realm and client roles with composite support
- ✅ **Group Management**: Hierarchical groups with role inheritance

### Authentication Protocols (Coming Soon)
- 🔜 **OpenID Connect**: Authorization Code (PKCE), Implicit, Client Credentials
- 🔜 **OAuth 2.0**: Full authorization server
- 🔜 **SAML 2.0**: Enterprise SSO support

### Security
- ✅ **Password Hashing**: bcrypt with configurable rounds
- ✅ **TOTP/2FA**: Time-based one-time passwords
- ✅ **PKCE Support**: Secure code exchange
- 🔜 **Brute Force Protection**: Configurable lockout policies

### Admin Console
- ✅ **Datta Able UI**: Modern Bootstrap admin template
- 🔜 **Realm Management**: Create and configure realms
- 🔜 **User/Client Management**: Full CRUD interface

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd rijansso

# Create virtual environment
python -m venv env

# Activate (Windows)
.\env\Scripts\activate

# Activate (Unix/macOS)
source env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run the Application

```bash
# Set environment variables (PowerShell)
$env:FLASK_APP = "run.py"
$env:FLASK_ENV = "development"

# Start the server
flask run
```

Visit `http://127.0.0.1:5000` in your browser.

---

## 📁 Project Structure

```
rijansso/
├── apps/
│   ├── models/                    # RijanAuth data models
│   │   ├── realm.py              # Realm (multi-tenancy)
│   │   ├── user.py               # User, Credentials, Attributes
│   │   ├── role.py               # Roles, Role Mappings
│   │   ├── group.py              # Groups with hierarchy
│   │   ├── client.py             # OAuth/OIDC clients
│   │   ├── session.py            # Sessions, Tokens
│   │   ├── identity_provider.py  # External IdP config
│   │   ├── authentication.py     # Auth flows
│   │   └── event.py              # Audit events
│   │
│   ├── services/                  # Business logic layer
│   │   ├── realm_service.py      # Realm CRUD
│   │   ├── user_service.py       # User management
│   │   └── client_service.py     # OAuth client management
│   │
│   ├── utils/                     # Utilities
│   │   └── crypto.py             # Password, PKCE, TOTP
│   │
│   ├── middleware/                # Middleware
│   │   └── realm.py              # Realm context
│   │
│   ├── authentication/            # Legacy auth (Datta Able)
│   ├── home/                      # Dashboard routes
│   ├── static/                    # CSS, JS, images
│   └── templates/                 # Jinja2 templates
│
├── requirements.txt
├── run.py                         # Application entry point
└── CHANGELOG.md
```

---

## 🔧 Configuration

Create a `.env` file in the project root:

```env
# Flask Configuration
DEBUG=True
SECRET_KEY=your-secret-key-here

# Assets
ASSETS_ROOT=/static/assets

# Database (optional - defaults to SQLite)
# DB_ENGINE=postgresql
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=rijanauth
# DB_USERNAME=postgres
# DB_PASS=password

# OAuth (optional)
GITHUB_ID=your-github-client-id
GITHUB_SECRET=your-github-client-secret
```

---

## 🐳 Docker

```bash
# Build and start
docker-compose up --build

# Access at http://localhost:5085
```

---

## 📊 Database

RijanAuth uses SQLite by default with 31 tables:

| Category | Tables |
|----------|--------|
| **Core** | realms, realm_attributes |
| **Users** | users, user_attributes, credentials |
| **Access Control** | roles, role_mappings, composite_roles |
| **Groups** | groups, group_memberships, group_attributes |
| **Clients** | clients, client_scopes, client_scope_mappings, protocol_mappers |
| **Sessions** | user_sessions, authenticated_client_sessions, refresh_tokens, authorization_codes |
| **Federation** | identity_providers, identity_provider_mappers, federated_identities |
| **Auth Flows** | authentication_flows, authentication_executions, authenticator_configs, required_actions |
| **Audit** | events, admin_events |

---

## 🗺️ Roadmap

- [x] **Phase 1**: Foundation & Core Architecture
- [ ] **Phase 2**: OAuth 2.0 / OpenID Connect Implementation
- [ ] **Phase 3**: Admin Console UI
- [ ] **Phase 4**: SAML 2.0 Support
- [ ] **Phase 5**: Identity Brokering & Social Login
- [ ] **Phase 6**: Account Management Console

---

## 📝 License

MIT License - See [LICENSE.md](LICENSE.md)

---

## 🙏 Credits

- **UI Template**: [Datta Able Flask](https://appseed.us/product/datta-able/flask/) by AppSeed
- **Inspiration**: [Keycloak](https://www.keycloak.org/) by Red Hat

---

Built with ❤️ by [PT Rijanara Inovasi Teknologi](https://rijanara.com)
