# RijanAuth API Guide

This guide explains how to use the RijanAuth Postman Collection to interact with the RijanAuth Identity Server.

## 1. Prerequisites

- **RijanAuth Server** running on `http://localhost:3000`
- **Postman** installed

## 2. Importing Collection

1. Open Postman.
2. Clilck **Import**.
3. Drag and drop `RijanAuth.postman_collection.json` and `RijanAuth-Environment.postman_environment.json`.
4. Select "RijanAuth Environment" from the environment dropdown in top right.

## 3. Authentication (Method: Session)

Current version (v2.1.1) uses **Session-based Authentication** (Cookies) for the Admin API. Token-based authentication (OIDC) will be available in Phase 3.

**Steps to Authenticate:**
1. Open folder `0. Setup & Authentication`.
2. Select `Admin Login (Session)`.
3. Click **Send**.
4. Verify status is **200 OK**.
5. Postman automatically saves the session cookie.
6. Now you can run other requests (e.g. `1. Realm Management / List Realms`).

## 4. Workflows

### User Management
1. **List Users**: Get all users in the master realm.
2. **Create User**: Creates a new user (default: `testuser`).
3. **Get Details**: Retrieve the created user by ID.

### Realm Management
- **List Realms**: See all configured realms.
- **Get Realm**: Get details about `master` realm.

## 5. Troubleshooting

- **Login Fails (401/403)**: Ensure your environment variables `admin_username` and `admin_password` are correct (`admin` / `_osnR8GKj1Cdv6FKZ8pmwg`).
- **CSRF Errors**: Currently CSRF protection relies on session; ensure cookies are enabled in Postman.
- **Connection Refused**: Ensure server is running (`python run.py`).

## 6. Future Features (Phase 3)
- OIDC Token Endpoint (`/auth/realms/{realm}/protocol/openid-connect/token`)
- Bearer Token Authentication for APIs
- Identity Provider Management
