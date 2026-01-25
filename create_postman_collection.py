
import json
import os
import uuid

def generate_collection():
    collection = {
        "info": {
            "name": "RijanAuth API Collection",
            "description": "Comprehensive API documentation for RijanAuth Identity Server",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": []
    }

    # 0. Setup & Authentication
    folder_setup = {
        "name": "0. Setup & Authentication",
        "item": [
            {
                "name": "System Health",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/health",
                        "host": ["{{base_url}}"],
                        "path": ["api", "health"]
                    }
                }
            },
            {
                "name": "Admin Login (Session)",
                "event": [
                    {
                        "listen": "test",
                        "script": {
                            "exec": [
                                "pm.test(\"Status code is 200\", function () {",
                                "    pm.response.to.have.status(200);",
                                "});",
                                "// Cookie is automatically saved by Postman"
                            ],
                            "type": "text/javascript"
                        }
                    }
                ],
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/x-www-form-urlencoded", "type": "text"}
                    ],
                    "body": {
                        "mode": "urlencoded",
                        "urlencoded": [
                            {"key": "username", "value": "{{admin_username}}", "type": "text"},
                            {"key": "password", "value": "{{admin_password}}", "type": "text"}
                        ]
                    },
                    "url": {
                        "raw": "{{base_url}}/auth/login",
                        "host": ["{{base_url}}"],
                        "path": ["auth", "login"]
                    }
                }
            },
            {
                "name": "Admin Logout",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/auth/logout",
                        "host": ["{{base_url}}"],
                        "path": ["auth", "logout"]
                    }
                }
            }
        ]
    }
    collection["item"].append(folder_setup)

    # 1. Realm Management
    folder_realms = {
        "name": "1. Realm Management",
        "item": [
            {
                "name": "List Realms",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/realms",
                        "host": ["{{base_url}}"],
                        "path": ["api", "realms"]
                    }
                }
            },
            {
                "name": "Get Realm Details",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/realms/{{master_realm}}",
                        "host": ["{{base_url}}"],
                        "path": ["api", "realms", "{{master_realm}}"]
                    }
                }
            }
        ]
    }
    collection["item"].append(folder_realms)

    # 2. User Management
    folder_users = {
        "name": "2. User Management",
        "item": [
            {
                "name": "List Users",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/{{master_realm}}/users",
                        "host": ["{{base_url}}"],
                        "path": ["api", "{{master_realm}}", "users"]
                    }
                }
            },
            {
                "name": "Create User",
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json", "type": "text"}],
                    "body": {
                        "mode": "raw",
                        "raw": json.dumps({
                            "username": "{{test_user}}",
                            "email": "test@example.com",
                            "firstName": "Test",
                            "lastName": "User",
                            "enabled": True,
                            "credentials": [{"type": "password", "value": "{{test_user_password}}"}]
                        }, indent=2)
                    },
                    "url": {
                        "raw": "{{base_url}}/api/{{master_realm}}/users",
                        "host": ["{{base_url}}"],
                        "path": ["api", "{{master_realm}}", "users"]
                    }
                }
            },
            {
                "name": "Create Service Account",
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json", "type": "text"}],
                    "body": {
                        "mode": "raw",
                        "raw": json.dumps({
                            "username": "service-account",
                            "enabled": True
                        }, indent=2)
                    },
                    "url": {
                        "raw": "{{base_url}}/api/{{master_realm}}/users",
                        "host": ["{{base_url}}"],
                        "path": ["api", "{{master_realm}}", "users"]
                    }
                }
            }
        ]
    }
    collection["item"].append(folder_users)
    
    # 3. Client Management
    folder_clients = {
        "name": "3. Client Management",
        "item": [
            {
                "name": "List Clients",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/{{master_realm}}/clients",
                        "host": ["{{base_url}}"],
                        "path": ["api", "{{master_realm}}", "clients"]
                    }
                }
            }
        ]
    }
    collection["item"].append(folder_clients)

    # 4. Role Management
    folder_roles = {
        "name": "4. Role Management",
         "item": [
            {
                "name": "List Roles",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/{{master_realm}}/roles",
                        "host": ["{{base_url}}"],
                        "path": ["api", "{{master_realm}}", "roles"]
                    }
                }
            }
        ]
    }
    collection["item"].append(folder_roles)
    
     # 5. Group Management
    folder_groups = {
        "name": "5. Group Management",
         "item": [
            {
                "name": "List Groups",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/{{master_realm}}/groups",
                        "host": ["{{base_url}}"],
                        "path": ["api", "{{master_realm}}", "groups"]
                    }
                }
            }
        ]
    }
    collection["item"].append(folder_groups)


    return collection

def generate_environment():
    env = {
        "id": "rija-auth-env",
        "name": "RijanAuth Environment",
        "values": [
            {"key": "base_url", "value": "http://localhost:3000", "enabled": True},
            {"key": "master_realm", "value": "master", "enabled": True},
            {"key": "admin_username", "value": "admin", "enabled": True},
            {"key": "admin_password", "value": "_osnR8GKj1Cdv6FKZ8pmwg", "enabled": True},
            {"key": "test_realm", "value": "test-realm", "enabled": True},
            {"key": "test_user", "value": "testuser_" + str(uuid.uuid4())[:8], "enabled": True},
            {"key": "test_user_password", "value": "TestPass123!", "enabled": True}
        ]
    }
    return env

if __name__ == "__main__":
    collection = generate_collection()
    with open("RijanAuth.postman_collection.json", "w") as f:
        json.dump(collection, f, indent=2)
        
    env = generate_environment()
    with open("RijanAuth-Environment.postman_environment.json", "w") as f:
        json.dump(env, f, indent=2)
        
    print("Postman files generated.")
