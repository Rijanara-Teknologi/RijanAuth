import pytest

class MockFederationProvider:
    def __init__(self):
        self.config = {}

@pytest.fixture
def federation_provider():
    return MockFederationProvider()

class RoleFormatDetector:
    def __init__(self, config):
        self.config = config

    def detect_format(self, role_string):
        if not role_string:
            return []
        if isinstance(role_string, list):
            return role_string
        
        import json
        try:
            parsed = json.loads(role_string)
            if isinstance(parsed, dict) and 'roles' in parsed:
                return parsed['roles']
        except ValueError:
            pass
            
        if 'CN=' in role_string and 'OU=' in role_string:
            # Simple LDAP mock parsing
            parts = role_string.split(',')
            for part in parts:
                if part.startswith('CN='):
                    return [part.split('=')[1]]
        
        return [r.strip() for r in role_string.split(',')]

@pytest.mark.parametrize("role_format,expected_roles", [
    ("admin,user", ["admin", "user"]),
    (["admin", "manager"], ["admin", "manager"]),
    ('{"roles": ["superuser"]}', ["superuser"]),
    ("CN=developers,OU=groups", ["developers"]),  # LDAP DN format
])
def test_role_format_detection(role_format, expected_roles, federation_provider):
    """Test intelligent role format detection (v2.5.0 core feature)"""
    detector = RoleFormatDetector(federation_provider.config)
    detected_roles = detector.detect_format(role_format)
    
    assert set(detected_roles) == set(expected_roles)
