# RijanAuth Testing Guide

## Testing Strategy
RijanAuth utilizes `pytest` to ensure comprehensive code coverage out of the box, reflecting its goal to become a robust Keycloak alternative. All testing modules are mapped to core project features and can be easily expanded.

## Running Tests Locally
To run tests locally, utilize the included script for specific modules:
```bash
./scripts/run-tests.sh auth
```
To run the entire suite, simply execute: `pytest tests/`

## Test Fixtures
The testing framework uses shared fixtures inside `tests/conftest.py`. Currently available fixtures:
- `app`: Provides the application context.
- `client`: Provides the `FlaskTestClient` for HTTP request simulation.
- `test_realm`: Automatically provisions a sample `test-realm`.
- `test_user`: Provisions a mock user with standard attributes.
- `test_client`: Provisions a mock OIDC client.

## Mocking & Isolation
Always ensure your unit tests mock external dependencies. Using the `MockFederationProvider` as a guide inside `test_role_sync.py`, we can simulate external DBs or LDAP without standing up actual services locally.
Integration tests on the other hand, inside `tests/integration`, can use the initialized sqlite DB for full flow testing.

## Security Gates
We enforce Bandit security scanning prior to any branch merge. Review `bandt-report.html` output inside GitHub Actions after submitting your Pull Request.
