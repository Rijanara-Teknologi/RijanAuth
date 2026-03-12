"""
Unit tests for database support in RijanAuth.

RijanAuth uses SQLite as its sole primary database.  MySQL and PostgreSQL
are supported exclusively as external *federation* targets (user-sync
sources), not as the application's own storage engine.

These tests verify:
  1. The application always configures a SQLite URI regardless of
     environment variables.
  2. The SQLite URI respects the DB_PATH override.
  3. The app creates and initialises correctly with SQLite.
  4. The PyMySQL driver is still installed (required by the MySQL
     federation provider for user-sync connections).
"""

import os
import importlib
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helper: reload apps.config with specific environment variables in place
# ---------------------------------------------------------------------------

def _load_config_with_env(env_vars: dict):
    """Return a freshly imported Config class after setting env_vars."""
    with patch.dict(os.environ, env_vars, clear=False):
        import apps.config as cfg_module
        importlib.reload(cfg_module)
        return cfg_module.Config


# ---------------------------------------------------------------------------
# Config-level tests – SQLite is always used as primary database
# ---------------------------------------------------------------------------

class TestSQLiteConfig:
    """Tests that confirm SQLite is always used as the primary database."""

    def test_default_uri_is_sqlite(self):
        """Without any DB env vars the config must use a SQLite URI."""
        cleaned = {
            k: v
            for k, v in os.environ.items()
            if k not in ("DB_ENGINE", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USERNAME", "DB_PASS", "DB_PATH")
        }
        with patch.dict(os.environ, cleaned, clear=True):
            import apps.config as cfg_module
            importlib.reload(cfg_module)
            Config = cfg_module.Config
        assert Config.SQLALCHEMY_DATABASE_URI.startswith("sqlite:///"), (
            f"Expected SQLite URI, got: {Config.SQLALCHEMY_DATABASE_URI}"
        )

    def test_db_path_env_overrides_sqlite_path(self):
        """DB_PATH env var must override the default sqlite file path."""
        custom_path = "/tmp/custom_test.sqlite3"
        cleaned = {
            k: v
            for k, v in os.environ.items()
            if k not in ("DB_ENGINE", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USERNAME", "DB_PASS")
        }
        cleaned["DB_PATH"] = custom_path
        with patch.dict(os.environ, cleaned, clear=True):
            import apps.config as cfg_module
            importlib.reload(cfg_module)
            Config = cfg_module.Config
        assert Config.SQLALCHEMY_DATABASE_URI == f"sqlite:///{custom_path}", (
            f"Unexpected URI: {Config.SQLALCHEMY_DATABASE_URI}"
        )

    def test_no_db_engine_class_variable(self):
        """Config must not expose DB_ENGINE as a class variable."""
        cleaned = {
            k: v
            for k, v in os.environ.items()
            if k not in ("DB_ENGINE", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USERNAME", "DB_PASS", "DB_PATH")
        }
        with patch.dict(os.environ, cleaned, clear=True):
            import apps.config as cfg_module
            importlib.reload(cfg_module)
            Config = cfg_module.Config
        assert not hasattr(Config, "DB_ENGINE"), (
            "Config should not expose DB_ENGINE – MySQL is not a supported primary DB"
        )


# ---------------------------------------------------------------------------
# App-factory tests
# ---------------------------------------------------------------------------

class TestAppWithSQLiteConfig:
    """Tests for creating the Flask application with SQLite."""

    def test_app_creates_with_sqlite(self):
        """The Flask application must initialise successfully with SQLite."""
        from apps import create_app, db

        config = {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SECRET_KEY": "sqlite-test-secret-key",
            "WTF_CSRF_ENABLED": False,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_SECURE": False,
        }

        app = create_app(config)
        assert app is not None

        with app.app_context():
            from sqlalchemy import text
            result = db.session.execute(text("SELECT 1")).fetchone()
            assert result[0] == 1

    def test_sqlite_uri_in_sqlalchemy_engine(self):
        """The SQLAlchemy engine URL must reflect the sqlite dialect."""
        from sqlalchemy.engine import make_url

        uri = "sqlite:////tmp/rijanauth_test.sqlite3"
        url = make_url(uri)
        assert url.drivername == "sqlite"
        assert url.database == "/tmp/rijanauth_test.sqlite3"


# ---------------------------------------------------------------------------
# Federation provider dependency tests
# ---------------------------------------------------------------------------

class TestFederationProviderDeps:
    """
    Verify that the drivers required by federation providers are installed.

    These drivers are NOT used for the application's primary database –
    they are used exclusively by the MySQL and PostgreSQL federation
    providers to connect to external user directories for synchronisation.
    """

    def test_pymysql_driver_importable(self):
        """PyMySQL must be installed (required by the MySQL federation provider)."""
        import pymysql  # noqa: F401
        assert pymysql.__version__ is not None

    def test_mysql_federation_provider_importable(self):
        """The MySQL federation provider module must be importable."""
        from apps.services.federation import mysql_provider  # noqa: F401

    def test_postgresql_federation_provider_importable(self):
        """The PostgreSQL federation provider module must be importable."""
        from apps.services.federation import postgresql_provider  # noqa: F401
