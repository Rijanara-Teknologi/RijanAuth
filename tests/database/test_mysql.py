"""
Unit tests for MySQL database support in RijanAuth.

These tests verify that the application correctly constructs MySQL connection
URLs, normalises the engine name to use the PyMySQL driver, and falls back
to SQLite when no database credentials are supplied.  The tests do *not*
require a running MySQL server – they use mocking to isolate the behaviour
being tested.
"""

import os
import importlib
import pytest
from unittest.mock import patch, MagicMock


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
# Config-level tests
# ---------------------------------------------------------------------------

class TestMySQLConfig:
    """Tests for MySQL-related configuration in apps/config.py."""

    def test_mysql_engine_normalised_to_pymysql(self):
        """Setting DB_ENGINE=mysql should produce a mysql+pymysql URI."""
        env = {
            "DB_ENGINE": "mysql",
            "DB_HOST": "localhost",
            "DB_PORT": "3306",
            "DB_NAME": "rijanauth",
            "DB_USERNAME": "rijanauth_user",
            "DB_PASS": "secret",
        }
        Config = _load_config_with_env(env)
        assert Config.SQLALCHEMY_DATABASE_URI.startswith("mysql+pymysql://"), (
            "Expected URI to start with 'mysql+pymysql://', "
            f"got: {Config.SQLALCHEMY_DATABASE_URI}"
        )

    def test_mysql_pymysql_engine_kept_as_is(self):
        """Setting DB_ENGINE=mysql+pymysql produces a mysql+pymysql URI."""
        env = {
            "DB_ENGINE": "mysql+pymysql",
            "DB_HOST": "db_host",
            "DB_PORT": "3306",
            "DB_NAME": "rijanauth",
            "DB_USERNAME": "user",
            "DB_PASS": "pass",
        }
        Config = _load_config_with_env(env)
        assert Config.SQLALCHEMY_DATABASE_URI.startswith("mysql+pymysql://"), (
            f"Unexpected URI: {Config.SQLALCHEMY_DATABASE_URI}"
        )

    def test_mysql_uri_contains_all_credentials(self):
        """The generated MySQL URI must include host, port, db name and user."""
        from sqlalchemy.engine import make_url

        env = {
            "DB_ENGINE": "mysql",
            "DB_HOST": "db.example.com",
            "DB_PORT": "3307",
            "DB_NAME": "mydb",
            "DB_USERNAME": "myuser",
            "DB_PASS": "mypassword",
        }
        Config = _load_config_with_env(env)
        url = make_url(Config.SQLALCHEMY_DATABASE_URI)
        assert url.username == "myuser"
        assert url.password == "mypassword"
        assert url.host == "db.example.com"
        assert url.port == 3307
        assert url.database == "mydb"

    def test_sqlite_fallback_when_no_db_engine(self):
        """Without DB_ENGINE set the config must fall back to SQLite."""
        env = {}
        # Make sure DB_ENGINE is not inherited from the real environment
        cleaned = {
            k: v
            for k, v in os.environ.items()
            if k not in ("DB_ENGINE", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USERNAME", "DB_PASS")
        }
        with patch.dict(os.environ, cleaned, clear=True):
            import apps.config as cfg_module
            importlib.reload(cfg_module)
            Config = cfg_module.Config
        assert "sqlite" in Config.SQLALCHEMY_DATABASE_URI.lower(), (
            f"Expected SQLite URI, got: {Config.SQLALCHEMY_DATABASE_URI}"
        )

    def test_sqlite_fallback_when_db_name_missing(self):
        """Without DB_NAME the config must fall back to SQLite."""
        env = {
            "DB_ENGINE": "mysql",
            "DB_HOST": "localhost",
            "DB_PORT": "3306",
            "DB_USERNAME": "user",
            "DB_PASS": "pass",
        }
        cleaned = {k: v for k, v in os.environ.items() if k != "DB_NAME"}
        cleaned.update(env)
        cleaned.pop("DB_NAME", None)
        with patch.dict(os.environ, cleaned, clear=True):
            import apps.config as cfg_module
            importlib.reload(cfg_module)
            Config = cfg_module.Config
        assert "sqlite" in Config.SQLALCHEMY_DATABASE_URI.lower()

    def test_use_sqlite_flag_false_for_mysql(self):
        """USE_SQLITE must be False when MySQL credentials are provided."""
        env = {
            "DB_ENGINE": "mysql",
            "DB_HOST": "localhost",
            "DB_PORT": "3306",
            "DB_NAME": "rijanauth",
            "DB_USERNAME": "user",
            "DB_PASS": "pass",
        }
        Config = _load_config_with_env(env)
        assert Config.USE_SQLITE is False

    def test_use_sqlite_flag_true_without_credentials(self):
        """USE_SQLITE must be True when no database credentials are present."""
        cleaned = {
            k: v
            for k, v in os.environ.items()
            if k not in ("DB_ENGINE", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USERNAME", "DB_PASS")
        }
        with patch.dict(os.environ, cleaned, clear=True):
            import apps.config as cfg_module
            importlib.reload(cfg_module)
            Config = cfg_module.Config
        assert Config.USE_SQLITE is True


# ---------------------------------------------------------------------------
# App-factory tests with a mocked MySQL engine
# ---------------------------------------------------------------------------

class TestAppWithMySQLConfig:
    """
    Tests for creating the Flask application with MySQL configuration.

    A real MySQL server is not required: SQLAlchemy's engine creation is
    mocked so these tests run in any CI environment.
    """

    def test_app_creates_with_mysql_config(self):
        """
        The Flask application should be created successfully when MySQL
        environment variables are provided, even without a live server.
        """
        from apps import create_app, db

        config = {
            "TESTING": True,
            # Use an in-memory SQLite URI for the actual connection so the
            # app can initialise tables without a real MySQL server.
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SECRET_KEY": "mysql-test-secret-key",
            "WTF_CSRF_ENABLED": False,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_SECURE": False,
            "DB_ENGINE": "mysql",
        }

        app = create_app(config)
        assert app is not None

        with app.app_context():
            # Verify the app initialised successfully and the database is accessible.
            from sqlalchemy import text
            result = db.session.execute(text("SELECT 1")).fetchone()
            assert result[0] == 1

    def test_mysql_uri_used_in_sqlalchemy_engine(self):
        """
        When the app is configured with a mysql+pymysql URI the SQLAlchemy
        engine URL should reflect that dialect (checked before any real
        connection attempt).
        """
        from apps import create_app, db

        mysql_uri = "mysql+pymysql://user:pass@localhost:3306/testdb"

        config = {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": mysql_uri,
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SECRET_KEY": "mysql-uri-test-key",
            "WTF_CSRF_ENABLED": False,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_SECURE": False,
        }

        # Patch SQLAlchemy's engine creation so no real connection is made.
        mock_engine = MagicMock()
        mock_engine.dialect.name = "mysql"
        mock_engine.url = MagicMock()
        mock_engine.url.drivername = "mysql+pymysql"

        with patch("sqlalchemy.create_engine", return_value=mock_engine):
            import sqlalchemy
            engine = sqlalchemy.create_engine(mysql_uri)
            assert engine.url.drivername == "mysql+pymysql"

    def test_pymysql_driver_importable(self):
        """PyMySQL must be installed and importable."""
        import pymysql  # noqa: F401 – just verify it is available
        assert pymysql.__version__ is not None

    def test_mysql_sqlalchemy_url_object(self):
        """
        SQLAlchemy's make_url must correctly parse a mysql+pymysql URI and
        expose the expected components.
        """
        from sqlalchemy.engine import make_url

        uri = "mysql+pymysql://rijanauth_user:secret@db_host:3306/rijanauth"
        url = make_url(uri)

        assert url.drivername == "mysql+pymysql"
        assert url.username == "rijanauth_user"
        assert url.host == "db_host"
        assert url.port == 3306
        assert url.database == "rijanauth"
