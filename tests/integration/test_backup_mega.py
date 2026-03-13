"""
Tests for Mega.nz backup upload/download in backup_service.py.

Verifies that:
- _upload_mega passes the folder handle (not the full tuple) as dest to m.upload()
- _upload_mega handles a freshly-created folder (create_folder dict response) correctly
- _upload_mega raises RuntimeError with a helpful message when mega.py cannot be imported
- _download_mega raises RuntimeError with a helpful message when mega.py cannot be imported
"""
import sys
import types
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_mega_module():
    """Return a minimal fake 'mega' package so tests don't need the real one."""
    fake_module = types.ModuleType('mega')
    fake_module.Mega = MagicMock
    sys.modules.setdefault('mega', fake_module)
    return fake_module


# ---------------------------------------------------------------------------
# _upload_mega
# ---------------------------------------------------------------------------

class TestUploadMega:

    def test_uses_folder_handle_when_folder_exists(self, tmp_path):
        """
        When m.find() returns an existing folder as (handle, node), _upload_mega
        must pass the handle string (index 0) – not the whole tuple – to m.upload().
        """
        from apps.services.backup_service import _upload_mega

        folder_handle = 'FOLDER_HANDLE_123'
        folder_node = {'a': {'n': 'RijanAuth Backups'}, 't': 1}
        existing_folder = (folder_handle, folder_node)

        fake_uploaded = {'f': [{'h': 'FILE_HANDLE', 'k': 'abc:def'}]}
        fake_link = 'https://mega.nz/#!abc!def'

        # m = mega.login(...) – this is the object whose methods we control
        mock_m = MagicMock()
        mock_m.find.return_value = existing_folder
        mock_m.upload.return_value = fake_uploaded
        mock_m.get_upload_link.return_value = fake_link

        # Mega() returns an object whose .login() returns mock_m
        mock_mega_instance = MagicMock()
        mock_mega_instance.login.return_value = mock_m
        mock_mega_cls = MagicMock(return_value=mock_mega_instance)

        fake_module = types.ModuleType('mega')
        fake_module.Mega = mock_mega_cls

        with patch.dict(sys.modules, {'mega': fake_module}):
            handle, link = _upload_mega(
                b'dummy zip data',
                'backup.zip',
                {'email': 'user@example.com', 'password': 'secret'},
            )

        # dest must be the handle string, not the tuple
        assert mock_m.upload.called, "m.upload() was never called"
        dest_passed = mock_m.upload.call_args.kwargs.get('dest')
        assert dest_passed == folder_handle, (
            f"Expected dest='{folder_handle}' but got dest={dest_passed!r}. "
            "The full (handle, node) tuple must NOT be passed as dest."
        )
        assert link == fake_link

    def test_uses_created_folder_handle(self, tmp_path):
        """
        When m.find() returns None (folder doesn't exist), _upload_mega creates
        the folder and uses the returned handle from create_folder's dict.
        """
        from apps.services.backup_service import _upload_mega

        new_folder_handle = 'NEW_FOLDER_HANDLE'
        fake_uploaded = {'f': [{'h': 'FILE_HANDLE2', 'k': 'abc:xyz'}]}
        fake_link = 'https://mega.nz/#!xyz!abc'

        mock_m = MagicMock()
        mock_m.find.return_value = None  # folder does not exist
        mock_m.create_folder.return_value = {'RijanAuth Backups': new_folder_handle}
        mock_m.upload.return_value = fake_uploaded
        mock_m.get_upload_link.return_value = fake_link

        mock_mega_instance = MagicMock()
        mock_mega_instance.login.return_value = mock_m
        mock_mega_cls = MagicMock(return_value=mock_mega_instance)
        fake_module = types.ModuleType('mega')
        fake_module.Mega = mock_mega_cls

        with patch.dict(sys.modules, {'mega': fake_module}):
            handle, link = _upload_mega(
                b'dummy zip data',
                'backup.zip',
                {'email': 'user@example.com', 'password': 'secret'},
            )

        assert mock_m.upload.called, "m.upload() was never called"
        dest_passed = mock_m.upload.call_args.kwargs.get('dest')
        assert dest_passed == new_folder_handle, (
            f"Expected dest='{new_folder_handle}' but got dest={dest_passed!r}."
        )

    def test_raises_runtime_error_on_import_failure(self):
        """
        If importing mega raises an ImportError or AttributeError (e.g. Python
        3.11+ tenacity incompatibility), _upload_mega should raise RuntimeError
        with a helpful install message.
        """
        from apps.services.backup_service import _upload_mega

        # Simulate ImportError (mega.py not installed)
        with patch.dict(sys.modules, {'mega': None}):
            with pytest.raises(RuntimeError, match="mega.py"):
                _upload_mega(b'data', 'f.zip', {'email': 'a@b.c', 'password': 'x'})

    def test_raises_runtime_error_on_attribute_error_import(self):
        """
        If importing mega raises AttributeError (tenacity asyncio.coroutine removed
        in Python 3.11+), _upload_mega must still raise RuntimeError, not
        propagate the raw AttributeError.
        """
        from apps.services.backup_service import _upload_mega

        # Patch so that 'from mega import Mega' raises AttributeError
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == 'mega':
                raise AttributeError(
                    "module 'asyncio' has no attribute 'coroutine'"
                )
            return real_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=fake_import):
            with pytest.raises(RuntimeError, match="mega.py"):
                _upload_mega(b'data', 'f.zip', {'email': 'a@b.c', 'password': 'x'})


# ---------------------------------------------------------------------------
# _download_mega
# ---------------------------------------------------------------------------

class TestDownloadMega:

    def test_raises_runtime_error_on_import_failure(self):
        """
        If mega.py is not installed, _download_mega raises RuntimeError.
        """
        from apps.services.backup_service import _download_mega

        with patch.dict(sys.modules, {'mega': None}):
            with pytest.raises(RuntimeError, match="mega.py"):
                _download_mega('some_handle', {'email': 'a@b.c', 'password': 'x'})

    def test_raises_runtime_error_on_attribute_error_import(self):
        """
        AttributeError during mega import (Python 3.11+ tenacity issue) must be
        converted to a clear RuntimeError by _download_mega.
        """
        from apps.services.backup_service import _download_mega

        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == 'mega':
                raise AttributeError(
                    "module 'asyncio' has no attribute 'coroutine'"
                )
            return real_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=fake_import):
            with pytest.raises(RuntimeError, match="mega.py"):
                _download_mega('handle', {'email': 'a@b.c', 'password': 'x'})
