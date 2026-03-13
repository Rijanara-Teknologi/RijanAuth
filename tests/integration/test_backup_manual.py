"""
Tests for manual backup download, local server backup, and upload-restore
in backup_service.py.

Verifies that:
- BackupService.build_download_backup() builds a ZIP and creates a BackupRecord
  with storage_provider='download' and status='success'
- BackupService.build_download_backup() records a 'failed' BackupRecord when
  _build_zip raises an exception
- BackupService.save_local_backup() saves a ZIP file to the local filesystem
  and creates a BackupRecord with storage_provider='local_server'
- BackupService.cleanup_old_local_backups() purges files older than 30 days
- BackupService.restore_from_upload() delegates to _restore_zip correctly
- BackupService.restore_from_upload() propagates exceptions from _restore_zip
"""
import os
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# build_download_backup
# ---------------------------------------------------------------------------

class TestBuildDownloadBackup:

    def test_returns_zip_bytes_filename_and_size(self, app):
        """
        build_download_backup should return (bytes, filename, size) and the
        filename should match the rijanauth_backup_YYYYMMDD_HHMMSS.zip pattern.
        """
        import re
        from apps.services.backup_service import BackupService

        fake_zip = b'PK\x03\x04fake zip data'
        fake_size = len(fake_zip)

        with app.app_context():
            with patch('apps.services.backup_service._build_zip',
                       return_value=(fake_zip, fake_size)):
                zip_data, filename, size = BackupService.build_download_backup()

        assert zip_data == fake_zip
        assert size == fake_size
        assert re.match(r'^rijanauth_backup_\d{8}_\d{6}\.zip$', filename), (
            f"Unexpected filename format: {filename!r}"
        )

    def test_creates_successful_backup_record(self, app):
        """
        build_download_backup should persist a BackupRecord with
        storage_provider='local' and status='success' and a positive size_bytes.
        """
        from apps.services.backup_service import BackupService
        from apps.models.backup import BackupRecord

        user_id = 'test-user-id-record-check'

        with app.app_context():
            _, filename, _size = BackupService.build_download_backup(
                triggered_by_user_id=user_id
            )

            record = BackupRecord.query.filter_by(
                created_by_user_id=user_id,
                storage_provider='download',
            ).order_by(BackupRecord.backed_up_at.desc()).first()
            assert record is not None, "BackupRecord was not created"
            assert record.storage_provider == 'download'
            assert record.status == 'success'
            assert record.size_bytes is not None and record.size_bytes > 0
            assert record.created_by_user_id == user_id

    def test_records_failure_when_build_zip_raises(self, app):
        """
        When _build_zip raises an exception, build_download_backup should set
        the BackupRecord status to 'failed' and re-raise the exception.
        """
        from apps.services.backup_service import BackupService
        from apps.models.backup import BackupRecord

        with app.app_context():
            with patch('apps.services.backup_service._build_zip',
                       side_effect=RuntimeError('disk full')):
                with pytest.raises(RuntimeError, match='disk full'):
                    BackupService.build_download_backup()

            # Most recent record for 'download' should be failed
            record = (
                BackupRecord.query
                .filter_by(storage_provider='download', status='failed')
                .order_by(BackupRecord.backed_up_at.desc())
                .first()
            )
            assert record is not None, "Failed BackupRecord was not created"
            assert 'disk full' in record.error_message

    def test_password_forwarded_to_build_zip(self, app):
        """
        The password argument must be forwarded to _build_zip.
        """
        from apps.services.backup_service import BackupService

        fake_zip = b'PK\x03\x04pw protected'
        fake_size = len(fake_zip)

        with app.app_context():
            with patch('apps.services.backup_service._build_zip',
                       return_value=(fake_zip, fake_size)) as mock_build:
                BackupService.build_download_backup(password='s3cr3t')

        mock_build.assert_called_once_with('s3cr3t')


# ---------------------------------------------------------------------------
# restore_from_upload
# ---------------------------------------------------------------------------

class TestRestoreFromUpload:

    def test_delegates_to_restore_zip(self, app):
        """
        restore_from_upload must call _restore_zip with the provided bytes
        and password, and return its result.
        """
        from apps.services.backup_service import BackupService

        fake_stats = {'tables_restored': 3, 'rows_restored': 42, 'errors': []}
        fake_zip = b'PK\x03\x04uploaded zip'

        with app.app_context():
            with patch.object(BackupService, '_restore_zip',
                              return_value=fake_stats) as mock_restore:
                result = BackupService.restore_from_upload(fake_zip, password='pw')

        mock_restore.assert_called_once_with(fake_zip, 'pw')
        assert result == fake_stats

    def test_uses_none_password_by_default(self, app):
        """
        When no password is given, restore_from_upload passes None to _restore_zip.
        """
        from apps.services.backup_service import BackupService

        fake_stats = {'tables_restored': 1, 'rows_restored': 5, 'errors': []}

        with app.app_context():
            with patch.object(BackupService, '_restore_zip',
                              return_value=fake_stats) as mock_restore:
                BackupService.restore_from_upload(b'PK\x03\x04data')

        mock_restore.assert_called_once_with(b'PK\x03\x04data', None)

    def test_propagates_exception_from_restore_zip(self, app):
        """
        Exceptions from _restore_zip (e.g. bad password) should propagate
        unchanged through restore_from_upload.
        """
        from apps.services.backup_service import BackupService

        with app.app_context():
            with patch.object(BackupService, '_restore_zip',
                              side_effect=ValueError('Incorrect ZIP password')):
                with pytest.raises(ValueError, match='Incorrect ZIP password'):
                    BackupService.restore_from_upload(b'bad data', password='wrong')


# ---------------------------------------------------------------------------
# save_local_backup
# ---------------------------------------------------------------------------

class TestSaveLocalBackup:

    def test_saves_file_to_filesystem(self, app, tmp_path):
        """
        save_local_backup should write a non-empty ZIP file to the server
        filesystem and return a successful BackupRecord.
        """
        from apps.services.backup_service import BackupService
        from apps.models.backup import BackupRecord

        fake_zip = b'PK\x03\x04local zip data'
        fake_size = len(fake_zip)
        user_id = 'test-local-backup-user'

        with app.app_context():
            with patch('apps.services.backup_service._build_zip',
                       return_value=(fake_zip, fake_size)), \
                 patch('apps.services.backup_service.BACKUP_STORAGE_DIR',
                       str(tmp_path)):
                record = BackupService.save_local_backup(
                    triggered_by_user_id=user_id
                )

            assert record.status == 'success'
            assert record.storage_provider == 'local_server'
            assert record.size_bytes == fake_size
            assert record.local_file_path is not None
            assert os.path.isfile(record.local_file_path)

            with open(record.local_file_path, 'rb') as fh:
                assert fh.read() == fake_zip

    def test_records_failure_when_build_zip_raises(self, app, tmp_path):
        """
        When _build_zip fails, save_local_backup should set the BackupRecord
        status to 'failed' and re-raise.
        """
        from apps.services.backup_service import BackupService
        from apps.models.backup import BackupRecord

        with app.app_context():
            with patch('apps.services.backup_service._build_zip',
                       side_effect=RuntimeError('out of space')):
                with pytest.raises(RuntimeError, match='out of space'):
                    BackupService.save_local_backup()

            record = (
                BackupRecord.query
                .filter_by(storage_provider='local_server', status='failed')
                .order_by(BackupRecord.backed_up_at.desc())
                .first()
            )
            assert record is not None, "Failed BackupRecord was not created"
            assert 'out of space' in record.error_message


# ---------------------------------------------------------------------------
# cleanup_old_local_backups
# ---------------------------------------------------------------------------

class TestCleanupOldLocalBackups:

    def test_purges_old_files_and_marks_records(self, app, tmp_path):
        """
        cleanup_old_local_backups should delete files and mark records as
        'purged' when the backed_up_at date is older than 30 days.
        """
        from datetime import datetime, timedelta
        from apps.services.backup_service import BackupService, LOCAL_BACKUP_RETENTION_DAYS
        from apps.models.backup import BackupRecord
        from apps import db

        # Create an old backup file
        old_file = tmp_path / "old_backup.zip"
        old_file.write_bytes(b'PK old data')

        with app.app_context():
            old_record = BackupRecord(
                filename='old_backup.zip',
                storage_provider='local_server',
                status='success',
                local_file_path=str(old_file),
                backed_up_at=datetime.utcnow() - timedelta(days=LOCAL_BACKUP_RETENTION_DAYS + 1),
            )
            db.session.add(old_record)
            db.session.commit()
            old_id = old_record.id

            deleted = BackupService.cleanup_old_local_backups()

            assert deleted >= 1
            assert not old_file.exists(), "Old file should have been deleted"

            refreshed = BackupRecord.find_by_id(old_id)
            assert refreshed.status == 'purged'
            assert refreshed.local_file_path is None

    def test_keeps_recent_files(self, app, tmp_path):
        """
        cleanup_old_local_backups should NOT delete files that are recent
        (backed_up_at within the retention window).
        """
        from datetime import datetime, timedelta
        from apps.services.backup_service import BackupService
        from apps.models.backup import BackupRecord
        from apps import db

        recent_file = tmp_path / "recent_backup.zip"
        recent_file.write_bytes(b'PK recent data')

        with app.app_context():
            recent_record = BackupRecord(
                filename='recent_backup.zip',
                storage_provider='local_server',
                status='success',
                local_file_path=str(recent_file),
                backed_up_at=datetime.utcnow() - timedelta(days=5),
            )
            db.session.add(recent_record)
            db.session.commit()

            BackupService.cleanup_old_local_backups()

            assert recent_file.exists(), "Recent file should NOT have been deleted"
            refreshed = BackupRecord.find_by_id(recent_record.id)
            assert refreshed.status == 'success'
