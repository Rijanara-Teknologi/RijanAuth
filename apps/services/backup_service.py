# -*- encoding: utf-8 -*-
"""
RijanAuth - Backup Service
Handles database backup, file archiving, local server storage and restore.

What gets backed up:
  1. Database  – full JSON dump of every table
  2. Media     – apps/static/media/ (uploaded logos / backgrounds)

The archive is a ZIP file (via pyzipper).  When a password is supplied, it is
protected with AES-256 encryption; without a password the archive is created
without encryption.

Backup types:
  - Manual Download : ZIP is sent directly to the admin's browser.
  - Local Server    : ZIP is saved in storage/backups/ on the RijanAuth server.
                      Local backups older than 30 days are automatically purged.
"""

import io
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

from flask import current_app
from apps import db
from apps.models.backup import BackupConfig, BackupRecord

logger = logging.getLogger(__name__)

# ── optional heavy deps (installed at runtime) ───────────────────────────────
try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

BACKUP_STORAGE_DIR = os.path.join('storage', 'backups')
LOCAL_BACKUP_RETENTION_DAYS = 30
INTERVAL_SECONDS = {
    'daily':   86400,
    'weekly':  604800,
    'monthly': 2629746,   # average Gregorian month (365.2425 / 12 days)
}


# =============================================================================
# Helper – collect all data into a JSON-serialisable dict
# =============================================================================

def _get_db_dump() -> Dict[str, Any]:
    """
    Export every SQLAlchemy table to a plain dict.
    Dates/UUIDs are serialised as strings.
    """
    dump: Dict[str, list] = {}
    for table in db.metadata.sorted_tables:
        rows = []
        try:
            result = db.session.execute(table.select())
            for row in result:
                row_dict = {}
                for key, value in row._mapping.items():
                    if isinstance(value, datetime):
                        row_dict[key] = value.isoformat()
                    else:
                        row_dict[key] = value
                rows.append(row_dict)
        except Exception as exc:
            logger.warning("Could not dump table %s: %s", table.name, exc)
        dump[table.name] = rows
    return dump


def _collect_media_files() -> Dict[str, bytes]:
    """
    Return a dict of {relative_path: file_bytes} for every media asset.
    """
    media_root = current_app.config.get('MEDIA_ROOT', os.path.join('apps', 'static', 'media'))
    files: Dict[str, bytes] = {}
    if os.path.isdir(media_root):
        for fname in os.listdir(media_root):
            fpath = os.path.join(media_root, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, 'rb') as fh:
                        files[os.path.join('media', fname)] = fh.read()
                except Exception as exc:
                    logger.warning("Could not read media file %s: %s", fpath, exc)
    return files


# =============================================================================
# Build ZIP archive
# =============================================================================

def _build_zip(password: Optional[str]) -> Tuple[bytes, int]:
    """
    Build a ZIP archive and return (bytes, size).
    If a password is provided, the archive is AES-256 encrypted.
    If password is empty or None, a plain (unencrypted) ZIP is created.
    Raises RuntimeError if pyzipper is not available.
    """
    if not PYZIPPER_AVAILABLE:
        raise RuntimeError(
            "pyzipper is not installed. Run: pip install pyzipper"
        )

    buf = io.BytesIO()

    if password:
        pwd_bytes = password.encode('utf-8')
        zip_ctx = pyzipper.AESZipFile(buf, 'w',
                                      compression=pyzipper.ZIP_DEFLATED,
                                      encryption=pyzipper.WZ_AES)
        zip_ctx.setpassword(pwd_bytes)
    else:
        zip_ctx = pyzipper.ZipFile(buf, 'w',
                                   compression=pyzipper.ZIP_DEFLATED)

    with zip_ctx as zf:

        # 1. Database JSON
        db_dump = _get_db_dump()
        db_json = json.dumps(db_dump, ensure_ascii=False, indent=2)
        zf.writestr('db_export.json', db_json)

        # 2. Manifest / README
        manifest = {
            'backup_version': '1.0',
            'created_at': datetime.utcnow().isoformat(),
            'product': 'RijanAuth',
            'contents': ['db_export.json', 'media/'],
        }
        zf.writestr('manifest.json', json.dumps(manifest, indent=2))

        # 3. Media assets
        for rel_path, data in _collect_media_files().items():
            zf.writestr(rel_path, data)

    data = buf.getvalue()
    return data, len(data)




# =============================================================================
# Public API
# =============================================================================

class BackupService:
    """
    High-level interface for backup and restore operations.
    """

    # ── Manual Download ───────────────────────────────────────────────────────

    @classmethod
    def build_download_backup(cls, password: Optional[str] = None,
                              triggered_by_user_id: Optional[str] = None
                              ) -> Tuple[bytes, str, int]:
        """
        Build a ZIP archive and return the raw bytes for direct browser download.

        Also creates a BackupRecord with storage_provider='download' so the
        action appears in the backup history.

        Returns (zip_bytes, filename, size_bytes).
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"rijanauth_backup_{timestamp}.zip"

        record = BackupRecord(
            filename=filename,
            storage_provider='download',
            status='in_progress',
            created_by_user_id=triggered_by_user_id,
            backed_up_at=datetime.utcnow(),
        )
        db.session.add(record)
        db.session.commit()

        try:
            zip_data, size = _build_zip(password)
        except Exception as exc:
            record.status = 'failed'
            record.error_message = str(exc)
            db.session.commit()
            raise

        record.status = 'success'
        record.size_bytes = size
        db.session.commit()

        return zip_data, filename, size

    # ── Local Server Backup ───────────────────────────────────────────────────

    @classmethod
    def save_local_backup(cls, password: Optional[str] = None,
                          triggered_by_user_id: Optional[str] = None
                          ) -> 'BackupRecord':
        """
        Build a ZIP archive and save it to the local server filesystem
        (BACKUP_STORAGE_DIR).  Creates a BackupRecord with
        storage_provider='local_server'.

        Returns the saved BackupRecord.
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"rijanauth_backup_{timestamp}.zip"

        record = BackupRecord(
            filename=filename,
            storage_provider='local_server',
            status='in_progress',
            created_by_user_id=triggered_by_user_id,
            backed_up_at=datetime.utcnow(),
        )
        db.session.add(record)
        db.session.commit()

        try:
            zip_data, size = _build_zip(password)
        except Exception as exc:
            record.status = 'failed'
            record.error_message = str(exc)
            db.session.commit()
            raise

        try:
            storage_dir = BACKUP_STORAGE_DIR
            os.makedirs(storage_dir, exist_ok=True)
            file_path = os.path.join(storage_dir, filename)
            with open(file_path, 'wb') as fh:
                fh.write(zip_data)
            record.status = 'success'
            record.size_bytes = size
            record.local_file_path = os.path.abspath(file_path)
        except Exception as exc:
            record.status = 'failed'
            record.error_message = str(exc)
            logger.exception("Local backup save failed: %s", exc)

        config = BackupConfig.get_config()
        if config:
            config.last_backup_at = datetime.utcnow()

        db.session.commit()
        return record

    # ── Cleanup old local backups ─────────────────────────────────────────────

    @classmethod
    def cleanup_old_local_backups(cls) -> int:
        """
        Delete local server backup files older than LOCAL_BACKUP_RETENTION_DAYS
        and update the corresponding BackupRecord rows to mark them as purged.

        Returns the number of files deleted.
        """
        cutoff = datetime.utcnow() - timedelta(days=LOCAL_BACKUP_RETENTION_DAYS)
        old_records = (
            BackupRecord.query
            .filter(
                BackupRecord.storage_provider == 'local_server',
                BackupRecord.status == 'success',
                BackupRecord.backed_up_at < cutoff,
                BackupRecord.local_file_path.isnot(None),
            )
            .all()
        )

        deleted = 0
        for rec in old_records:
            try:
                if rec.local_file_path and os.path.isfile(rec.local_file_path):
                    os.remove(rec.local_file_path)
                    deleted += 1
                rec.status = 'purged'
                rec.local_file_path = None
            except Exception as exc:
                logger.warning("Could not delete old backup %s: %s",
                               rec.local_file_path, exc)

        if old_records:
            db.session.commit()
            logger.info("Cleanup: removed %d old local backup(s).", deleted)

        return deleted

    # ── Restore ───────────────────────────────────────────────────────────────

    @classmethod
    def restore_from_record(cls, record_id: str,
                            password: Optional[str] = None) -> Dict[str, Any]:
        """
        Restore from a local server backup by its BackupRecord ID.

        Returns a dict with restore statistics.
        """
        record = BackupRecord.find_by_id(record_id)
        if not record:
            raise ValueError("Backup record not found.")
        if record.status != 'success':
            raise ValueError("Only successfully completed backups can be restored.")
        if record.storage_provider != 'local_server':
            raise ValueError("Only local server backups can be restored from history.")

        if not record.local_file_path or not os.path.isfile(record.local_file_path):
            raise ValueError(
                "Backup file not found on server. "
                "The file may have been deleted. Use Upload & Restore instead."
            )

        with open(record.local_file_path, 'rb') as fh:
            zip_data = fh.read()

        return cls._restore_zip(zip_data, password)

    @classmethod
    def restore_from_upload(cls, zip_data: bytes,
                            password: Optional[str] = None) -> Dict[str, Any]:
        """
        Restore the database from a manually uploaded ZIP archive.

        zip_data  – raw bytes of the ZIP file uploaded by the user.
        password  – optional decryption password.

        Returns a dict with restore statistics.
        """
        return cls._restore_zip(zip_data, password)

    @classmethod
    def _restore_zip(cls, zip_data: bytes, password: Optional[str]) -> Dict[str, Any]:
        if not PYZIPPER_AVAILABLE:
            raise RuntimeError("pyzipper is not installed.")

        buf = io.BytesIO(zip_data)
        stats: Dict[str, Any] = {'tables_restored': 0, 'rows_restored': 0, 'errors': []}

        try:
            zf_ctx = pyzipper.AESZipFile(buf, 'r')
            if password:
                zf_ctx.setpassword(password.encode('utf-8'))
            # Test decryption early by reading the file list
            zf_ctx.testzip()
        except (RuntimeError, Exception) as exc:
            if 'password' in str(exc).lower() or 'bad password' in str(exc).lower() or isinstance(exc, RuntimeError):
                raise ValueError("Incorrect ZIP password. Please check the password and try again.") from exc
            raise

        with zf_ctx as zf:
            # Validate manifest
            if 'manifest.json' in zf.namelist():
                try:
                    manifest = json.loads(zf.read('manifest.json'))
                    logger.info("Restoring backup from %s", manifest.get('created_at'))
                except Exception:
                    pass

            # Restore DB
            if 'db_export.json' not in zf.namelist():
                raise ValueError("Backup archive does not contain db_export.json.")

            try:
                db_dump = json.loads(zf.read('db_export.json').decode('utf-8'))
            except Exception as exc:
                raise ValueError("Incorrect ZIP password or corrupted archive.") from exc

            # Disable FK checks for the restore session (SQLite)
            try:
                db.session.execute(db.text("PRAGMA foreign_keys = OFF"))
            except Exception:
                pass

            for table_name, rows in db_dump.items():
                table_obj = db.metadata.tables.get(table_name)
                if table_obj is None:
                    stats['errors'].append(f"Table '{table_name}' not in schema, skipped.")
                    continue
                try:
                    db.session.execute(table_obj.delete())
                    if rows:
                        db.session.execute(table_obj.insert(), rows)
                    stats['tables_restored'] += 1
                    stats['rows_restored'] += len(rows)
                except Exception as exc:
                    db.session.rollback()
                    stats['errors'].append(f"{table_name}: {exc}")
                    logger.warning("Error restoring table %s: %s", table_name, exc)

            try:
                db.session.execute(db.text("PRAGMA foreign_keys = ON"))
            except Exception:
                pass

            db.session.commit()

            # Restore media files
            media_root = current_app.config.get(
                'MEDIA_ROOT', os.path.join('apps', 'static', 'media')
            )
            os.makedirs(media_root, exist_ok=True)
            for name in zf.namelist():
                if name.startswith('media/') and not name.endswith('/'):
                    try:
                        data = zf.read(name)
                        dest = os.path.join(media_root, os.path.basename(name))
                        with open(dest, 'wb') as fh:
                            fh.write(data)
                    except Exception as exc:
                        stats['errors'].append(f"Media {name}: {exc}")

        return stats

    # ── Scheduler ─────────────────────────────────────────────────────────────

    _scheduler = None

    @classmethod
    def init_scheduler(cls, app):
        """Start the APScheduler for auto-backups (call from app factory)."""
        if not SCHEDULER_AVAILABLE:
            logger.warning("APScheduler not available; auto-backup disabled.")
            return

        if cls._scheduler is not None:
            return

        cls._scheduler = BackgroundScheduler()
        cls._scheduler.start()
        logger.info("Backup scheduler started.")

        with app.app_context():
            cls._reschedule(app)

    @classmethod
    def _reschedule(cls, app=None):
        """Re-read config and reschedule (or cancel) the auto-backup job."""
        if not cls._scheduler:
            return

        job_id = 'auto_backup'
        cleanup_job_id = 'local_backup_cleanup'
        try:
            cls._scheduler.remove_job(job_id)
        except Exception:
            pass
        try:
            cls._scheduler.remove_job(cleanup_job_id)
        except Exception:
            pass

        config = BackupConfig.get_config()
        if not config or not config.auto_backup_interval:
            return

        seconds = INTERVAL_SECONDS.get(config.auto_backup_interval)
        if not seconds:
            return

        cls._scheduler.add_job(
            cls._run_auto_backup,
            'interval',
            seconds=seconds,
            id=job_id,
            replace_existing=True,
        )
        logger.info("Local auto-backup scheduled every %s.", config.auto_backup_interval)

        # Schedule daily cleanup of old local backups
        cls._scheduler.add_job(
            cls._run_cleanup,
            'interval',
            seconds=86400,
            id=cleanup_job_id,
            replace_existing=True,
        )
        logger.info("Local backup cleanup scheduled (daily).")

    @classmethod
    def _run_auto_backup(cls):
        """Called by the scheduler; needs an app context."""
        try:
            from flask import current_app
            with current_app.app_context():
                cls._do_auto_backup()
        except RuntimeError:
            logger.warning("No Flask app context for auto-backup run.")

    @classmethod
    def _run_cleanup(cls):
        """Called by the scheduler; needs an app context."""
        try:
            from flask import current_app
            with current_app.app_context():
                cls.cleanup_old_local_backups()
        except RuntimeError:
            logger.warning("No Flask app context for cleanup run.")

    @classmethod
    def _do_auto_backup(cls):
        config = BackupConfig.get_config()
        if not config or not config.auto_backup_interval:
            logger.warning("Auto-backup skipped: no interval configured.")
            return

        password = None
        if config.credentials_json:
            try:
                creds = json.loads(config.credentials_json)
                password = creds.get('zip_password') or None
            except (json.JSONDecodeError, TypeError):
                pass

        try:
            cls.save_local_backup(password)
            logger.info("Auto local backup completed successfully.")
        except Exception as exc:
            logger.error("Auto local backup failed: %s", exc)

    @classmethod
    def apply_config(cls, app=None):
        """Call after saving a new BackupConfig to reschedule jobs."""
        cls._reschedule(app)
