# -*- encoding: utf-8 -*-
"""
RijanAuth - Backup Service
Handles database backup, file archiving, cloud upload and restore operations.

What gets backed up:
  1. Database  – full JSON dump of every table
  2. Media     – apps/static/media/ (uploaded logos / backgrounds)

The archive is a password-protected AES-256 ZIP (via pyzipper).
Cloud providers: Google Drive, Mega.nz, Dropbox, Box
"""

import io
import os
import json
import logging
import tempfile
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
    from apscheduler.triggers.cron import CronTrigger
    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

BACKUP_STORAGE_DIR = os.path.join('storage', 'backups')
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

def _build_zip(password: str) -> Tuple[bytes, int]:
    """
    Build a password-protected AES-256 ZIP and return (bytes, size).
    Raises RuntimeError if pyzipper is not available.
    """
    if not PYZIPPER_AVAILABLE:
        raise RuntimeError(
            "pyzipper is not installed. Run: pip install pyzipper"
        )

    buf = io.BytesIO()
    pwd_bytes = password.encode('utf-8')

    with pyzipper.AESZipFile(buf, 'w',
                             compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(pwd_bytes)

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
# Cloud uploader helpers
# =============================================================================

def _upload_google_drive(zip_bytes: bytes, filename: str,
                         creds: Dict[str, Any]) -> Tuple[str, str]:
    """
    Upload to Google Drive using a Service Account JSON key.
    Returns (file_id, file_link).
    """
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseUpload
    except ImportError:
        raise RuntimeError(
            "google-api-python-client or google-auth are not installed.\n"
            "Run: pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib"
        )

    sa_info = json.loads(creds.get('service_account_json', '{}'))
    folder_id = creds.get('folder_id', '')

    scopes = ['https://www.googleapis.com/auth/drive.file']
    credentials = service_account.Credentials.from_service_account_info(
        sa_info, scopes=scopes
    )
    service = build('drive', 'v3', credentials=credentials, cache_discovery=False)

    file_metadata = {'name': filename}
    if folder_id:
        file_metadata['parents'] = [folder_id]

    media = MediaIoBaseUpload(io.BytesIO(zip_bytes),
                              mimetype='application/zip',
                              resumable=True)
    uploaded = service.files().create(
        body=file_metadata, media_body=media, fields='id,webViewLink'
    ).execute()

    return uploaded.get('id', ''), uploaded.get('webViewLink', '')


def _upload_mega(zip_bytes: bytes, filename: str,
                 creds: Dict[str, Any]) -> Tuple[str, str]:
    """
    Upload to Mega.nz.
    Returns (file_handle, file_link).
    """
    try:
        from mega import Mega
    except ImportError:
        raise RuntimeError(
            "mega.py is not installed. Run: pip install mega.py"
        )

    mega = Mega()
    m = mega.login(creds['email'], creds['password'])

    folder_name = creds.get('folder', 'RijanAuth Backups')
    folder = m.find(folder_name)
    if not folder:
        folder = m.create_folder(folder_name)
        if isinstance(folder, dict):
            folder = list(folder.values())[0]

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    try:
        tmp.write(zip_bytes)
        tmp.flush()
        tmp.close()
        uploaded = m.upload(tmp.name, dest=folder)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    link = m.get_upload_link(uploaded)
    handle = str(uploaded)
    return handle, link or ''


def _upload_dropbox(zip_bytes: bytes, filename: str,
                    creds: Dict[str, Any]) -> Tuple[str, str]:
    """
    Upload to Dropbox using OAuth2 refresh token.
    Returns (dropbox_path, shared_link).
    """
    try:
        import dropbox
        from dropbox.files import WriteMode
        from dropbox.exceptions import ApiError
    except ImportError:
        raise RuntimeError(
            "dropbox is not installed. Run: pip install dropbox"
        )

    dbx = dropbox.Dropbox(
        oauth2_refresh_token=creds.get('refresh_token', ''),
        app_key=creds.get('app_key', ''),
        app_secret=creds.get('app_secret', ''),
    )

    dest_path = f"/RijanAuth Backups/{filename}"
    dbx.files_upload(zip_bytes, dest_path, mode=WriteMode.overwrite)

    try:
        link_result = dbx.sharing_create_shared_link_with_settings(dest_path)
        shared_link = link_result.url
    except ApiError:
        shared_link = ''

    return dest_path, shared_link


def _upload_box(zip_bytes: bytes, filename: str,
                creds: Dict[str, Any]) -> Tuple[str, str]:
    """
    Upload to Box using a Developer Token (simple auth).
    Returns (file_id, file_url).
    """
    try:
        from boxsdk import Client, OAuth2
    except ImportError:
        raise RuntimeError(
            "boxsdk is not installed. Run: pip install boxsdk"
        )

    auth = OAuth2(
        client_id=creds.get('client_id', ''),
        client_secret=creds.get('client_secret', ''),
        access_token=creds.get('developer_token', ''),
    )
    client = Client(auth)

    folder_name = 'RijanAuth Backups'
    root_folder = client.folder('0')

    # Find or create backup folder
    folder_id = '0'
    try:
        items = root_folder.get_items()
        for item in items:
            if item.type == 'folder' and item.name == folder_name:
                folder_id = item.id
                break
        else:
            new_folder = root_folder.create_subfolder(folder_name)
            folder_id = new_folder.id
    except Exception:
        folder_id = '0'

    stream = io.BytesIO(zip_bytes)
    box_file = client.folder(folder_id).upload_stream(stream, filename)
    file_url = f"https://app.box.com/file/{box_file.id}"
    return box_file.id, file_url


# =============================================================================
# Public API
# =============================================================================

class BackupService:
    """
    High-level interface for backup and restore operations.
    """

    # ── Create backup ─────────────────────────────────────────────────────────

    @classmethod
    def create_backup(cls, password: str,
                      triggered_by_user_id: Optional[str] = None) -> BackupRecord:
        """
        Build a ZIP archive of the database + media files and upload it
        to the configured cloud provider.

        Returns the saved BackupRecord.
        Raises on fatal errors (no config, missing credentials, etc.).
        """
        config = BackupConfig.get_config()
        if not config or not config.storage_provider:
            raise ValueError(
                "No backup configuration found. "
                "Please configure a cloud storage provider first."
            )
        if not password:
            raise ValueError("A ZIP password is required for backup.")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"rijanauth_backup_{timestamp}.zip"

        record = BackupRecord(
            filename=filename,
            storage_provider=config.storage_provider,
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

        creds = {}
        if config.credentials_json:
            try:
                creds = json.loads(config.credentials_json)
            except json.JSONDecodeError:
                creds = {}

        try:
            file_id, file_path = cls._upload(
                zip_data, filename, config.storage_provider, creds
            )
            record.status = 'success'
            record.size_bytes = size
            record.remote_file_id = file_id
            record.remote_file_path = file_path
        except Exception as exc:
            record.status = 'failed'
            record.error_message = str(exc)
            logger.exception("Backup upload failed: %s", exc)

        config.last_backup_at = datetime.utcnow()
        db.session.commit()

        return record

    @classmethod
    def _upload(cls, zip_data: bytes, filename: str,
                provider: str, creds: Dict[str, Any]) -> Tuple[str, str]:
        if provider == 'google_drive':
            return _upload_google_drive(zip_data, filename, creds)
        if provider == 'mega':
            return _upload_mega(zip_data, filename, creds)
        if provider == 'dropbox':
            return _upload_dropbox(zip_data, filename, creds)
        if provider == 'box':
            return _upload_box(zip_data, filename, creds)
        raise ValueError(f"Unknown storage provider: {provider}")

    # ── Restore ───────────────────────────────────────────────────────────────

    @classmethod
    def restore_from_record(cls, record_id: str,
                            password: str) -> Dict[str, Any]:
        """
        Download a backup ZIP by its BackupRecord ID, decrypt it
        and restore the database from the embedded db_export.json.

        Returns a dict with restore statistics.
        """
        record = BackupRecord.find_by_id(record_id)
        if not record:
            raise ValueError("Backup record not found.")
        if record.status != 'success':
            raise ValueError("Only successfully completed backups can be restored.")

        config = BackupConfig.get_config()
        creds: Dict[str, Any] = {}
        if config and config.credentials_json:
            try:
                creds = json.loads(config.credentials_json)
            except json.JSONDecodeError:
                pass

        zip_data = cls._download(record, creds)
        stats = cls._restore_zip(zip_data, password)
        return stats

    @classmethod
    def _download(cls, record: BackupRecord,
                  creds: Dict[str, Any]) -> bytes:
        provider = record.storage_provider
        if provider == 'google_drive':
            return _download_google_drive(record.remote_file_id, creds)
        if provider == 'mega':
            return _download_mega(record.remote_file_id, creds)
        if provider == 'dropbox':
            return _download_dropbox(record.remote_file_id, creds)
        if provider == 'box':
            return _download_box(record.remote_file_id, creds)
        raise ValueError(f"Unknown storage provider: {provider}")

    @classmethod
    def _restore_zip(cls, zip_data: bytes, password: str) -> Dict[str, Any]:
        if not PYZIPPER_AVAILABLE:
            raise RuntimeError("pyzipper is not installed.")

        buf = io.BytesIO(zip_data)
        stats: Dict[str, Any] = {'tables_restored': 0, 'rows_restored': 0, 'errors': []}

        try:
            zf_ctx = pyzipper.AESZipFile(buf, 'r')
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
        try:
            cls._scheduler.remove_job(job_id)
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
        logger.info("Auto-backup scheduled every %s.", config.auto_backup_interval)

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
    def _do_auto_backup(cls):
        config = BackupConfig.get_config()
        if not config or not config.credentials_json:
            logger.warning("Auto-backup skipped: no credentials configured.")
            return

        creds = json.loads(config.credentials_json)
        password = creds.get('zip_password', '')
        if not password:
            logger.warning("Auto-backup skipped: no zip_password in credentials.")
            return

        try:
            cls.create_backup(password)
            logger.info("Auto-backup completed successfully.")
        except Exception as exc:
            logger.error("Auto-backup failed: %s", exc)

    @classmethod
    def apply_config(cls, app=None):
        """Call after saving a new BackupConfig to reschedule jobs."""
        cls._reschedule(app)


# =============================================================================
# Download helpers
# =============================================================================

def _download_google_drive(file_id: str, creds: Dict[str, Any]) -> bytes:
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload
    except ImportError:
        raise RuntimeError("google-api-python-client is not installed.")

    sa_info = json.loads(creds.get('service_account_json', '{}'))
    scopes = ['https://www.googleapis.com/auth/drive.file']
    credentials = service_account.Credentials.from_service_account_info(
        sa_info, scopes=scopes
    )
    service = build('drive', 'v3', credentials=credentials, cache_discovery=False)
    buf = io.BytesIO()
    request = service.files().get_media(fileId=file_id)
    downloader = MediaIoBaseDownload(buf, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return buf.getvalue()


def _download_mega(file_handle: str, creds: Dict[str, Any]) -> bytes:
    try:
        from mega import Mega
    except ImportError:
        raise RuntimeError("mega.py is not installed.")

    mega = Mega()
    m = mega.login(creds['email'], creds['password'])
    # mega.py download_url downloads to a file path, not a buffer
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    tmp.close()
    try:
        m.download_url(file_handle, dest_filename=tmp.name)
        with open(tmp.name, 'rb') as f:
            return f.read()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _download_dropbox(dropbox_path: str, creds: Dict[str, Any]) -> bytes:
    try:
        import dropbox
    except ImportError:
        raise RuntimeError("dropbox is not installed.")

    dbx = dropbox.Dropbox(
        oauth2_refresh_token=creds.get('refresh_token', ''),
        app_key=creds.get('app_key', ''),
        app_secret=creds.get('app_secret', ''),
    )
    _, response = dbx.files_download(dropbox_path)
    return response.content


def _download_box(file_id: str, creds: Dict[str, Any]) -> bytes:
    try:
        from boxsdk import Client, OAuth2
    except ImportError:
        raise RuntimeError("boxsdk is not installed.")

    auth = OAuth2(
        client_id=creds.get('client_id', ''),
        client_secret=creds.get('client_secret', ''),
        access_token=creds.get('developer_token', ''),
    )
    client = Client(auth)
    buf = io.BytesIO()
    client.file(file_id).download_to(buf)
    return buf.getvalue()
