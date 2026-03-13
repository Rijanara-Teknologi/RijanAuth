# -*- encoding: utf-8 -*-
"""
RijanAuth - Backup Models
Models for backup configuration and backup history records
"""

from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Integer, Boolean
from apps.models.base import BaseModel


class BackupConfig(BaseModel):
    """
    Stores the active backup configuration.
    Only one row is used (global config for the master realm).
    """
    __tablename__ = 'backup_configs'

    # Kept for schema compatibility; not used for cloud providers any more.
    storage_provider = Column(String(50), nullable=True)

    # JSON-encoded settings.  Currently stores {"zip_password": "..."} for
    # the scheduled (local) auto-backup job.
    credentials_json = Column(Text, nullable=True)

    # Auto-backup interval: None / 'daily' / 'weekly' / 'monthly'
    auto_backup_interval = Column(String(20), nullable=True)

    # Scheduled backup timestamps
    next_backup_at = Column(DateTime, nullable=True)
    last_backup_at = Column(DateTime, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)

    @classmethod
    def get_config(cls):
        """Return the single active config row, or None."""
        return cls.query.filter_by(is_active=True).first()

    def to_dict(self):
        return {
            'id': self.id,
            'storage_provider': self.storage_provider,
            'auto_backup_interval': self.auto_backup_interval,
            'next_backup_at': self.next_backup_at.isoformat() if self.next_backup_at else None,
            'last_backup_at': self.last_backup_at.isoformat() if self.last_backup_at else None,
            'is_active': self.is_active,
        }


class BackupRecord(BaseModel):
    """
    A log of every backup that was created.
    Used for the restore history page.
    """
    __tablename__ = 'backup_records'

    # Filename of the zip (e.g. 'rijanauth_backup_20240101_120000.zip')
    filename = Column(String(255), nullable=False)

    # Backup type: 'local_server' (saved on server) | 'download' (browser download)
    storage_provider = Column(String(50), nullable=True)

    # Not used for new backups; kept for schema compatibility.
    remote_file_id = Column(String(500), nullable=True)

    # Absolute filesystem path for 'local_server' backups; NULL for downloads.
    local_file_path = Column(String(1000), nullable=True)

    # File size in bytes
    size_bytes = Column(Integer, nullable=True)

    # 'success' | 'failed' | 'in_progress'
    status = Column(String(20), default='in_progress', nullable=False)

    error_message = Column(Text, nullable=True)

    # ID of admin user who triggered the backup (may be NULL for auto-backups)
    created_by_user_id = Column(String(36), nullable=True)

    backed_up_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    @classmethod
    def get_history(cls, limit=50):
        """Return recent backup records ordered newest-first."""
        return (
            cls.query
            .order_by(cls.backed_up_at.desc())
            .limit(limit)
            .all()
        )

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'storage_provider': self.storage_provider,
            'local_file_path': self.local_file_path,
            'size_bytes': self.size_bytes,
            'status': self.status,
            'error_message': self.error_message,
            'created_by_user_id': self.created_by_user_id,
            'backed_up_at': self.backed_up_at.isoformat() if self.backed_up_at else None,
        }
