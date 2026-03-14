# -*- encoding: utf-8 -*-
"""
RijanAuth - Import Job Model
Tracks asynchronous CSV import jobs for users, roles, and groups.
"""

import json
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime
from apps.models.base import BaseModel


class ImportJob(BaseModel):
    """
    Represents a background CSV import job.

    Lifecycle:
        pending  → processing → completed
                             → failed
    """
    __tablename__ = 'import_jobs'

    # The realm this job belongs to
    realm_id = Column(String(36), nullable=False, index=True)

    # 'users', 'roles', or 'groups'
    job_type = Column(String(20), nullable=False)

    # 'pending' | 'processing' | 'completed' | 'failed'
    status = Column(String(20), nullable=False, default='pending')

    # Row counts
    total_rows = Column(Integer, nullable=False, default=0)
    processed_rows = Column(Integer, nullable=False, default=0)
    imported = Column(Integer, nullable=False, default=0)
    updated = Column(Integer, nullable=False, default=0)
    skipped = Column(Integer, nullable=False, default=0)

    # JSON-encoded list of error dicts
    errors_json = Column(Text, nullable=False, default='[]')

    # Timestamps
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    # ------------------------------------------------------------------ #

    @property
    def errors(self):
        """Return the errors list (decoded from JSON)."""
        try:
            return json.loads(self.errors_json or '[]')
        except (ValueError, TypeError):
            return []

    @errors.setter
    def errors(self, value):
        self.errors_json = json.dumps(value)

    def to_dict(self):
        return {
            'id': self.id,
            'realm_id': self.realm_id,
            'job_type': self.job_type,
            'status': self.status,
            'total_rows': self.total_rows,
            'processed_rows': self.processed_rows,
            'imported': self.imported,
            'updated': self.updated,
            'skipped': self.skipped,
            'errors': self.errors,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'finished_at': self.finished_at.isoformat() if self.finished_at else None,
        }

    @classmethod
    def find_by_realm(cls, realm_id):
        return cls.query.filter_by(realm_id=realm_id).order_by(
            cls.created_at.desc()
        ).all()
