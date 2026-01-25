# -*- encoding: utf-8 -*-
"""
RijanAuth - Base Model
Common base class and utilities for all models
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declared_attr
from apps import db


def generate_uuid():
    """Generate a UUID string for primary keys"""
    return str(uuid.uuid4())


class TimestampMixin:
    """Mixin to add created_at and updated_at timestamps"""
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class SoftDeleteMixin:
    """Mixin for soft delete functionality"""
    
    deleted_at = Column(DateTime, nullable=True)
    
    @property
    def is_deleted(self):
        return self.deleted_at is not None
    
    def soft_delete(self):
        self.deleted_at = datetime.utcnow()


class BaseModel(db.Model, TimestampMixin):
    """
    Abstract base model with common functionality.
    Uses UUID as primary key for better distributed system compatibility.
    """
    __abstract__ = True
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    def save(self):
        """Save the model instance to database"""
        try:
            db.session.add(self)
            db.session.commit()
            return self
        except Exception as e:
            db.session.rollback()
            raise e
    
    def delete(self):
        """Delete the model instance from database"""
        try:
            db.session.delete(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e
    
    def update(self, **kwargs):
        """Update model attributes"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self.save()
    
    @classmethod
    def find_by_id(cls, id):
        """Find a model instance by its ID"""
        return cls.query.filter_by(id=id).first()
    
    @classmethod
    def find_all(cls):
        """Get all instances of this model"""
        return cls.query.all()
    
    def to_dict(self):
        """Convert model to dictionary (override in subclasses for custom serialization)"""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class RealmScopedModel(BaseModel):
    """
    Abstract base for models that belong to a realm.
    Provides realm_id foreign key and related query methods.
    """
    __abstract__ = True
    
    @declared_attr
    def realm_id(cls):
        return Column(String(36), db.ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    
    @classmethod
    def find_by_realm(cls, realm_id):
        """Find all instances belonging to a specific realm"""
        return cls.query.filter_by(realm_id=realm_id).all()
    
    @classmethod
    def find_by_realm_and_id(cls, realm_id, id):
        """Find instance by realm and ID"""
        return cls.query.filter_by(realm_id=realm_id, id=id).first()
