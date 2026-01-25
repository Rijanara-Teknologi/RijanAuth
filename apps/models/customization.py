# -*- encoding: utf-8 -*-
"""
RijanAuth - Page Customization Models
Realm-specific page customization and media assets
"""

import json
from sqlalchemy import Column, String, Text, Integer, ForeignKey, CheckConstraint
from sqlalchemy.orm import relationship
from apps.models.base import BaseModel, RealmScopedModel, generate_uuid
from apps import db


class RealmPageCustomization(BaseModel):
    """
    Realm Page Customization - Custom styling for authentication pages
    """
    __tablename__ = 'realm_page_customizations'
    
    realm_id = Column(String(36), ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    page_type = Column(String(50), nullable=False)  # 'login', 'register', 'forgot_password', 'consent', 'error'
    
    # Background settings
    background_type = Column(String(20), default='color', nullable=False)  # 'color', 'gradient', 'image'
    background_color = Column(String(20), default='#673AB7')
    background_gradient = Column(Text, nullable=True)  # JSON string: {"colors": ["#673AB7", "#3F51B5"], "direction": "to right"}
    background_image_id = Column(String(36), ForeignKey('media_assets.id', ondelete='SET NULL'), nullable=True)
    
    # Color scheme
    primary_color = Column(String(20), default='#673AB7')
    secondary_color = Column(String(20), default='#3F51B5')
    
    # Typography
    font_family = Column(String(100), default='Inter, system-ui, -apple-system, sans-serif')
    
    # Styling
    button_radius = Column(Integer, default=4)
    form_radius = Column(Integer, default=4)
    
    # Logo
    logo_id = Column(String(36), ForeignKey('media_assets.id', ondelete='SET NULL'), nullable=True)
    logo_position = Column(String(20), default='center')  # 'center', 'top', 'bottom'
    
    # Advanced
    custom_css = Column(Text, nullable=True)
    
    # Relationships
    realm = relationship('Realm', backref='page_customizations')
    background_image = relationship('MediaAsset', foreign_keys=[background_image_id], post_update=True)
    logo = relationship('MediaAsset', foreign_keys=[logo_id], post_update=True)
    
    __table_args__ = (
        CheckConstraint("page_type IN ('login', 'register', 'forgot_password', 'consent', 'error')", name='check_page_type'),
        CheckConstraint("background_type IN ('color', 'gradient', 'image')", name='check_background_type'),
        CheckConstraint("logo_position IN ('center', 'top', 'bottom')", name='check_logo_position'),
        {'sqlite_autoincrement': False}
    )
    
    @classmethod
    def get_or_create(cls, realm_id, page_type):
        """Get existing customization or create default one"""
        customization = cls.query.filter_by(realm_id=realm_id, page_type=page_type).first()
        if not customization:
            customization = cls(
                realm_id=realm_id,
                page_type=page_type
            )
            db.session.add(customization)
            db.session.commit()
        return customization
    
    @classmethod
    def get(cls, realm_id, page_type):
        """Get customization for realm and page type"""
        return cls.query.filter_by(realm_id=realm_id, page_type=page_type).first()
    
    def get_background_gradient_dict(self):
        """Get background gradient as dictionary"""
        if self.background_gradient:
            try:
                return json.loads(self.background_gradient)
            except:
                return None
        return None
    
    def set_background_gradient_dict(self, gradient_dict):
        """Set background gradient from dictionary"""
        if gradient_dict:
            self.background_gradient = json.dumps(gradient_dict)
        else:
            self.background_gradient = None
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'realm_id': self.realm_id,
            'page_type': self.page_type,
            'background_type': self.background_type,
            'background_color': self.background_color,
            'background_gradient': self.get_background_gradient_dict(),
            'background_image_id': self.background_image_id,
            'primary_color': self.primary_color,
            'secondary_color': self.secondary_color,
            'font_family': self.font_family,
            'button_radius': self.button_radius,
            'form_radius': self.form_radius,
            'logo_id': self.logo_id,
            'logo_position': self.logo_position,
            'custom_css': self.custom_css,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class MediaAsset(BaseModel):
    """
    Media Asset - Stored images for customization (logos, backgrounds)
    """
    __tablename__ = 'media_assets'
    
    realm_id = Column(String(36), ForeignKey('realms.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_type = Column(String(20), nullable=False)  # 'logo', 'background'
    original_filename = Column(String(255), nullable=False)
    stored_path = Column(String(512), nullable=False)
    content_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)
    
    # Relationships
    realm = relationship('Realm', backref='media_assets')
    
    __table_args__ = (
        CheckConstraint("asset_type IN ('logo', 'background')", name='check_asset_type'),
        {'sqlite_autoincrement': False}
    )
    
    @classmethod
    def create(cls, realm_id, asset_type, original_filename, stored_path, content_type, file_size):
        """Create a new media asset"""
        asset = cls(
            realm_id=realm_id,
            asset_type=asset_type,
            original_filename=original_filename,
            stored_path=stored_path,
            content_type=content_type,
            file_size=file_size
        )
        db.session.add(asset)
        db.session.commit()
        return asset
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'realm_id': self.realm_id,
            'asset_type': self.asset_type,
            'original_filename': self.original_filename,
            'stored_path': self.stored_path,
            'content_type': self.content_type,
            'file_size': self.file_size,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
