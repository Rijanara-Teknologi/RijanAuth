# -*- encoding: utf-8 -*-
"""
RijanAuth - Media Upload Handler
Secure handling of media file uploads for customization
"""

import os
import uuid
from typing import Tuple
from werkzeug.utils import secure_filename
from flask import current_app
from apps.models.customization import MediaAsset


class MediaHandler:
    """Handle media file uploads with security validation"""
    
    # Allowed MIME types
    LOGO_ALLOWED_TYPES = ['image/png', 'image/svg+xml', 'image/jpeg']
    BACKGROUND_ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/svg+xml', 'image/webp']
    
    # Max file sizes (in bytes)
    MAX_LOGO_SIZE = 500 * 1024  # 500KB
    MAX_BACKGROUND_SIZE = 2 * 1024 * 1024  # 2MB
    
    @classmethod
    def get_upload_directory(cls):
        """Get the upload directory path"""
        upload_dir = current_app.config.get('MEDIA_ROOT', 'apps/static/media')
        # Create directory if it doesn't exist
        os.makedirs(upload_dir, exist_ok=True)
        return upload_dir
    
    @classmethod
    def validate_file(cls, file, asset_type: str) -> Tuple[bool, str]:
        """
        Validate uploaded file
        
        Args:
            file: FileStorage object from Flask
            asset_type: 'logo' or 'background'
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not file or not file.filename:
            return False, "No file provided"
        
        # Check file type
        if asset_type == 'logo':
            allowed_types = cls.LOGO_ALLOWED_TYPES
            max_size = cls.MAX_LOGO_SIZE
        elif asset_type == 'background':
            allowed_types = cls.BACKGROUND_ALLOWED_TYPES
            max_size = cls.MAX_BACKGROUND_SIZE
        else:
            return False, f"Invalid asset type: {asset_type}"
        
        # Check content type
        if file.content_type not in allowed_types:
            return False, f"Invalid file type. Allowed types: {', '.join(allowed_types)}"
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > max_size:
            max_size_mb = max_size / (1024 * 1024)
            return False, f"File too large. Maximum size: {max_size_mb:.1f}MB"
        
        if file_size == 0:
            return False, "File is empty"
        
        return True, ""
    
    @classmethod
    def save_file(cls, file, realm_id: str, asset_type: str) -> MediaAsset:
        """
        Save uploaded file and create MediaAsset record
        
        Args:
            file: FileStorage object from Flask
            realm_id: Realm ID
            asset_type: 'logo' or 'background'
            
        Returns:
            MediaAsset instance
        """
        # Validate file
        is_valid, error = cls.validate_file(file, asset_type)
        if not is_valid:
            raise ValueError(error)
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        file_ext = os.path.splitext(original_filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_ext}"
        
        # Get upload directory
        upload_dir = cls.get_upload_directory()
        stored_path = os.path.join(upload_dir, unique_filename)
        
        # Save file
        file.save(stored_path)
        
        # Get file size
        file_size = os.path.getsize(stored_path)
        
        # Create MediaAsset record
        asset = MediaAsset.create(
            realm_id=realm_id,
            asset_type=asset_type,
            original_filename=original_filename,
            stored_path=unique_filename,  # Store only filename, not full path
            content_type=file.content_type,
            file_size=file_size
        )
        
        return asset
    
    @classmethod
    def delete_file(cls, asset: MediaAsset):
        """Delete file and asset record"""
        if not asset:
            return
        
        upload_dir = cls.get_upload_directory()
        file_path = os.path.join(upload_dir, asset.stored_path)
        
        # Delete file if exists
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                current_app.logger.error(f"Error deleting file {file_path}: {str(e)}")
        
        # Delete asset record
        asset.delete()
    
    @classmethod
    def get_file_path(cls, asset: MediaAsset) -> str:
        """Get full file path for serving"""
        if not asset:
            return None
        
        upload_dir = cls.get_upload_directory()
        return os.path.join(upload_dir, asset.stored_path)
    
    @classmethod
    def get_file_url(cls, asset: MediaAsset) -> str:
        """Get URL path for serving media file"""
        if not asset:
            return None
        
        return f"/media/{asset.id}/{asset.stored_path}"
