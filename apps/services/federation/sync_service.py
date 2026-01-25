# -*- encoding: utf-8 -*-
"""
RijanAuth - Federation Sync Service
Handles user synchronization from external identity sources
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
import threading
import logging

from apps import db
from apps.models.federation import (
    UserFederationProvider,
    UserFederationLink,
    FederationSyncLog
)
from apps.models.user import User
from apps.services.federation.federation_service import FederationService
from apps.services.federation.base import FederationError

logger = logging.getLogger(__name__)

# Optional APScheduler support
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False


class SyncService:
    """
    Service for synchronizing users from external federation sources.
    
    Provides:
    - Full synchronization (all users)
    - Changed synchronization (incremental)
    - Manual sync triggers
    - Scheduled sync via APScheduler
    """
    
    _scheduler = None
    _scheduler_lock = threading.Lock()
    
    # ==================== Scheduler Management ====================
    
    @classmethod
    def init_scheduler(cls, app=None):
        """
        Initialize the background scheduler for periodic syncs.
        
        Args:
            app: Flask app instance (optional, for context)
        """
        if not SCHEDULER_AVAILABLE:
            logger.warning("APScheduler not installed. Scheduled sync disabled.")
            return
        
        with cls._scheduler_lock:
            if cls._scheduler is not None:
                return
            
            cls._scheduler = BackgroundScheduler()
            cls._scheduler.start()
            logger.info("Federation sync scheduler started")
            
            # Schedule sync jobs for all providers
            cls._schedule_all_providers()
    
    @classmethod
    def shutdown_scheduler(cls):
        """Shutdown the background scheduler"""
        with cls._scheduler_lock:
            if cls._scheduler:
                cls._scheduler.shutdown(wait=False)
                cls._scheduler = None
                logger.info("Federation sync scheduler stopped")
    
    @classmethod
    def _schedule_all_providers(cls):
        """Schedule sync jobs for all providers with sync enabled"""
        providers = UserFederationProvider.query.filter(
            UserFederationProvider.enabled == True,
            (UserFederationProvider.full_sync_period > 0) |
            (UserFederationProvider.changed_sync_period > 0)
        ).all()
        
        for provider in providers:
            cls._schedule_provider_sync(provider)
    
    @classmethod
    def _schedule_provider_sync(cls, provider: UserFederationProvider):
        """Schedule sync jobs for a specific provider"""
        if not cls._scheduler:
            return
        
        # Full sync schedule
        if provider.full_sync_period > 0:
            job_id = f"full_sync_{provider.id}"
            cls._scheduler.add_job(
                cls._run_scheduled_sync,
                IntervalTrigger(seconds=provider.full_sync_period),
                id=job_id,
                replace_existing=True,
                args=[provider.id, 'full']
            )
            logger.info(f"Scheduled full sync for {provider.name} every {provider.full_sync_period}s")
        
        # Changed sync schedule
        if provider.changed_sync_period > 0:
            job_id = f"changed_sync_{provider.id}"
            cls._scheduler.add_job(
                cls._run_scheduled_sync,
                IntervalTrigger(seconds=provider.changed_sync_period),
                id=job_id,
                replace_existing=True,
                args=[provider.id, 'changed']
            )
            logger.info(f"Scheduled changed sync for {provider.name} every {provider.changed_sync_period}s")
    
    @classmethod
    def _run_scheduled_sync(cls, provider_id: str, sync_type: str):
        """Run a scheduled sync (called by scheduler)"""
        from flask import current_app
        
        # Need app context for database access
        try:
            with current_app.app_context():
                if sync_type == 'full':
                    cls.sync_all_users(provider_id)
                else:
                    cls.sync_changed_users(provider_id)
        except RuntimeError:
            # No app context - try to create one
            logger.warning("No app context for scheduled sync")
    
    @classmethod
    def reschedule_provider(cls, provider: UserFederationProvider):
        """Reschedule sync jobs after provider update"""
        if not cls._scheduler:
            return
        
        # Remove existing jobs
        for prefix in ['full_sync_', 'changed_sync_']:
            job_id = f"{prefix}{provider.id}"
            try:
                cls._scheduler.remove_job(job_id)
            except Exception:
                pass
        
        # Add new jobs if enabled
        if provider.enabled:
            cls._schedule_provider_sync(provider)
    
    # ==================== Manual Sync ====================
    
    @classmethod
    def sync_all_users(cls, provider_id: str) -> Dict[str, Any]:
        """
        Perform full synchronization from external source.
        
        Args:
            provider_id: Provider ID to sync
            
        Returns:
            Dict with sync results
        """
        provider_config = UserFederationProvider.find_by_id(provider_id)
        if not provider_config:
            return {'success': False, 'error': 'Provider not found'}
        
        if not provider_config.enabled:
            return {'success': False, 'error': 'Provider is disabled'}
        
        # Create sync log
        sync_log = FederationSyncLog(
            provider_id=provider_id,
            sync_type='full',
            status='running'
        )
        db.session.add(sync_log)
        db.session.commit()
        
        # Update provider status
        provider_config.last_sync_status = 'running'
        db.session.commit()
        
        stats = {
            'users_processed': 0,
            'users_created': 0,
            'users_updated': 0,
            'users_removed': 0,
            'errors': []
        }
        
        try:
            provider = FederationService.create_provider_instance(provider_config)
            
            with provider:
                # Track which external IDs we've seen
                seen_external_ids = set()
                
                # Process all users
                for external_user in provider.get_all_users():
                    stats['users_processed'] += 1
                    external_id = external_user.get('external_id')
                    
                    if external_id:
                        seen_external_ids.add(external_id)
                    
                    try:
                        result = cls._sync_user(
                            provider_config.realm_id,
                            provider_id,
                            external_user,
                            provider
                        )
                        
                        if result == 'created':
                            stats['users_created'] += 1
                        elif result == 'updated':
                            stats['users_updated'] += 1
                            
                    except Exception as e:
                        error_msg = f"Error syncing user {external_user.get('username', 'unknown')}: {str(e)}"
                        stats['errors'].append(error_msg)
                        logger.error(error_msg)
                
                # Handle removed users (optional - based on mode)
                mode = provider_config.config.get('mode', 'READ_ONLY')
                if mode == 'IMPORT':
                    removed = cls._remove_unlinked_users(provider_id, seen_external_ids)
                    stats['users_removed'] = removed
            
            # Update sync log - success
            sync_log.status = 'success'
            sync_log.completed_at = datetime.utcnow()
            sync_log.users_processed = stats['users_processed']
            sync_log.users_created = stats['users_created']
            sync_log.users_updated = stats['users_updated']
            sync_log.users_removed = stats['users_removed']
            sync_log.errors_count = len(stats['errors'])
            sync_log.error_details = stats['errors'][:100]  # Limit stored errors
            
            provider_config.last_sync = datetime.utcnow()
            provider_config.last_sync_status = 'success'
            provider_config.last_sync_error = None
            
            db.session.commit()
            
            logger.info(f"Full sync completed for {provider_config.name}: "
                       f"{stats['users_processed']} processed, "
                       f"{stats['users_created']} created, "
                       f"{stats['users_updated']} updated")
            
            return {'success': True, 'stats': stats}
            
        except Exception as e:
            error_msg = f"Sync failed: {str(e)}"
            logger.exception(error_msg)
            
            sync_log.status = 'failed'
            sync_log.completed_at = datetime.utcnow()
            sync_log.error_message = error_msg
            sync_log.users_processed = stats['users_processed']
            sync_log.errors_count = len(stats['errors']) + 1
            
            provider_config.last_sync = datetime.utcnow()
            provider_config.last_sync_status = 'failed'
            provider_config.last_sync_error = error_msg
            
            db.session.commit()
            
            return {'success': False, 'error': error_msg, 'stats': stats}
    
    @classmethod
    def sync_changed_users(cls, provider_id: str) -> Dict[str, Any]:
        """
        Perform incremental synchronization of changed users.
        
        Args:
            provider_id: Provider ID to sync
            
        Returns:
            Dict with sync results
        """
        provider_config = UserFederationProvider.find_by_id(provider_id)
        if not provider_config:
            return {'success': False, 'error': 'Provider not found'}
        
        if not provider_config.enabled:
            return {'success': False, 'error': 'Provider is disabled'}
        
        # Create sync log
        sync_log = FederationSyncLog(
            provider_id=provider_id,
            sync_type='changed',
            status='running'
        )
        db.session.add(sync_log)
        db.session.commit()
        
        stats = {
            'users_processed': 0,
            'users_created': 0,
            'users_updated': 0,
            'errors': []
        }
        
        try:
            provider = FederationService.create_provider_instance(provider_config)
            
            if not provider.supports_changed_sync():
                sync_log.status = 'skipped'
                sync_log.completed_at = datetime.utcnow()
                sync_log.error_message = 'Provider does not support changed sync'
                db.session.commit()
                return {'success': False, 'error': 'Provider does not support changed sync'}
            
            # Get last sync time
            since = provider_config.last_sync or datetime.min
            
            with provider:
                for external_user in provider.get_changed_users(since):
                    stats['users_processed'] += 1
                    
                    try:
                        result = cls._sync_user(
                            provider_config.realm_id,
                            provider_id,
                            external_user,
                            provider
                        )
                        
                        if result == 'created':
                            stats['users_created'] += 1
                        elif result == 'updated':
                            stats['users_updated'] += 1
                            
                    except Exception as e:
                        error_msg = f"Error syncing user {external_user.get('username', 'unknown')}: {str(e)}"
                        stats['errors'].append(error_msg)
                        logger.error(error_msg)
            
            # Update sync log - success
            sync_log.status = 'success'
            sync_log.completed_at = datetime.utcnow()
            sync_log.users_processed = stats['users_processed']
            sync_log.users_created = stats['users_created']
            sync_log.users_updated = stats['users_updated']
            sync_log.errors_count = len(stats['errors'])
            
            provider_config.last_sync = datetime.utcnow()
            provider_config.last_sync_status = 'success'
            provider_config.last_sync_error = None
            
            db.session.commit()
            
            logger.info(f"Changed sync completed for {provider_config.name}: "
                       f"{stats['users_processed']} processed")
            
            return {'success': True, 'stats': stats}
            
        except Exception as e:
            error_msg = f"Changed sync failed: {str(e)}"
            logger.exception(error_msg)
            
            sync_log.status = 'failed'
            sync_log.completed_at = datetime.utcnow()
            sync_log.error_message = error_msg
            
            provider_config.last_sync = datetime.utcnow()
            provider_config.last_sync_status = 'failed'
            provider_config.last_sync_error = error_msg
            
            db.session.commit()
            
            return {'success': False, 'error': error_msg, 'stats': stats}
    
    @classmethod
    def _sync_user(cls, realm_id: str, provider_id: str, 
                   external_user: Dict[str, Any],
                   provider_instance) -> str:
        """
        Sync a single user from external source.
        
        Returns:
            'created', 'updated', or 'skipped'
        """
        external_id = external_user.get('external_id')
        if not external_id:
            return 'skipped'
        
        # Check if already linked
        link = UserFederationLink.find_by_external_id(provider_id, external_id)
        
        if link:
            # Update existing
            user = User.find_by_id(link.user_id)
            if user:
                FederationService._update_user_from_external(user, external_user, provider_instance)
                link.last_sync = datetime.utcnow()
                db.session.commit()
                return 'updated'
            return 'skipped'
        
        # Create new
        user = FederationService.import_federated_user(
            realm_id=realm_id,
            provider_id=provider_id,
            external_user=external_user,
            provider_instance=provider_instance
        )
        
        if user:
            return 'created'
        return 'skipped'
    
    @classmethod
    def _remove_unlinked_users(cls, provider_id: str, seen_external_ids: set) -> int:
        """
        Remove users that no longer exist in external source.
        Only for IMPORT mode.
        
        Returns:
            Number of users removed
        """
        count = 0
        
        # Get all links for this provider
        links = UserFederationLink.find_by_provider(provider_id)
        
        for link in links:
            if link.external_id not in seen_external_ids:
                # User no longer exists in external source
                user = User.find_by_id(link.user_id)
                if user:
                    # Mark user as disabled instead of deleting
                    user.enabled = False
                    link.storage_mode = 'UNLINKED'
                    count += 1
        
        if count > 0:
            db.session.commit()
            logger.info(f"Disabled {count} users no longer in external source")
        
        return count
    
    # ==================== Sync Status ====================
    
    @classmethod
    def get_sync_status(cls, provider_id: str) -> Dict[str, Any]:
        """
        Get sync status for a provider.
        
        Returns:
            Dict with status info and recent logs
        """
        provider = UserFederationProvider.find_by_id(provider_id)
        if not provider:
            return {'error': 'Provider not found'}
        
        recent_logs = FederationSyncLog.get_recent_logs(provider_id, limit=10)
        
        return {
            'provider_id': provider_id,
            'provider_name': provider.name,
            'enabled': provider.enabled,
            'last_sync': provider.last_sync.isoformat() if provider.last_sync else None,
            'last_sync_status': provider.last_sync_status,
            'last_sync_error': provider.last_sync_error,
            'full_sync_period': provider.full_sync_period,
            'changed_sync_period': provider.changed_sync_period,
            'recent_logs': [log.to_dict() for log in recent_logs]
        }
    
    @classmethod
    def get_linked_users_count(cls, provider_id: str) -> int:
        """Get count of users linked to a provider"""
        return UserFederationLink.query.filter_by(provider_id=provider_id).count()
