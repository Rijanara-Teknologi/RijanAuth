# -*- encoding: utf-8 -*-
"""
RijanAuth - Authentication Routes
"""

from flask import render_template, redirect, request, url_for, flash, current_app, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from apps.blueprints.auth import auth_bp
from apps.models.user import User
from apps.models.realm import Realm
from apps.models.event import Event
from apps.models.session import UserSession
from apps.utils.customization_renderer import get_page_customization
from apps.services.user_service import UserService
from apps import db
import re
from datetime import datetime, timedelta

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    from flask import session
    current_app.logger.info("LOGIN ATTEMPT STARTED", extra={
        'route': request.path,
        'method': request.method,
        'client_ip': request.remote_addr,
        'user_agent': request.user_agent.string
    })
    
    if current_user.is_authenticated:
        current_app.logger.debug("USER ALREADY AUTHENTICATED", extra={
            'user_id': getattr(current_user, 'id', 'UNKNOWN'),
            'username': getattr(current_user, 'username', 'UNKNOWN'),
            'realm': getattr(current_user, 'realm_id', 'N/A')
        })
        return redirect(url_for('admin.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        current_app.logger.debug("PROCESSING CREDENTIALS", extra={
            'username': username,
            'password_provided': bool(password)
        })
        
        # Authenticate against Master Realm for Admin Console
        master_realm = Realm.find_by_name('master')
        user = None
        authenticated = False
        
        if master_realm:
            # Try local user first
            user = User.find_by_username(master_realm.id, username)
            if not user:
                user = User.find_by_email(master_realm.id, username)
            
            if user:
                current_app.logger.debug("USER FOUND IN DATABASE", extra={
                    'user_id': user.id,
                    'username': user.username,
                    'enabled': user.enabled,
                    'email_verified': user.email_verified
                })
                
                # Check if federated user (no local password)
                if user.federation_link:
                    # Federated user - authenticate against federation provider
                    try:
                        from apps.services.federation import FederationService
                        fed_user = FederationService.authenticate_federated(
                            master_realm.id, username, password
                        )
                        if fed_user and fed_user.id == user.id:
                            authenticated = True
                            current_app.logger.debug("FEDERATED AUTH SUCCESS", extra={
                                'user_id': user.id
                            })
                    except Exception as e:
                        current_app.logger.error(f"Federation auth error: {str(e)}")
                else:
                    # Local user - verify password
                    password_valid = user.verify_password(password)
                    current_app.logger.debug("PASSWORD VERIFICATION", extra={
                        'result': 'SUCCESS' if password_valid else 'FAILURE',
                        'user_id': user.id
                    })
                    authenticated = password_valid
            
            # If local auth failed, try federation providers
        if authenticated and user:
            if not user.enabled:
                current_app.logger.warning("USER DISABLED", extra={'user_id': user.id})
                # Get customization for master realm
                master_realm = Realm.find_by_name('master')
                customization = get_page_customization(master_realm.id, 'login') if master_realm else None
                return render_template('auth/login.html', msg='Account is disabled', 
                                     realm=master_realm, customization=customization)

            # Log pre-login state
            current_app.logger.debug("PRE-LOGIN USER STATE", extra={
                'user_id': user.id,
                'realm': user.realm.name if user.realm else 'None'
            })
            
            # Login user with remember=True for persistent session
            login_success = login_user(user, remember=True)
            
            if login_success:
                next_url = request.args.get('next')
                if not next_url or not next_url.startswith('/'):
                    next_url = url_for('admin.index')

                try:
                    if master_realm and master_realm.events_enabled:
                        event_type = 'LOGIN'
                        if not master_realm.enabled_event_types or event_type in master_realm.enabled_event_types:
                            Event.log_event(
                                realm_id=master_realm.id,
                                event_type=event_type,
                                user_id=user.id,
                                ip_address=request.remote_addr,
                                details={'username': user.username, 'auth_method': 'password'}
                            )
                except Exception as e:
                    current_app.logger.error(f"Failed to record login event: {e}")

                current_app.logger.info("LOGIN SUCCESSFUL", extra={
                    'user_id': user.id,
                    'username': user.username,
                    'redirect_url': next_url
                })
                return redirect(next_url)
        
        # Log failed login attempt
        current_app.logger.warning("FAILED LOGIN ATTEMPT", extra={
            'username': username,
            'user_exists': bool(user),
            'ip_address': request.remote_addr
        })
        # Get customization for master realm
        master_realm = Realm.find_by_name('master')
        try:
            if master_realm and master_realm.events_enabled:
                event_type = 'LOGIN_ERROR'
                if not master_realm.enabled_event_types or event_type in master_realm.enabled_event_types:
                    Event.log_event(
                        realm_id=master_realm.id,
                        event_type=event_type,
                        user_id=user.id if user else None,
                        ip_address=request.remote_addr,
                        error='invalid_user_credentials',
                        details={'username': username}
                    )
        except Exception as e:
            current_app.logger.error(f"Failed to record login error event: {e}")
        customization = get_page_customization(master_realm.id, 'login') if master_realm else None
        return render_template('auth/login.html', msg='Invalid credentials',
                             realm=master_realm, customization=customization)
    
    current_app.logger.debug("RENDERING LOGIN PAGE", extra={
        'next_param': request.args.get('next', 'NOT SET')
    })
    # Get customization for master realm
    master_realm = Realm.find_by_name('master')
    customization = get_page_customization(master_realm.id, 'login') if master_realm else None
    return render_template('auth/login.html', realm=master_realm, customization=customization)


@auth_bp.route('/logout')
def logout():
    try:
        if current_user.is_authenticated:
            master_realm = Realm.find_by_name('master')
            if master_realm and master_realm.events_enabled:
                event_type = 'LOGOUT'
                if not master_realm.enabled_event_types or event_type in master_realm.enabled_event_types:
                    Event.log_event(
                        realm_id=master_realm.id,
                        event_type=event_type,
                        user_id=current_user.id,
                        ip_address=request.remote_addr
                    )
    except Exception as e:
        current_app.logger.error(f"Failed to record logout event: {e}")
    logout_user()
    return redirect(url_for('auth_bp.login'))


# =============================================================================
# Password Change - Self Service
# =============================================================================

def validate_password_complexity(password):
    """Validate password complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)"
    return True, None


def check_rate_limit(user_id, action='password_change', max_attempts=5, window_minutes=60):
    """Check if user has exceeded rate limit for an action"""
    # Simple in-memory rate limiting using Flask session
    # For production, consider using Redis or database-backed rate limiting
    from flask import session
    
    key = f'rate_limit_{action}_{user_id}'
    now = datetime.utcnow()
    
    if key not in session:
        session[key] = {'attempts': 1, 'first_attempt': now.isoformat()}
        return True, None
    
    limit_data = session[key]
    first_attempt = datetime.fromisoformat(limit_data['first_attempt'])
    window = timedelta(minutes=window_minutes)
    
    # Reset if window has passed
    if now - first_attempt > window:
        session[key] = {'attempts': 1, 'first_attempt': now.isoformat()}
        return True, None
    
    # Check attempts
    if limit_data['attempts'] >= max_attempts:
        remaining = window - (now - first_attempt)
        return False, f"Rate limit exceeded. Try again in {remaining.seconds // 60} minutes."
    
    limit_data['attempts'] += 1
    session[key] = limit_data
    return True, None


def logout_all_sessions(user_id, realm_id, exclude_current=False):
    """Logout all active sessions for a user"""
    current_session_id = None
    if exclude_current and hasattr(current_user, 'current_session_id'):
        current_session_id = current_user.current_session_id
    
    sessions = UserSession.query.filter_by(
        user_id=user_id,
        realm_id=realm_id,
        state='ACTIVE'
    ).all()
    
    logged_out_count = 0
    for session in sessions:
        if exclude_current and session.id == current_session_id:
            continue
        session.logout()
        logged_out_count += 1
    
    return logged_out_count


@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """API endpoint for changing password"""
    current_app.logger.info("PASSWORD CHANGE ATTEMPT", extra={
        'user_id': getattr(current_user, 'id', None),
        'username': getattr(current_user, 'username', None),
        'ip_address': request.remote_addr
    })
    
    # Get request data (support both JSON and form data)
    if request.is_json:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
    else:
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
    
    # Validate input
    if not current_password or not new_password:
        current_app.logger.warning("PASSWORD CHANGE FAILED: Missing fields", extra={
            'user_id': current_user.id,
            'has_current': bool(current_password),
            'has_new': bool(new_password)
        })
        if request.is_json:
            return jsonify({'error': 'Both current_password and new_password are required'}), 400
        flash('Both current and new password are required', 'error')
        return redirect(url_for('auth_bp.account'))
    
    # Rate limiting
    allowed, message = check_rate_limit(current_user.id, 'password_change')
    if not allowed:
        current_app.logger.warning("PASSWORD CHANGE RATE LIMITED", extra={
            'user_id': current_user.id,
            'ip_address': request.remote_addr
        })
        if request.is_json:
            return jsonify({'error': message}), 429
        flash(message, 'error')
        return redirect(url_for('auth_bp.account'))
    
    # Verify current password
    if not UserService.verify_password(current_user, current_password):
        current_app.logger.warning("PASSWORD CHANGE FAILED: Incorrect current password", extra={
            'user_id': current_user.id,
            'username': current_user.username
        })
        
        # Log failed event
        try:
            master_realm = Realm.find_by_name('master')
            if master_realm and master_realm.events_enabled:
                event_type = 'UPDATE_PASSWORD_ERROR'
                if not master_realm.enabled_event_types or event_type in master_realm.enabled_event_types:
                    Event.log_event(
                        realm_id=master_realm.id,
                        event_type=event_type,
                        user_id=current_user.id,
                        ip_address=request.remote_addr,
                        error='invalid_password',
                        details={'reason': 'Current password incorrect'}
                    )
        except Exception as e:
            current_app.logger.error(f"Failed to record password change error event: {e}")
        
        if request.is_json:
            return jsonify({'error': 'Current password is incorrect'}), 400
        flash('Current password is incorrect', 'error')
        return redirect(url_for('auth_bp.account'))
    
    # Check new password is different
    if current_password == new_password:
        if request.is_json:
            return jsonify({'error': 'New password must be different from current password'}), 400
        flash('New password must be different from current password', 'error')
        return redirect(url_for('auth_bp.account'))
    
    # Validate password complexity
    valid, error_msg = validate_password_complexity(new_password)
    if not valid:
        current_app.logger.warning("PASSWORD CHANGE FAILED: Complexity check failed", extra={
            'user_id': current_user.id,
            'reason': error_msg
        })
        if request.is_json:
            return jsonify({'error': error_msg}), 400
        flash(error_msg, 'error')
        return redirect(url_for('auth_bp.account'))
    
    # Update password
    try:
        UserService.set_password(current_user, new_password)
        
        # Logout all other sessions
        realm_id = current_user.realm_id
        logged_out = logout_all_sessions(current_user.id, realm_id, exclude_current=True)
        
        current_app.logger.info("PASSWORD CHANGE SUCCESS", extra={
            'user_id': current_user.id,
            'username': current_user.username,
            'sessions_logged_out': logged_out
        })
        
        # Log success event
        try:
            master_realm = Realm.find_by_name('master')
            if master_realm and master_realm.events_enabled:
                event_type = 'UPDATE_PASSWORD'
                if not master_realm.enabled_event_types or event_type in master_realm.enabled_event_types:
                    Event.log_event(
                        realm_id=master_realm.id,
                        event_type=event_type,
                        user_id=current_user.id,
                        ip_address=request.remote_addr,
                        details={'sessions_invalidated': logged_out}
                    )
        except Exception as e:
            current_app.logger.error(f"Failed to record password change event: {e}")
        
        if request.is_json:
            return jsonify({
                'message': 'Password changed successfully',
                'sessions_invalidated': logged_out
            }), 200
        
        flash(f'Password changed successfully. {logged_out} other session(s) were logged out.', 'success')
        return redirect(url_for('auth_bp.account'))
        
    except Exception as e:
        current_app.logger.error(f"PASSWORD CHANGE ERROR: {str(e)}", extra={
            'user_id': current_user.id,
            'error': str(e)
        })
        db.session.rollback()
        if request.is_json:
            return jsonify({'error': 'An error occurred while changing password'}), 500
        flash('An error occurred while changing password', 'error')
        return redirect(url_for('auth_bp.account'))


# =============================================================================
# Account Management Page
# =============================================================================

@auth_bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """Account management page for logged-in users"""
    
    # Get user's realm
    realm = Realm.find_by_id(current_user.realm_id)
    if not realm:
        realm = Realm.find_by_name('master')
    
    # Get page customization
    customization = get_page_customization(realm.id if realm else None, 'login') if realm else None
    
    # Get active sessions
    active_sessions = UserSession.query.filter_by(
        user_id=current_user.id,
        state='ACTIVE'
    ).order_by(UserSession.last_session_refresh.desc()).all()
    
    # Get user's roles
    from apps.services.user_service import UserService
    user_roles = UserService.get_user_roles(current_user)
    user_groups = UserService.get_user_groups(current_user)
    
    if request.method == 'POST':
        action = request.form.get('action', 'update_profile')
        
        if action == 'update_profile':
            # Update profile information
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            email = request.form.get('email', '').strip()
            
            try:
                if first_name:
                    current_user.first_name = first_name
                if last_name:
                    current_user.last_name = last_name
                if email:
                    current_user.email = email
                
                db.session.commit()
                flash('Profile updated successfully', 'success')
                
                # Log event
                try:
                    if realm and realm.events_enabled:
                        event_type = 'UPDATE_PROFILE'
                        if not realm.enabled_event_types or event_type in realm.enabled_event_types:
                            Event.log_event(
                                realm_id=realm.id,
                                event_type=event_type,
                                user_id=current_user.id,
                                ip_address=request.remote_addr
                            )
                except Exception as e:
                    current_app.logger.error(f"Failed to record profile update event: {e}")
                    
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating profile: {str(e)}', 'error')
        
        elif action == 'logout_all':
            # Logout all sessions except current
            logged_out = logout_all_sessions(current_user.id, current_user.realm_id, exclude_current=True)
            flash(f'Logged out from {logged_out} other session(s)', 'success')
    
    return render_template('auth/account.html',
                         user=current_user,
                         realm=realm,
                         customization=customization,
                         active_sessions=active_sessions,
                         roles=user_roles,
                         groups=user_groups,
                         now=datetime.utcnow())
