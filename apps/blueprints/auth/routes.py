# -*- encoding: utf-8 -*-
"""
RijanAuth - Authentication Routes
"""

from flask import render_template, redirect, request, url_for, flash, current_app
from flask_login import login_user, logout_user, current_user
from apps.blueprints.auth import auth_bp
from apps.models.user import User
from apps.models.realm import Realm
from apps.utils.customization_renderer import get_page_customization

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
    logout_user()
    return redirect(url_for('auth_bp.login'))
