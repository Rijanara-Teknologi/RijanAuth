# -*- encoding: utf-8 -*-
"""
RijanAuth - Authentication Routes
"""

from flask import render_template, redirect, request, url_for, flash, current_app
from flask_login import login_user, logout_user, current_user
from apps.blueprints.auth import auth_bp
from apps.models.user import User
from apps.models.realm import Realm

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
        
        if master_realm:
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
            
            # Verify password
            password_valid = user.verify_password(password)
            current_app.logger.debug("PASSWORD VERIFICATION", extra={
                'result': 'SUCCESS' if password_valid else 'FAILURE',
                'user_id': user.id
            })
            
            if password_valid:
                if not user.enabled:
                     current_app.logger.warning("USER DISABLED", extra={'user_id': user.id})
                     return render_template('auth/login.html', msg='Account is disabled')

                # Log pre-login state
                # Note: relations might be partial if lazy loading
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
        return render_template('auth/login.html', msg='Invalid credentials')
    
    current_app.logger.debug("RENDERING LOGIN PAGE", extra={
        'next_param': request.args.get('next', 'NOT SET')
    })
    return render_template('auth/login.html')


@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth_bp.login'))
