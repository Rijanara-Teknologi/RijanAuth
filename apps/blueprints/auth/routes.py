# -*- encoding: utf-8 -*-
"""
RijanAuth - Authentication Routes
"""

from flask import render_template, redirect, request, url_for, flash, current_app
from flask_login import login_user, logout_user, current_user
from apps.blueprints.auth import auth_bp
from apps.models.user import User
from apps.models.realm import Realm

print("DEBUG_V2: auth.routes module loaded", flush=True)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    import sys
    current_app.logger.info(f"DEBUG_V2: Login route accessed. Method: {request.method}")
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('auth/login.html', msg='Username and Password are required')

        try:
            # Authenticate against Master Realm for Admin Console
            master_realm = Realm.find_by_name('master')
            user = None
            
            if master_realm:
                user = User.find_by_username(master_realm.id, username)
                print(f"DEBUG: Login attempt for '{username}'. Found user: {user}")
                if not user:
                    user = User.find_by_email(master_realm.id, username)
                    print(f"DEBUG: Checking email. Found: {user}")
            
            if user and user.verify_password(password):
                if not user.enabled:
                    print("DEBUG: User disabled")
                    return render_template('auth/login.html', msg='Account is disabled')
                    
                login_user(user)
                print(f"DEBUG: Valid credentials. Logged in user: {user.id}")
                
                # Handle 'next' redirect
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                
                return redirect(url_for('admin.index'))
            
            print("DEBUG: Invalid credentials or password verify failed")
            return render_template('auth/login.html', msg='Invalid credentials')
            
        except Exception as e:
            print(f"Login error: {e}")
            return render_template('auth/login.html', msg='An internal error occurred')

    return render_template('auth/login.html')


@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth_bp.login'))
