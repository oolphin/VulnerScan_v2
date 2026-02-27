#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAB-SEC Authentication Module
Gestion des utilisateurs, sessions et authentification
"""

import hashlib
import secrets
import socket
import struct
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify

# Imports absolus
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SESSION_TIMEOUT, RADIUS_SERVER, RADIUS_PORT, RADIUS_SECRET
from modules.database import db_conn, audit_log

# Création du blueprint
auth_bp = Blueprint('auth', __name__)

# ============ AUTH UTILS ============
def hash_pw(password, salt):
    """Hash password with salt"""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def verify_local(username, password):
    """Verify local user credentials"""
    with db_conn() as conn:
        c = conn.cursor()
        c.execute('''SELECT id, password_hash, salt, role, is_active, 
                    failed_attempts, locked_until 
                    FROM users WHERE username=? AND auth_type='local' ''', (username,))
        row = c.fetchone()
        
        if not row:
            return None
        
        uid, stored_hash, salt, role, active, fails, locked = row
        
        # Check if account is locked
        if locked:
            try:
                if datetime.now() < datetime.fromisoformat(locked):
                    return {'error': 'account_locked', 'locked_until': locked}
                # Unlock if lock expired
                c.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?", (uid,))
                conn.commit()
            except:
                # Si format de date invalide, déverrouiller
                c.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?", (uid,))
                conn.commit()
        
        if not active:
            return {'error': 'account_disabled'}
        
        if hash_pw(password, salt) == stored_hash:
            # Success - reset failed attempts
            c.execute("UPDATE users SET failed_attempts=0, last_login=? WHERE id=?", 
                     (datetime.now().isoformat(), uid))
            conn.commit()
            return {'user_id': uid, 'username': username, 'role': role}
        else:
            # Failed attempt - increment counter
            new_fails = fails + 1
            lock_until = None
            if new_fails >= 5:
                lock_until = (datetime.now() + timedelta(minutes=15)).isoformat()
            
            c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", 
                     (new_fails, lock_until, uid))
            conn.commit()
            return None

def verify_radius(username, password):
    """Verify RADIUS authentication"""
    try:
        # Create RADIUS Access-Request packet
        authenticator = os.urandom(16)
        rid = secrets.randbelow(256)
        secret = RADIUS_SECRET.encode()
        
        # Encode password (RFC 2865)
        pwd = password.encode()
        if len(pwd) % 16:
            pwd += b'\x00' * (16 - len(pwd) % 16)
        
        enc = b''
        last = authenticator
        for i in range(0, len(pwd), 16):
            block = hashlib.md5(secret + last).digest()
            eb = bytes(a ^ b for a, b in zip(pwd[i:i+16], block))
            enc += eb
            last = eb
        
        # Build attributes
        attrs = bytes([1, len(username) + 2]) + username.encode()
        attrs += bytes([2, len(enc) + 2]) + enc
        
        # Build packet
        length = 20 + len(attrs)
        packet = struct.pack('!BBH', 1, rid, length) + authenticator + attrs
        
        # Send to RADIUS server
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(packet, (RADIUS_SERVER, RADIUS_PORT))
        
        resp, _ = sock.recvfrom(4096)
        sock.close()
        
        if resp[0] == 2:  # Access-Accept
            with db_conn() as conn:
                c = conn.cursor()
                c.execute("SELECT id, role FROM users WHERE username=?", (username,))
                row = c.fetchone()
                
                if row:
                    uid, role = row
                    c.execute("UPDATE users SET last_login=? WHERE id=?", 
                             (datetime.now().isoformat(), uid))
                else:
                    # Create new user with viewer role
                    salt = secrets.token_hex(16)
                    h = hash_pw(secrets.token_hex(32), salt)  # Random password
                    c.execute('''INSERT INTO users 
                        (username, password_hash, salt, role, auth_type, created_at) 
                        VALUES (?,?,?,?,'radius',?)''',
                        (username, h, salt, 'viewer', datetime.now().isoformat()))
                    uid = c.lastrowid
                    role = 'viewer'
                
                conn.commit()
            
            return {'user_id': uid, 'username': username, 'role': role}
        
        return None
        
    except socket.timeout:
        return {'error': 'radius_timeout'}
    except ConnectionRefusedError:
        return {'error': 'radius_unavailable'}
    except Exception as e:
        return {'error': 'radius_error', 'message': str(e)}

def create_session(user, ip='', ua=''):
    """Create a new session"""
    session_id = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(minutes=SESSION_TIMEOUT)).isoformat()
    
    with db_conn() as conn:
        conn.execute('''INSERT INTO sessions 
            (session_id, user_id, username, role, created_at, expires_at, ip_address, user_agent, is_active)
            VALUES (?,?,?,?,?,?,?,?,1)''',
            (session_id, user['user_id'], user['username'], user['role'],
             datetime.now().isoformat(), expires, ip, ua))
    
    return session_id

def validate_session(session_id):
    """Validate a session ID"""
    if not session_id:
        return None
    
    with db_conn() as conn:
        c = conn.cursor()
        c.execute('''SELECT user_id, username, role, expires_at, is_active 
                    FROM sessions WHERE session_id=?''', (session_id,))
        row = c.fetchone()
        
        if not row or not row[4]:  # Not active
            return None
        
        # Check expiration
        try:
            if datetime.now() > datetime.fromisoformat(row[3]):
                conn.execute("UPDATE sessions SET is_active=0 WHERE session_id=?", (session_id,))
                conn.commit()
                return None
        except:
            # Si format de date invalide, considérer comme expiré
            conn.execute("UPDATE sessions SET is_active=0 WHERE session_id=?", (session_id,))
            conn.commit()
            return None
        
        return {
            'user_id': row[0],
            'username': row[1],
            'role': row[2],
            'session_id': session_id
        }

# ============ DECORATORS ============
def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.headers.get('X-Session-Id') or request.cookies.get('session_id')
        user = validate_session(session_id)
        if not user:
            return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.headers.get('X-Session-Id') or request.cookies.get('session_id')
        user = validate_session(session_id)
        if not user:
            return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401
        if user['role'] != 'admin':
            audit_log(user['username'], 'ACCESS_DENIED', f"Admin required: {request.path}", 
                     request.remote_addr, 'warning')
            return jsonify({'error': 'Admin access required', 'code': 'ADMIN_REQUIRED'}), 403
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_scan(f):
    """Decorator to require scan permission (admin only, viewers cannot scan)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.headers.get('X-Session-Id') or request.cookies.get('session_id')
        user = validate_session(session_id)
        if not user:
            return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401
        if user['role'] == 'viewer':
            return jsonify({'error': 'Viewers cannot perform scans', 'code': 'VIEWER_NO_SCAN'}), 403
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

# ============ AUTH ROUTES ============
@auth_bp.route('/login', methods=['POST'])
def login():
    """Login endpoint - version corrigée avec gestion d'erreurs améliorée"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        auth_type = data.get('auth_type', 'local')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        user = None
        
        if auth_type == 'local':
            user = verify_local(username, password)
        elif auth_type == 'radius':
            user = verify_radius(username, password)
            if user and isinstance(user, dict) and 'error' in user:
                if user['error'] == 'radius_timeout':
                    return jsonify({'error': 'RADIUS timeout. Try local auth.'}), 503
                if user['error'] == 'radius_unavailable':
                    return jsonify({'error': 'RADIUS unavailable. Use local.'}), 503
                return jsonify({'error': f"RADIUS: {user.get('message', '')}"}), 500
        else:
            return jsonify({'error': 'Invalid auth type'}), 400
        
        if not user:
            audit_log(username, 'LOGIN_FAILED', f'Auth: {auth_type}', request.remote_addr, 'warning')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if isinstance(user, dict) and 'error' in user:
            if user['error'] == 'account_locked':
                return jsonify({'error': f"Account locked until {user['locked_until']}"}), 423
            if user['error'] == 'account_disabled':
                return jsonify({'error': 'Account disabled'}), 403
        
        # Create session
        session_id = create_session(user, request.remote_addr, request.headers.get('User-Agent', ''))
        if not session_id:
            return jsonify({'error': 'Session creation error'}), 500
        
        audit_log(username, 'LOGIN_SUCCESS', f'Auth:{auth_type} Role:{user["role"]}', request.remote_addr)
        
        response = jsonify({
            'success': True,
            'session_id': session_id,
            'username': user['username'],
            'role': user['role'],
            'auth_type': auth_type
        })
        
        # Set cookie with proper parameters
        response.set_cookie(
            'session_id', 
            session_id, 
            httponly=True, 
            samesite='Lax',
            max_age=SESSION_TIMEOUT * 60,
            secure=False  # Set to True if using HTTPS
        )
        
        return response
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint"""
    session_id = request.headers.get('X-Session-Id') or request.cookies.get('session_id')
    
    if session_id:
        with db_conn() as conn:
            conn.execute("UPDATE sessions SET is_active=0 WHERE session_id=?", (session_id,))
    
    response = jsonify({'success': True})
    response.delete_cookie('session_id')
    return response

@auth_bp.route('/session', methods=['GET'])
def check_session():
    """Check if session is valid"""
    session_id = request.headers.get('X-Session-Id') or request.cookies.get('session_id')
    user = validate_session(session_id)
    
    if user:
        return jsonify({
            'authenticated': True,
            'username': user['username'],
            'role': user['role']
        })
    
    return jsonify({'authenticated': False}), 401

@auth_bp.route('/change-password', methods=['POST'])
@require_auth
def change_password():
    """Change user password"""
    data = request.json
    old = data.get('old_password', '')
    new = data.get('new_password', '')
    
    if len(new) < 8:
        return jsonify({'error': 'Minimum 8 characters required'}), 400
    
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT password_hash, salt FROM users WHERE id=?", 
                 (request.current_user['user_id'],))
        row = c.fetchone()
        
        if not row or hash_pw(old, row[1]) != row[0]:
            return jsonify({'error': 'Wrong password'}), 400
        
        new_salt = secrets.token_hex(16)
        new_hash = hash_pw(new, new_salt)
        
        c.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", 
                 (new_hash, new_salt, request.current_user['user_id']))
    
    audit_log(request.current_user['username'], 'PASSWORD_CHANGED', '', request.remote_addr)
    
    return jsonify({'success': True})