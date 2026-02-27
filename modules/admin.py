#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import signal
import os
import json
import platform
import socket
import time
import sqlite3
from datetime import datetime

from flask import Blueprint, request, jsonify

# Imports absolus
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.auth import require_admin, require_auth, hash_pw
from modules.database import db_conn, backup_db, audit_log
from modules.utils import get_local_ip

admin_bp = Blueprint('admin', __name__)

# Variable globale pour l'uptime
start_time = time.time()

# ============ USER MANAGEMENT ============
@admin_bp.route('/users', methods=['GET'])
@require_admin
def list_users():
    """List all users"""
    with db_conn() as conn:
        c = conn.cursor()
        c.execute('''SELECT id, username, role, auth_type, created_at, last_login, is_active 
                    FROM users ORDER BY id''')
        users = [{
            'id': r[0],
            'username': r[1],
            'role': r[2],
            'auth_type': r[3],
            'created_at': r[4],
            'last_login': r[5],
            'is_active': bool(r[6])
        } for r in c.fetchall()]
    
    return jsonify({'users': users})

@admin_bp.route('/users', methods=['POST'])
@require_admin
def create_user():
    """Create a new user"""
    import secrets
    
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'viewer')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if role not in ('admin', 'viewer'):
        return jsonify({'error': 'Role must be admin or viewer'}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    salt = secrets.token_hex(16)
    password_hash = hash_pw(password, salt)
    
    try:
        with db_conn() as conn:
            conn.execute('''INSERT INTO users 
                (username, password_hash, salt, role, auth_type, created_at)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (username, password_hash, salt, role, 'local', datetime.now().isoformat()))
        
        audit_log(request.current_user['username'], 'USER_CREATED', 
                 f'{username} ({role})', request.remote_addr)
        
        return jsonify({'success': True, 'username': username, 'role': role})
        
    except Exception as e:
        if 'UNIQUE constraint' in str(e):
            return jsonify({'error': 'Username already exists'}), 409
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@require_admin
def update_user(user_id):
    """Update a user (enable/disable, change role, reset password)"""
    import secrets
    
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Petite pause pour éviter les conflits de locking
    time.sleep(0.1)
    
    try:
        with db_conn() as conn:
            c = conn.cursor()
            
            # Vérifier que l'utilisateur existe
            c.execute("SELECT id, username FROM users WHERE id=?", (user_id,))
            user = c.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            updates = []
            params = []
            
            # Mise à jour du rôle
            if 'role' in data and data['role'] in ('admin', 'viewer'):
                updates.append("role=?")
                params.append(data['role'])
            
            # Mise à jour du statut actif/inactif
            if 'is_active' in data:
                # Empêcher la désactivation de son propre compte
                if user_id == request.current_user['user_id'] and not data['is_active']:
                    return jsonify({'error': 'You cannot disable your own account'}), 400
                
                updates.append("is_active=?")
                params.append(1 if data['is_active'] else 0)
                print(f"Setting user {user_id} active to {data['is_active']}")  # Debug
            
            # Réinitialisation du mot de passe
            if data.get('reset_password'):
                new_password = data.get('new_password', 'LabSec2025!')
                if len(new_password) < 8:
                    return jsonify({'error': 'New password must be at least 8 characters'}), 400
                
                salt = secrets.token_hex(16)
                password_hash = hash_pw(new_password, salt)
                updates.append("password_hash=?")
                params.append(password_hash)
                updates.append("salt=?")
                params.append(salt)
                updates.append("failed_attempts=?")
                params.append(0)
                updates.append("locked_until=?")
                params.append(None)
            
            if updates:
                query = f"UPDATE users SET {', '.join(updates)} WHERE id=?"
                params.append(user_id)
                c.execute(query, params)
                conn.commit()
                print(f"User {user_id} updated successfully")  # Debug
            
            # Audit log
            try:
                action = 'USER_UPDATED'
                details = []
                if 'role' in data:
                    details.append(f"role={data['role']}")
                if 'is_active' in data:
                    status = 'enabled' if data['is_active'] else 'disabled'
                    details.append(status)
                if data.get('reset_password'):
                    details.append("password_reset")
                
                audit_log(request.current_user['username'], action, 
                         f"User {user[1]}: {', '.join(details)}", request.remote_addr)
            except:
                pass
        
        return jsonify({'success': True})
        
    except sqlite3.OperationalError as e:
        if 'database is locked' in str(e):
            return jsonify({'error': 'Database is busy, please try again'}), 503
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        print(f"Error updating user: {e}")  # Debug
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    """Delete a user permanently"""
    try:
        with db_conn() as conn:
            c = conn.cursor()
            
            # Vérifier que l'utilisateur existe
            c.execute("SELECT id, username FROM users WHERE id=?", (user_id,))
            user = c.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Empêcher la suppression de son propre compte
            if user_id == request.current_user['user_id']:
                return jsonify({'error': 'You cannot delete your own account'}), 400
            
            # Supprimer d'abord les sessions de l'utilisateur
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            
            # Supprimer l'utilisateur
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
            
            conn.commit()
            
            audit_log(request.current_user['username'], 'USER_DELETED', 
                     f"Deleted user {user[1]}", request.remote_addr, 'warning')
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error deleting user: {e}")
        return jsonify({'error': str(e)}), 500

# ============ EMERGENCY KILL ============
@admin_bp.route('/kill-all', methods=['POST'])
@require_admin
def kill_all():
    """Kill all scan processes"""
    killed = {}
    
    for tool in ['nmap', 'nikto', 'sqlmap', 'hashcat', 'hydra', 'dirb', 'whatweb', 'crackmapexec']:
        try:
            result = subprocess.run(['pgrep', '-f', tool], capture_output=True, text=True)
            if result.returncode == 0:
                count = 0
                for pid in result.stdout.strip().split('\n'):
                    if pid.strip():
                        try:
                            os.kill(int(pid.strip()), signal.SIGKILL)
                            count += 1
                        except:
                            pass
                if count > 0:
                    killed[tool] = count
        except:
            pass
    
    total = sum(killed.values())
    audit_log(request.current_user['username'], 'EMERGENCY_KILL', 
             f"Killed {total} processes", request.remote_addr, 'critical')
    
    return jsonify({
        'killed': total,
        'details': killed,
        'message': f'{total} processes killed'
    })

@admin_bp.route('/kill-nmap', methods=['POST'])
@require_admin
def kill_nmap():
    """Kill all nmap processes"""
    killed = 0
    
    try:
        result = subprocess.run(['pgrep', '-f', 'nmap'], capture_output=True, text=True)
        if result.returncode == 0:
            for pid in result.stdout.strip().split('\n'):
                if pid.strip():
                    try:
                        os.kill(int(pid.strip()), signal.SIGKILL)
                        killed += 1
                    except:
                        pass
    except:
        pass
    
    audit_log(request.current_user['username'], 'KILL_NMAP', 
             f"Killed {killed}", request.remote_addr, 'warning')
    
    return jsonify({'killed': killed, 'message': f'{killed} nmap processes killed'})

# ============ BACKUP & MAINTENANCE ============
@admin_bp.route('/backup', methods=['POST'])
@require_admin
def backup():
    """Backup database"""
    success = backup_db()
    if success:
        audit_log(request.current_user['username'], 'BACKUP', 'Database backup', request.remote_addr)
        return jsonify({'message': 'Backup completed successfully'})
    return jsonify({'error': 'Backup failed'}), 500

@admin_bp.route('/clear', methods=['POST'])
@require_admin
def clear_data():
    """Clear scan data"""
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM scans")
        c.execute("DELETE FROM risk_scans")
        c.execute("DELETE FROM alerts")
    
    audit_log(request.current_user['username'], 'DB_CLEARED', '', request.remote_addr, 'warning')
    
    return jsonify({'message': 'Database cleared'})

@admin_bp.route('/audit-log', methods=['GET'])
@require_admin
def get_audit_log():
    """Get audit log entries"""
    limit = request.args.get('limit', 100, type=int)
    
    with db_conn() as conn:
        c = conn.cursor()
        c.execute('''SELECT timestamp, username, action, details, ip_address, severity 
                    FROM audit_log ORDER BY timestamp DESC LIMIT ?''', (limit,))
        logs = [{
            'timestamp': r[0],
            'username': r[1],
            'action': r[2],
            'details': r[3],
            'ip': r[4],
            'severity': r[5]
        } for r in c.fetchall()]
    
    return jsonify({'logs': logs})

# ============ SYSTEM INFO ============
@admin_bp.route('/system/info', methods=['GET'])
@require_auth
def system_info():
    """Get system information"""
    nmap_version = 'not installed'
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if 'Nmap version' in line:
                nmap_version = line.split()[2]
                break
    except:
        pass
    
    return jsonify({
        'python': platform.python_version(),
        'system': platform.system(),
        'hostname': socket.gethostname(),
        'ip': get_local_ip(),
        'nmap_version': nmap_version,
        'uptime': time.time() - start_time
    })

@admin_bp.route('/logs/system', methods=['GET'])
@require_auth
def system_logs():
    """Get system logs"""
    from config import LOGS_DIR
    
    log_file = os.path.join(LOGS_DIR, 'labsec.log')
    logs = []
    
    try:
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.readlines()[-100:]
    except Exception as e:
        logs = [f"Error reading logs: {e}"]
    
    return jsonify({'logs': [l.strip() for l in logs]})