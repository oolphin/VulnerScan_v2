#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager
import shutil
import logging
import threading

# Imports absolus
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATABASE_FILE, BACKUP_DIR

logger = logging.getLogger('LAB-SEC')

_db_local = threading.local()
_db_initialized = False

def get_db():
    """Get a thread-safe DB connection"""
    global _db_initialized
    
    # Vérifier si une connexion existe déjà pour ce thread
    if hasattr(_db_local, 'conn'):
        try:
            # Vérifier si la connexion est toujours valide
            _db_local.conn.execute("SELECT 1").fetchone()
            return _db_local.conn
        except:
            # Connexion invalide, en créer une nouvelle
            pass
    
    # Créer une nouvelle connexion
    conn = sqlite3.connect(DATABASE_FILE, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging pour meilleure concurrence
    conn.execute("PRAGMA busy_timeout=30000")  # 30 secondes de timeout
    conn.execute("PRAGMA synchronous=NORMAL")  # Équilibre sécurité/performance
    conn.row_factory = sqlite3.Row  # Pour un accès plus facile aux résultats
    
    _db_local.conn = conn
    return conn

@contextmanager
def db_conn():
    """Context manager for safe DB access"""
    conn = None
    try:
        conn = get_db()
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        # Ne pas fermer la connexion ici - elle est réutilisée par le thread
        pass

def close_db():
    """Ferme la connexion database pour le thread courant"""
    if hasattr(_db_local, 'conn'):
        try:
            _db_local.conn.close()
        except:
            pass
        del _db_local.conn

def init_database():
    """Initialize database with all tables"""
    global _db_initialized
    
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # Utiliser une connexion dédiée pour l'initialisation
    conn = sqlite3.connect(DATABASE_FILE, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    
    try:
        c = conn.cursor()
        
        # Tables existantes
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, 
            salt TEXT NOT NULL, 
            role TEXT NOT NULL DEFAULT 'viewer',
            auth_type TEXT DEFAULT 'local', 
            created_at TEXT, 
            last_login TEXT,
            is_active INTEGER DEFAULT 1, 
            failed_attempts INTEGER DEFAULT 0, 
            locked_until TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY, 
            user_id INTEGER, 
            username TEXT, 
            role TEXT,
            created_at TEXT, 
            expires_at TEXT, 
            ip_address TEXT, 
            user_agent TEXT, 
            is_active INTEGER DEFAULT 1)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, 
            target TEXT NOT NULL, 
            scan_level TEXT NOT NULL,
            scan_type TEXT DEFAULT 'nmap', 
            nmap_options TEXT, 
            risk_module_options TEXT,
            timestamp TEXT NOT NULL, 
            duration TEXT, 
            open_ports INTEGER DEFAULT 0,
            services INTEGER DEFAULT 0, 
            vulnerabilities TEXT DEFAULT 'none',
            risk_score INTEGER DEFAULT 0, 
            status TEXT DEFAULT 'pending',
            results TEXT, 
            user_id INTEGER, 
            username TEXT, 
            use_real_nmap INTEGER DEFAULT 1)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS risk_scans (
            id TEXT PRIMARY KEY, 
            target TEXT NOT NULL, 
            modules TEXT,
            module_options TEXT, 
            timestamp TEXT NOT NULL, 
            duration TEXT,
            status TEXT DEFAULT 'pending', 
            results TEXT, 
            user_id INTEGER,
            username TEXT, 
            findings INTEGER DEFAULT 0)''')
        
        # Tables CVE et autres...
        c.execute('''CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY, 
            description TEXT, 
            severity TEXT,
            cvss_score REAL, 
            affected_products TEXT, 
            published_date TEXT,
            exploit_available INTEGER DEFAULT 0)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            type TEXT, 
            message TEXT,
            severity TEXT, 
            scan_id TEXT, 
            timestamp TEXT, 
            acknowledged INTEGER DEFAULT 0)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            timestamp TEXT, 
            username TEXT,
            action TEXT, 
            details TEXT, 
            ip_address TEXT, 
            severity TEXT DEFAULT 'info')''')
        
        # Nouvelle table pour l'état des modules
        c.execute('''CREATE TABLE IF NOT EXISTS module_status (
            module_id TEXT PRIMARY KEY, 
            installed INTEGER DEFAULT 0,
            install_error TEXT, 
            last_checked TEXT, 
            version TEXT)''')
        
        # Default users
        def hash_pw(password, salt):
            import hashlib
            return hashlib.sha256((password+salt).encode()).hexdigest()
        
        import secrets
        
        for uname, pwd, role in [('admin','admin','admin'),('viewer','viewer','viewer')]:
            salt = secrets.token_hex(16)
            h = hash_pw(pwd, salt)
            c.execute("INSERT OR IGNORE INTO users (username,password_hash,salt,role,auth_type,created_at) VALUES (?,?,?,?,?,?)",
                     (uname, h, salt, role, 'local', datetime.now().isoformat()))
        
        conn.commit()
        _db_initialized = True
        logger.info("Database initialized")
        
    finally:
        conn.close()

def save_scan(scan_data):
    """Save scan to database"""
    with db_conn() as conn:
        results_json = json.dumps(scan_data.get('results'), ensure_ascii=False) if scan_data.get('results') else '{}'
        conn.execute('''INSERT OR REPLACE INTO scans 
            (id, target, scan_level, scan_type, nmap_options, risk_module_options,
             timestamp, duration, open_ports, services, vulnerabilities,
             risk_score, status, results, user_id, username, use_real_nmap)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (scan_data['job_id'], scan_data['target'], scan_data.get('scan_level'),
             scan_data.get('scan_type', 'nmap'), json.dumps(scan_data.get('nmap_options', {})),
             json.dumps(scan_data.get('risk_module_options', {})),
             scan_data['timestamp'], scan_data.get('duration'),
             scan_data.get('open_ports', 0), scan_data.get('services', 0),
             scan_data.get('vulnerabilities', 'low'), scan_data.get('risk_score', 0),
             scan_data.get('status', 'unknown'), results_json,
             scan_data.get('user_id'), scan_data.get('username'),
             1 if scan_data.get('use_real_nmap', True) else 0))
        
        if scan_data.get('risk_score', 0) > 70:
            conn.execute('''INSERT INTO alerts (type, message, severity, scan_id, timestamp)
                VALUES (?,?,?,?,?)''',
                ('high_risk', f"High risk on {scan_data['target']}: {scan_data.get('risk_score')}",
                 'high', scan_data['job_id'], scan_data['timestamp']))
        
        return True

def save_risk_scan(scan_data):
    """Save risk module scan to database"""
    with db_conn() as conn:
        results_json = json.dumps(scan_data.get('results'), ensure_ascii=False) if scan_data.get('results') else '{}'
        conn.execute('''INSERT OR REPLACE INTO risk_scans
            (id, target, modules, module_options, timestamp, duration,
             status, results, user_id, username, findings)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            (scan_data['job_id'], scan_data['target'],
             json.dumps(scan_data.get('modules', [])),
             json.dumps(scan_data.get('module_options', {})),
             scan_data['timestamp'], scan_data.get('duration'),
             scan_data.get('status'), results_json,
             scan_data.get('user_id'), scan_data.get('username'),
             len(scan_data.get('results', {}).get('findings', []))))

def backup_db():
    """Backup database"""
    try:
        if not os.path.exists(DATABASE_FILE):
            return False
        backup_file = os.path.join(BACKUP_DIR, f"labsec_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
        
        # Forcer un checkpoint avant backup
        with db_conn() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        
        shutil.copy2(DATABASE_FILE, backup_file)
        # Garder seulement les 10 derniers backups
        backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')])
        for old in backups[:-10]:
            os.remove(os.path.join(BACKUP_DIR, old))
        return True
    except Exception as e:
        logger.error(f"Backup error: {e}")
        return False

def audit_log(username, action, details='', ip='', severity='info'):
    """Add audit log entry"""
    max_retries = 3
    retry_delay = 0.1
    
    for attempt in range(max_retries):
        try:
            with db_conn() as conn:
                conn.execute('''INSERT INTO audit_log 
                    (timestamp, username, action, details, ip_address, severity)
                    VALUES (?,?,?,?,?,?)''',
                    (datetime.now().isoformat(), username, action, details, ip, severity))
            return
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e) and attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))
                continue
            else:
                logger.error(f"Audit log error (attempt {attempt+1}): {e}")
                # Ne pas bloquer l'application pour un log
                return
        except Exception as e:
            logger.error(f"Audit log error: {e}")
            return

# Ajouter un hook pour nettoyer les connexions à la fin des threads
import atexit

@atexit.register
def cleanup_connections():
    """Ferme toutes les connexions database à la sortie"""
    if hasattr(_db_local, 'conn'):
        try:
            _db_local.conn.close()
        except:
            pass