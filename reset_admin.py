#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de réinitialisation d'urgence des comptes administrateur
"""
import sqlite3
import hashlib
import secrets
from datetime import datetime

DB_PATH = 'data/labsec.db'

def hash_pw(password, salt):
    """Hash password with salt"""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def reset_admin():
    """Réinitialise le compte admin"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Voir les utilisateurs existants
    c.execute("SELECT id, username, role, is_active, locked_until FROM users")
    users = c.fetchall()
    print("Utilisateurs existants:")
    for u in users:
        print(f"  ID: {u[0]}, Username: {u[1]}, Role: {u[2]}, Active: {u[3]}, Locked: {u[4]}")
    
    # Réinitialiser le compte admin
    salt = secrets.token_hex(16)
    password_hash = hash_pw('admin', salt)
    
    c.execute('''INSERT OR REPLACE INTO users 
        (id, username, password_hash, salt, role, auth_type, created_at, is_active, failed_attempts, locked_until)
        VALUES (
            (SELECT id FROM users WHERE username='admin'),
            'admin', ?, ?, 'admin', 'local', ?, 1, 0, NULL
        )''', (password_hash, salt, datetime.now().isoformat()))
    
    # Réinitialiser aussi le compte viewer
    salt2 = secrets.token_hex(16)
    password_hash2 = hash_pw('viewer', salt2)
    
    c.execute('''INSERT OR REPLACE INTO users 
        (id, username, password_hash, salt, role, auth_type, created_at, is_active, failed_attempts, locked_until)
        VALUES (
            (SELECT id FROM users WHERE username='viewer'),
            'viewer', ?, ?, 'viewer', 'local', ?, 1, 0, NULL
        )''', (password_hash2, salt2, datetime.now().isoformat()))
    
    # Supprimer toutes les sessions pour forcer une nouvelle connexion
    c.execute("DELETE FROM sessions")
    
    conn.commit()
    conn.close()
    
    print("\n✅ Comptes réinitialisés avec succès!")
    print("   admin / admin")
    print("   viewer / viewer")

if __name__ == "__main__":
    reset_admin()