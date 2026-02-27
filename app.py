#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAB-SEC CYBERSECURITY PLATFORM v3.2.1
Professional Penetration Testing & Security Audit

Version production - Utilise les certificats existants sans génération automatique
"""

import os
import sys
import time
import logging
import ssl
from pathlib import Path
from datetime import datetime
from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
import subprocess
import socket
import ipaddress

# ============ IMPORTS OPTIONNELS POUR CRYPTO ============
# Ces imports ne sont nécessaires que pour la génération de certificats
# Comme on utilise des certificats existants, on les rend optionnels
try:
    import OpenSSL.crypto
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    # Pas d'erreur, on continue en mode production

# ============ GLOBAL VARIABLES ============
start_time = time.time()
high_risk_unlocked = {}  # Pour le déverrouillage des modules

# Ajouter le répertoire courant au path
sys.path.insert(0, str(Path(__file__).parent))

from config import SCAN_PORT, LOGS_DIR, DATABASE_FILE, SCAN_LEVELS, HIGH_RISK_MODULES
from modules.database import init_database, backup_db, db_conn, audit_log
from modules.auth import auth_bp, require_auth, require_admin, require_scan
from modules.scanner import CyberSecScanner
from modules.cve import update_cve_db
from modules.utils import get_local_ip, setup_logging, validate_target
from modules.reports import reports_bp
from modules.tools import tools_bp
from modules.admin import admin_bp

# Configuration logging
logger = setup_logging()

# Initialisation Flask
app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())
CORS(app, supports_credentials=True)

# Scheduler
scheduler = BackgroundScheduler()

# Scanner global
scanner = CyberSecScanner()

# Enregistrement des blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(reports_bp, url_prefix='/api/report')
app.register_blueprint(tools_bp, url_prefix='/api')
app.register_blueprint(admin_bp, url_prefix='/api/admin')

# ============ ROUTES API ============
@app.route('/api/scan/levels', methods=['GET'])
def scan_levels():
    """Retourne les niveaux de scan disponibles"""
    levels = []
    for level_id, level_info in SCAN_LEVELS.items():
        levels.append({
            'id': level_id,
            'name': level_info['name'],
            'desc': level_info['desc'],
            'icon': level_info['icon'],
            'danger': level_info.get('danger', False)
        })
    return jsonify(levels)

@app.route('/api/risk/modules', methods=['GET'])
@require_auth
def risk_modules():
    """Retourne la liste des modules à risque avec leur statut"""
    modules = []
    for module_id, module_info in HIGH_RISK_MODULES.items():
        status = scanner.risk_manager.get_module_info(module_id)
        modules.append({
            'id': module_id,
            'name': module_info['name'],
            'desc': module_info['desc'],
            'installed': status.get('installed', False),
            'version': status.get('version'),
            'options': module_info.get('options', {})
        })
    return jsonify({'modules': modules})

@app.route('/api/risk/install', methods=['POST'])
@require_admin
def install_risk_module():
    """Installe un module à risque"""
    data = request.json
    module_id = data.get('module_id')
    
    if not module_id:
        return jsonify({'error': 'Module ID requis'}), 400
    
    result = scanner.risk_manager.install_module(module_id)
    return jsonify(result)

@app.route('/api/risk/check', methods=['POST'])
@require_scan
def check_risk_modules():
    """Vérifie que les modules sélectionnés sont installés"""
    data = request.json
    modules = data.get('modules', [])
    
    missing = []
    for module_id in modules:
        status = scanner.risk_manager.get_module_info(module_id)
        if not status.get('installed'):
            missing.append(module_id)
    
    if missing:
        return jsonify({
            'all_installed': False,
            'missing': missing,
            'message': f"Modules manquants: {', '.join(missing)}"
        })
    
    return jsonify({'all_installed': True})

@app.route('/api/risk/options/<module_id>', methods=['GET'])
@require_auth
def get_module_options(module_id):
    """Retourne les options configurables d'un module"""
    if module_id not in HIGH_RISK_MODULES:
        return jsonify({'error': 'Module inconnu'}), 404
    
    module = HIGH_RISK_MODULES[module_id]
    return jsonify({'options': module.get('options', {})})

@app.route('/api/scan/nmap', methods=['POST'])
@require_scan
def start_nmap_scan():
    """Démarre un scan Nmap seul"""
    data = request.json
    target = data.get('target')
    level = data.get('scan_level', 'normal')
    options = data.get('nmap_options', {})
    
    if not target:
        return jsonify({'error': 'Target requis'}), 400
    
    if not validate_target(target):
        return jsonify({'error': 'Target invalide'}), 400
    
    job_id = f"nmap_{int(time.time())}_{hash(target) % 10000}"
    success = scanner.start_nmap_scan(job_id, target, level, options, request.current_user)
    
    if not success:
        return jsonify({'error': 'Impossible de démarrer le scan'}), 500
    
    return jsonify({
        'job_id': job_id,
        'type': 'nmap',
        'status': 'running',
        'target': target
    })

@app.route('/api/scan/risk', methods=['POST'])
@require_scan
def start_risk_scan():
    """Démarre un scan de modules à risque seul"""
    data = request.json
    target = data.get('target')
    modules = data.get('modules', [])
    module_options = data.get('module_options', {})
    
    if not target:
        return jsonify({'error': 'Target requis'}), 400
    
    if not modules:
        return jsonify({'error': 'Aucun module sélectionné'}), 400
    
    if not validate_target(target):
        return jsonify({'error': 'Target invalide'}), 400
    
    # Vérifier que tous les modules sont installés
    missing = []
    for module_id in modules:
        status = scanner.risk_manager.get_module_info(module_id)
        if not status.get('installed'):
            missing.append(module_id)
    
    if missing:
        return jsonify({
            'error': 'Modules manquants',
            'missing': missing
        }), 400
    
    # Valider les options
    for module_id in modules:
        if module_id in module_options:
            validation = scanner.risk_manager.validate_module_options(module_id, module_options[module_id])
            if not validation.get('valid'):
                return jsonify({
                    'error': f"Options invalides pour {module_id}",
                    'errors': validation.get('errors')
                }), 400
    
    job_id = f"risk_{int(time.time())}_{hash(target) % 10000}"
    success = scanner.start_risk_scan(job_id, target, modules, module_options, request.current_user)
    
    if not success:
        return jsonify({'error': 'Impossible de démarrer le scan'}), 500
    
    return jsonify({
        'job_id': job_id,
        'type': 'risk',
        'status': 'running',
        'target': target,
        'modules': modules
    })

@app.route('/api/scan/combined', methods=['POST'])
@require_scan
def start_combined_scan():
    """Démarre un scan combiné (Nmap + modules à risque)"""
    data = request.json
    target = data.get('target')
    level = data.get('scan_level', 'normal')
    nmap_options = data.get('nmap_options', {})
    modules = data.get('modules', [])
    module_options = data.get('module_options', {})
    
    if not target:
        return jsonify({'error': 'Target requis'}), 400
    
    if not validate_target(target):
        return jsonify({'error': 'Target invalide'}), 400
    
    # Vérifier les modules si sélectionnés
    if modules:
        missing = []
        for module_id in modules:
            status = scanner.risk_manager.get_module_info(module_id)
            if not status.get('installed'):
                missing.append(module_id)
        
        if missing:
            return jsonify({
                'error': 'Modules manquants',
                'missing': missing
            }), 400
    
    job_id = f"combined_{int(time.time())}_{hash(target) % 10000}"
    success = scanner.start_combined_scan(job_id, target, level, nmap_options, modules, module_options, request.current_user)
    
    if not success:
        return jsonify({'error': 'Impossible de démarrer le scan'}), 500
    
    return jsonify({
        'job_id': job_id,
        'type': 'combined',
        'status': 'running',
        'target': target,
        'modules': modules
    })

@app.route('/api/scan/<job_id>/status', methods=['GET'])
@require_auth
def scan_status(job_id):
    """Récupère le statut d'un scan"""
    job = scanner.get_scan_status(job_id)
    if not job:
        return jsonify({'error': 'Scan non trouvé'}), 404
    
    return jsonify(job)

@app.route('/api/scan/<job_id>/stop', methods=['POST'])
@require_scan
def stop_scan(job_id):
    """Arrête un scan en cours"""
    success = scanner.stop_scan(job_id)
    if success:
        audit_log(request.current_user['username'], 'SCAN_STOPPED', f"Scan {job_id} arrêté", request.remote_addr)
        return jsonify({'success': True, 'message': 'Scan arrêté'})
    return jsonify({'error': 'Impossible d\'arrêter le scan'}), 400

@app.route('/api/scan/active', methods=['GET'])
@require_auth
def active_scans():
    """Liste les scans actifs"""
    active = scanner.get_active_scans()
    return jsonify({'active_scans': active})

@app.route('/api/scan/history', methods=['GET'])
@require_auth
def scan_history():
    """Historique des scans"""
    limit = request.args.get('limit', 50, type=int)
    scan_type = request.args.get('type', 'all')
    
    with db_conn() as conn:
        c = conn.cursor()
        
        if scan_type == 'nmap':
            c.execute('''SELECT id, target, scan_level, timestamp, duration, 
                         open_ports, services, risk_score, status, username
                         FROM scans ORDER BY timestamp DESC LIMIT ?''', (limit,))
            scans = []
            for row in c.fetchall():
                scans.append({
                    'job_id': row[0],
                    'target': row[1],
                    'type': 'nmap',
                    'scan_level': row[2],
                    'timestamp': row[3],
                    'duration': row[4],
                    'open_ports': row[5],
                    'services': row[6],
                    'risk_score': row[7],
                    'status': row[8],
                    'username': row[9]
                })
        
        elif scan_type == 'risk':
            c.execute('''SELECT id, target, modules, timestamp, duration,
                         findings, status, username
                         FROM risk_scans ORDER BY timestamp DESC LIMIT ?''', (limit,))
            scans = []
            for row in c.fetchall():
                scans.append({
                    'job_id': row[0],
                    'target': row[1],
                    'type': 'risk',
                    'modules': row[2],
                    'timestamp': row[3],
                    'duration': row[4],
                    'findings': row[5] or 0,
                    'status': row[6],
                    'username': row[7]
                })
        
        else:  # 'all'
            # Récupérer les scans nmap
            c.execute('''SELECT id, target, scan_level, timestamp, duration, 
                         open_ports, services, risk_score, status, username, 'nmap' as source
                         FROM scans ORDER BY timestamp DESC LIMIT ?''', (limit,))
            nmap_scans = []
            for row in c.fetchall():
                nmap_scans.append({
                    'job_id': row[0],
                    'target': row[1],
                    'type': 'nmap',
                    'scan_level': row[2],
                    'timestamp': row[3],
                    'duration': row[4],
                    'open_ports': row[5],
                    'services': row[6],
                    'risk_score': row[7],
                    'status': row[8],
                    'username': row[9]
                })
            
            # Récupérer les scans risk
            c.execute('''SELECT id, target, modules, timestamp, duration,
                         findings, status, username, 'risk' as source
                         FROM risk_scans ORDER BY timestamp DESC LIMIT ?''', (limit,))
            risk_scans = []
            for row in c.fetchall():
                risk_scans.append({
                    'job_id': row[0],
                    'target': row[1],
                    'type': 'risk',
                    'modules': row[2],
                    'timestamp': row[3],
                    'duration': row[4],
                    'findings': row[5] or 0,
                    'status': row[6],
                    'username': row[7]
                })
            
            # Fusionner et trier
            scans = nmap_scans + risk_scans
            scans.sort(key=lambda x: x['timestamp'], reverse=True)
            scans = scans[:limit]
    
    return jsonify({'scans': scans})


@app.route('/api/risk/scan-levels', methods=['GET'])
def risk_scan_levels():
    """Get scan levels for risk modules"""
    levels = [
        {
            'id': 'quick',
            'name': 'Quick Scan',
            'desc': 'Basic module scans, ~2-5 min',
            'timeout': 120,
            'modules': ['nikto', 'whatweb', 'dirb']
        },
        {
            'id': 'normal',
            'name': 'Normal Scan',
            'desc': 'Standard module scans, ~5-15 min',
            'timeout': 300,
            'modules': ['nikto', 'whatweb', 'dirb', 'sqlmap', 'hydra']
        },
        {
            'id': 'advanced',
            'name': 'Advanced Scan',
            'desc': 'Comprehensive module scans, ~15-30 min',
            'timeout': 600,
            'modules': ['nikto', 'whatweb', 'dirb', 'sqlmap', 'hydra', 'crackmapexec', 'impacket']
        },
        {
            'id': 'full',
            'name': 'Full Scan',
            'desc': 'All modules with aggressive settings, ~30-60 min',
            'timeout': 1200,
            'modules': ['nikto', 'whatweb', 'dirb', 'sqlmap', 'hydra', 'crackmapexec', 'impacket', 'hashcat']
        }
    ]
    return jsonify(levels)

# ============ ALERTS ============
@app.route('/api/alerts', methods=['GET'])
@require_auth
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 20, type=int)
    
    with db_conn() as conn:
        c = conn.cursor()
        c.execute('''SELECT type, message, severity, timestamp 
                    FROM alerts ORDER BY timestamp DESC LIMIT ?''', (limit,))
        alerts = [{
            'type': r[0],
            'message': r[1],
            'severity': r[2],
            'timestamp': r[3]
        } for r in c.fetchall()]
    
    return jsonify({'alerts': alerts})

# ============ CVE ROUTES ============
@app.route('/api/cve/search', methods=['GET'])
@require_auth
def cve_search():
    """Search CVEs"""
    from modules.cve import search_cves
    
    keyword = request.args.get('q', '')
    severity = request.args.get('severity', '')
    limit = request.args.get('limit', 50, type=int)
    
    cves = search_cves(keyword, severity, limit)
    
    return jsonify({'cves': cves, 'total': len(cves)})

@app.route('/api/cve/update', methods=['POST'])
@require_admin
def cve_update():
    """Update CVE database"""
    from modules.cve import update_cve_db
    
    result = update_cve_db()
    return jsonify(result)

# ============ SYSTEM ROUTES (unifiées dans admin.py) ============
@app.route('/api/system/info', methods=['GET'])
@require_auth
def system_info():
    """Get system information - redirigé vers admin"""
    from modules.admin import system_info as admin_system_info
    return admin_system_info()

@app.route('/api/logs/system', methods=['GET'])
@require_auth
def system_logs():
    """Get system logs - redirigé vers admin"""
    from modules.admin import system_logs as admin_system_logs
    return admin_system_logs()

# ============ MODULE LOCK ============
# Dictionnaire global pour stocker les déverrouillages
high_risk_unlocked = {}

@app.route('/api/modules/status', methods=['GET'])
@require_auth
def module_status():
    """Get high-risk modules unlock status"""
    username = request.current_user['username']
    expiry = high_risk_unlocked.get(username, 0)
    unlocked = time.time() < expiry
    
    from config import HIGH_RISK_MODULES
    
    return jsonify({
        'unlocked': unlocked,
        'remaining': max(0, int(expiry - time.time())) if unlocked else 0,
        'modules': list(HIGH_RISK_MODULES.keys()),
        'role': request.current_user['role']
    })

@app.route('/api/modules/unlock', methods=['POST'])
@require_admin
def unlock_modules():
    """Unlock high-risk modules"""
    from config import HIGH_RISK_PASSWORD
    
    data = request.json
    password = data.get('password')
    
    if password != HIGH_RISK_PASSWORD:
        audit_log(request.current_user['username'], 'UNLOCK_FAILED', 
                 'Wrong password', request.remote_addr, 'warning')
        return jsonify({'error': 'Invalid unlock password'}), 403
    
    username = request.current_user['username']
    high_risk_unlocked[username] = time.time() + 3600  # 1 hour
    
    audit_log(request.current_user['username'], 'MODULES_UNLOCKED', 
             '60 minutes', request.remote_addr, 'warning')
    
    return jsonify({'success': True, 'unlocked': True, 'expires_in': 3600})

@app.route('/api/modules/lock', methods=['POST'])
@require_admin
def lock_modules():
    """Lock high-risk modules"""
    username = request.current_user['username']
    if username in high_risk_unlocked:
        del high_risk_unlocked[username]
    
    return jsonify({'success': True, 'unlocked': False})

@app.route('/api/scan/<job_id>/result', methods=['GET'])
@require_auth
def scan_result(job_id):
    """Récupère les résultats d'un scan"""
    import json
    
    # Chercher d'abord dans les scans en mémoire
    job = scanner.get_scan_status(job_id)
    if job and job.get('results'):
        return jsonify({'results': job['results']})
    
    # Chercher dans la base de données
    with db_conn() as conn:
        c = conn.cursor()
        c.execute('''SELECT results, target, scan_level, timestamp, duration,
                     open_ports, services, risk_score, vulnerabilities, status
                     FROM scans WHERE id=?''', (job_id,))
        row = c.fetchone()
        
        if row and row[0]:
            try:
                results = json.loads(row[0])
                return jsonify({'results': results})
            except:
                pass
        
        # Chercher dans risk_scans
        c.execute('''SELECT results, target, modules, timestamp, duration, status
                     FROM risk_scans WHERE id=?''', (job_id,))
        row = c.fetchone()
        
        if row and row[0]:
            try:
                results = json.loads(row[0])
                return jsonify({'results': results})
            except:
                pass
    
    return jsonify({'error': 'Résultats non trouvés'}), 404

@app.route('/api/scan/quick', methods=['POST'])
@require_scan
def quick_scan():
    """Scan rapide (ping + ports courants)"""
    try:
        target = request.json.get('target', '').strip()
        if not target or not validate_target(target):
            return jsonify({'error': 'Invalid target'}), 400
        
        for p in ['http://', 'https://']:
            if target.startswith(p):
                target = target[len(p):]
        
        result = {'target': target, 'timestamp': datetime.now().isoformat(), 
                  'reachable': False, 'ping_success': False}
        
        # Test ping
        try:
            import platform
            ping_param = '-n' if platform.system().lower() == 'windows' else '-c'
            res = subprocess.run(['ping', ping_param, '2', '-W', '2', target], 
                                capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                result['reachable'] = True
                result['ping_success'] = True
        except:
            pass
        
        # Test ports courants si ping échoue
        if not result['reachable']:
            for port in [80, 443, 22, 445, 3389]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    if s.connect_ex((target, port)) == 0:
                        result['reachable'] = True
                        result['open_port'] = port
                    s.close()
                    if result['reachable']:
                        break
                except:
                    pass
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ STATS ============
@app.route('/api/stats', methods=['GET'])
@require_auth
def stats():
    """Statistiques globales"""
    try:
        with db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM scans")
            total = c.fetchone()[0] or 0
            
            c.execute("SELECT COUNT(*) FROM scans WHERE status='completed'")
            completed = c.fetchone()[0] or 0
            
            c.execute("SELECT AVG(risk_score) FROM scans WHERE risk_score>0")
            avg_risk = c.fetchone()[0] or 0
            
            c.execute("SELECT COUNT(*) FROM alerts WHERE severity='high'")
            high_alerts = c.fetchone()[0] or 0
            
            c.execute("SELECT SUM(open_ports) FROM scans")
            total_ports = c.fetchone()[0] or 0
            
            c.execute("SELECT COUNT(*) FROM cve_entries")
            cve_count = c.fetchone()[0] or 0
            
            c.execute("SELECT DISTINCT target, timestamp, risk_score FROM scans ORDER BY timestamp DESC LIMIT 10")
            recent = [{'target': r[0], 'timestamp': r[1], 'risk_score': r[2]} for r in c.fetchall()]
            
            active = len(scanner.get_active_scans())
        
        return jsonify({
            'total_scans': total,
            'completed': completed,
            'avg_risk': round(avg_risk, 1),
            'high_alerts': high_alerts,
            'total_ports': total_ports,
            'cve_count': cve_count,
            'recent': recent,
            'active': active
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ STATIC ROUTES ============
@app.route('/')
def index():
    return send_file('static/index.html')

@app.route('/app')
def app_page():
    return send_file('static/index.html')

@app.route('/<path:path>')
def static_files(path):
    if os.path.exists(os.path.join('static', path)):
        return send_from_directory('static', path)
    return 'Not found', 404

# ============ HEALTH ============
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'LAB-SEC',
        'version': '3.2.1',
        'nmap': 'ok' if scanner.nm else 'error',
        'database': 'ok' if os.path.exists(DATABASE_FILE) else 'error',
        'uptime': time.time() - start_time,
        'timestamp': datetime.now().isoformat()
    })

# ============ FAVICON ============
@app.route('/favicon.ico')
def favicon():
    """Sert le favicon"""
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/favicon-32x32.png')
def favicon_32():
    """Sert le favicon 32x32"""
    return send_from_directory('static', 'favicon-32x32.png', mimetype='image/png')

@app.route('/favicon-16x16.png')
def favicon_16():
    """Sert le favicon 16x16"""
    return send_from_directory('static', 'favicon-16x16.png', mimetype='image/png')

@app.route('/apple-touch-icon.png')
def apple_touch_icon():
    """Sert l'icône Apple Touch"""
    return send_from_directory('static', 'apple-touch-icon.png', mimetype='image/png')

@app.route('/site.webmanifest')
def webmanifest():
    """Sert le manifeste web"""
    return send_from_directory('static', 'site.webmanifest', mimetype='application/manifest+json')


# ============ CERTIFICATE CHECK ============
def check_existing_certificates(cert_dir='certs'):
    """Vérifie si des certificats existent déjà"""
    cert_file = os.path.join(cert_dir, 'cert.pem')
    key_file = os.path.join(cert_dir, 'key.pem')
    
    # Créer le dossier certs s'il n'existe pas
    os.makedirs(cert_dir, exist_ok=True)
    
    # Vérifier si les certificats existent et ne sont pas vides
    if os.path.exists(cert_file) and os.path.exists(key_file):
        if os.path.getsize(cert_file) > 0 and os.path.getsize(key_file) > 0:
            logger.info(f"✅ Certificats trouvés dans {cert_dir}/")
            return cert_file, key_file
    
    logger.warning(f"❌ Certificats non trouvés dans {cert_dir}/")
    return None, None

# ============ INIT ============
start_time = time.time()

if __name__ == '__main__':
    # Initialisation
    init_database()
    
    # Scheduler
    scheduler.add_job(backup_db, 'interval', hours=1)
    scheduler.start()
    
    # Affichage
    local_ip = get_local_ip()
    print("="*70)
    print("  LAB-SEC CYBERSECURITY PLATFORM v3.2.1 - PRODUCTION")
    print("="*70)
    
    # Vérifier les certificats existants (PAS de génération automatique)
    cert_file, key_file = check_existing_certificates()
    
    if cert_file and key_file:
        # Mode HTTPS avec certificats existants
        print(f"  🔒 HTTPS:   https://localhost:{SCAN_PORT}")
        print(f"              https://{local_ip}:{SCAN_PORT}")
        print(f"  📜 Certificats: {cert_file}")
        print(f"  🔑 Clé: {key_file}")
        
        try:
            # Tenter de charger les certificats
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_file, key_file)
            USE_HTTPS = True
        except Exception as e:
            logger.error(f"Erreur lors du chargement des certificats: {e}")
            logger.warning("Fallback vers HTTP")
            USE_HTTPS = False
            print(f"  ⚠️  Erreur de chargement: {e}")
    else:
        # Mode HTTP uniquement
        USE_HTTPS = False
        print(f"  🔓 HTTP:    http://localhost:{SCAN_PORT}")
        print(f"              http://{local_ip}:{SCAN_PORT}")
        print("  ⚠️  Mode HTTP uniquement - Placez vos certificats SSL dans le dossier 'certs/'")
        print("     Fichiers attendus: cert.pem et key.pem")
    
    print(f"  Database: {DATABASE_FILE}")
    print("-"*70)
    print("  CONFIGURATION PRODUCTION:")
    print("  ✓ Pas de génération automatique de certificats")
    print("  ✓ Utilisation des certificats existants uniquement")
    print("  ✓ Modules crypto optionnels")
    print("-"*70)
    print("  COMPTES PAR DÉFAUT:")
    print("    admin / admin  (accès complet)")
    print("    viewer / viewer (lecture seule)")
    print("="*70)
    
    try:
        if USE_HTTPS:
            # Lancer en HTTPS avec certificats existants
            app.run(host='0.0.0.0', port=SCAN_PORT, debug=False, threaded=True, ssl_context=context)
        else:
            # Fallback en HTTP
            app.run(host='0.0.0.0', port=SCAN_PORT, debug=False, threaded=True)
    except KeyboardInterrupt:
        scheduler.shutdown()
        logger.info("Serveur arrêté")
    except Exception as e:
        logger.error(f"Erreur au démarrage: {e}")
        sys.exit(1)