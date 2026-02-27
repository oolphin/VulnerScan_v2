#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import secrets
from pathlib import Path

# Chemins
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
REPORTS_DIR = DATA_DIR / 'reports'
BACKUP_DIR = DATA_DIR / 'backups'
LOGS_DIR = DATA_DIR / 'logs'
CVE_DIR = DATA_DIR / 'cve_database'

for d in [DATA_DIR, REPORTS_DIR, BACKUP_DIR, LOGS_DIR, CVE_DIR]:
    d.mkdir(exist_ok=True, parents=True)

# Configuration serveur
SCAN_PORT = 9010
DATABASE_FILE = DATA_DIR / 'labsec.db'
SECRET_KEY = secrets.token_hex(32)
SESSION_TIMEOUT = 30  # minutes

# Authentification
RADIUS_SERVER = os.environ.get('RADIUS_SERVER', '')
RADIUS_PORT = int(os.environ.get('RADIUS_PORT', 1812))
RADIUS_SECRET = os.environ.get('RADIUS_SECRET', '')
HIGH_RISK_PASSWORD = os.environ.get('HIGH_RISK_PASSWORD', 'LabSec@2025!')

# Modules à risque
HIGH_RISK_MODULES = {
    'nikto': {
        'name': 'Nikto',
        'desc': 'Scanner de vulnérabilités web (headers, fichiers sensibles, CVE)',
        'binary': 'nikto',
        'install_cmd': ['apt-get', 'install', '-y', 'nikto'],
        'check_cmd':   ['nikto', '-Version'],
        'options': {
            'port': {
                'label': 'Port HTTP/HTTPS',
                'desc':  'Port cible (vide = 80 ou 443)',
                'type': 'int', 'default': '', 'min': 1, 'max': 65535, 'optional': True
            },
            'ssl': {
                'label': 'Forcer SSL/TLS',
                'desc':  'Activer si le service utilise HTTPS',
                'type': 'bool', 'default': False
            },
            'tuning': {
                'label': 'Tuning (catégories de tests)',
                'desc':  '1=Info, 2=Fichiers intéressants, 3=Mauvaise config, 4=Injection, 5=XSS, 6=Déni de service, 7=Remote Shell, 8=Upload, 9=SQL Injection',
                'type': 'select',
                'options': [
                    {'value': '1',   'label': '1 – Divulgation info'},
                    {'value': '2',   'label': '2 – Fichiers intéressants'},
                    {'value': '3',   'label': '3 – Mauvaise configuration'},
                    {'value': '4',   'label': '4 – Injection'},
                    {'value': '5',   'label': '5 – Cross-Site Scripting (XSS)'},
                    {'value': '6',   'label': '6 – Déni de service'},
                    {'value': '7',   'label': '7 – Remote Shell / RCE'},
                    {'value': '8',   'label': '8 – Upload de fichiers'},
                    {'value': '9',   'label': '9 – SQL Injection'},
                    {'value': 'x',   'label': 'x – Injection XML/XSS avancé'},
                    {'value': 'b',   'label': 'b – Identification software'},
                    {'value': '',    'label': 'Tous (défaut)'},
                ],
                'default': ''
            },
            'maxtime': {
                'label': 'Durée max (secondes)',
                'desc':  'Arrêter le scan après N secondes',
                'type': 'int', 'default': 180, 'min': 30, 'max': 3600
            },
        }
    },

    'whatweb': {
        'name': 'WhatWeb',
        'desc': 'Identification des technologies web (CMS, frameworks, serveurs)',
        'binary': 'whatweb',
        'install_cmd': ['apt-get', 'install', '-y', 'whatweb'],
        'check_cmd':   ['whatweb', '--version'],
        'options': {
            'aggression': {
                'label': "Niveau d'agressivité",
                'desc':  '1=Passif (1 req), 2=Passif +(301), 3=Agressif, 4=Lourd (brute-force)',
                'type': 'select',
                'options': [
                    {'value': '1', 'label': '1 – Passif (furtif, 1 requête)'},
                    {'value': '2', 'label': '2 – Passif+ (suit les redirections)'},
                    {'value': '3', 'label': '3 – Agressif (recommandé)'},
                    {'value': '4', 'label': '4 – Lourd (brute-force plugins)'},
                ],
                'default': '3'
            },
            'port': {
                'label': 'Port (optionnel)',
                'desc':  'Port si différent de 80/443',
                'type': 'int', 'default': '', 'min': 1, 'max': 65535, 'optional': True
            },
            'ssl': {
                'label': 'Utiliser HTTPS',
                'desc':  'Forcer la connexion en HTTPS',
                'type': 'bool', 'default': False
            },
            'verbose': {
                'label': 'Mode verbeux',
                'desc':  'Afficher les détails de chaque plugin',
                'type': 'bool', 'default': False
            },
        }
    },

    'sqlmap': {
        'name': 'SQLMap',
        'desc': 'Détection et exploitation automatique des injections SQL',
        'binary': 'sqlmap',
        'install_cmd': ['apt-get', 'install', '-y', 'sqlmap'],
        'check_cmd':   ['sqlmap', '--version'],
        'options': {
            'port': {
                'label': 'Port (optionnel)',
                'desc':  'Port si différent de 80/443',
                'type': 'int', 'default': '', 'min': 1, 'max': 65535, 'optional': True
            },
            'ssl': {
                'label': 'Utiliser HTTPS',
                'desc':  'Forcer SSL sur la connexion',
                'type': 'bool', 'default': False
            },
            'level': {
                'label': "Niveau d'intensité",
                'desc':  '1=Basique → 5=Exhaustif (plus de vecteurs testés)',
                'type': 'select',
                'options': [
                    {'value': '1', 'label': '1 – Basique (rapide)'},
                    {'value': '2', 'label': '2 – Normal'},
                    {'value': '3', 'label': '3 – Moyen'},
                    {'value': '4', 'label': '4 – Approfondi'},
                    {'value': '5', 'label': '5 – Exhaustif (lent)'},
                ],
                'default': '1'
            },
            'risk': {
                'label': 'Niveau de risque',
                'desc':  '1=Sûr → 3=Risqué (peut endommager la base de données)',
                'type': 'select',
                'options': [
                    {'value': '1', 'label': '1 – Faible (sûr)'},
                    {'value': '2', 'label': '2 – Moyen'},
                    {'value': '3', 'label': '3 – Élevé (peut modifier des données)'},
                ],
                'default': '1'
            },
            'crawl': {
                'label': 'Profondeur de crawl',
                'desc':  'Nombre de niveaux de liens à parcourir',
                'type': 'int', 'default': 1, 'min': 0, 'max': 5
            },
            'forms': {
                'label': 'Tester les formulaires',
                'desc':  'Analyser automatiquement les formulaires HTML',
                'type': 'bool', 'default': True
            },
        }
    },

    'dirb': {
        'name': 'Dirb / Gobuster',
        'desc': 'Brute-force de répertoires et fichiers cachés sur serveur web',
        'binary': 'dirb',
        'binary_alt': 'gobuster',
        'install_cmd': ['apt-get', 'install', '-y', 'dirb'],
        'check_cmd':   ['dirb', '/dev/null'],
        'options': {
            'port': {
                'label': 'Port (optionnel)',
                'desc':  'Port si différent de 80/443',
                'type': 'int', 'default': '', 'min': 1, 'max': 65535, 'optional': True
            },
            'ssl': {
                'label': 'Utiliser HTTPS',
                'desc':  'Activer si le service utilise HTTPS',
                'type': 'bool', 'default': False
            },
            'wordlist': {
                'label': 'Wordlist',
                'desc':  'Chemin absolu vers la liste de mots',
                'type': 'select',
                'options': [
                    {'value': '/usr/share/dirb/wordlists/common.txt',      'label': 'common.txt (4k entrées)'},
                    {'value': '/usr/share/dirb/wordlists/big.txt',         'label': 'big.txt (20k entrées)'},
                    {'value': '/usr/share/dirb/wordlists/small.txt',       'label': 'small.txt (959 entrées)'},
                    {'value': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt', 'label': 'DirBuster medium (220k)'},
                    {'value': '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt', 'label': 'SecLists raft-medium'},
                ],
                'default': '/usr/share/dirb/wordlists/common.txt'
            },
            'recursive': {
                'label': 'Scan récursif',
                'desc':  'Parcourir récursivement les répertoires trouvés',
                'type': 'bool', 'default': False
            },
            'threads': {
                'label': 'Threads simultanés',
                'desc':  'Nombre de requêtes parallèles',
                'type': 'int', 'default': 10, 'min': 1, 'max': 50
            },
            'extensions': {
                'label': 'Extensions à tester',
                'desc':  'Extensions séparées par virgule (ex: php,html,txt)',
                'type': 'text', 'default': 'php,html,txt,bak,old'
            },
        }
    },

    'hydra': {
        'name': 'Hydra',
        'desc': 'Brute-force de services d\'authentification réseau',
        'binary': 'hydra',
        'install_cmd': ['apt-get', 'install', '-y', 'hydra'],
        'check_cmd':   ['hydra', '-h'],
        'options': {
            'service': {
                'label': 'Service cible',
                'desc':  'Protocole d\'authentification à attaquer',
                'type': 'select',
                'options': [
                    {'value': 'ssh',        'label': 'SSH (port 22)'},
                    {'value': 'ftp',        'label': 'FTP (port 21)'},
                    {'value': 'rdp',        'label': 'RDP (port 3389)'},
                    {'value': 'smb',        'label': 'SMB (port 445)'},
                    {'value': 'mysql',      'label': 'MySQL (port 3306)'},
                    {'value': 'mssql',      'label': 'MSSQL (port 1433)'},
                    {'value': 'postgres',   'label': 'PostgreSQL (port 5432)'},
                    {'value': 'http-get',   'label': 'HTTP Basic Auth (GET)'},
                    {'value': 'http-post-form', 'label': 'HTTP Form (POST)'},
                    {'value': 'vnc',        'label': 'VNC'},
                    {'value': 'telnet',     'label': 'Telnet'},
                    {'value': 'pop3',       'label': 'POP3 (port 110)'},
                    {'value': 'imap',       'label': 'IMAP (port 143)'},
                    {'value': 'snmp',       'label': 'SNMP'},
                ],
                'default': 'ssh'
            },
            'port': {
                'label': 'Port (optionnel)',
                'desc':  'Laisser vide pour utiliser le port standard du service',
                'type': 'int', 'default': '', 'min': 1, 'max': 65535, 'optional': True
            },
            'wordlist': {
                'label': 'Wordlist mots de passe',
                'desc':  'Chemin de la liste de mots de passe',
                'type': 'select',
                'options': [
                    {'value': '/usr/share/wordlists/fasttrack.txt',          'label': 'fasttrack.txt (222 mdp communs)'},
                    {'value': '/usr/share/wordlists/metasploit/unix_passwords.txt', 'label': 'unix_passwords.txt (1009)'},
                    {'value': '/usr/share/wordlists/metasploit/common_roots.txt',   'label': 'common_roots.txt (500)'},
                    {'value': '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt', 'label': 'SecLists 10k-common'},
                    {'value': '/usr/share/wordlists/rockyou.txt',            'label': 'rockyou.txt (14M – lent!)'},
                ],
                'default': '/usr/share/wordlists/fasttrack.txt'
            },
            'userlist': {
                'label': 'Wordlist utilisateurs',
                'desc':  'Chemin de la liste d\'utilisateurs',
                'type': 'select',
                'options': [
                    {'value': '/usr/share/wordlists/metasploit/unix_users.txt',  'label': 'unix_users.txt (168)'},
                    {'value': '/usr/share/seclists/Usernames/top-usernames-shortlist.txt', 'label': 'SecLists top usernames'},
                    {'value': '/usr/share/metasploit-framework/data/wordlists/default_users_for_services_unhashed.txt', 'label': 'MSF default users'},
                ],
                'default': '/usr/share/wordlists/metasploit/unix_users.txt'
            },
            'threads': {
                'label': 'Threads parallèles',
                'desc':  'Nombre de tentatives simultanées (max 16 pour SSH)',
                'type': 'int', 'default': 4, 'min': 1, 'max': 64
            },
            'stop_on_success': {
                'label': 'Arrêter au premier succès',
                'desc':  'Stopper dès qu\'un identifiant valide est trouvé',
                'type': 'bool', 'default': True
            },
        }
    },

    'crackmapexec': {
        'name': 'CrackMapExec / NetExec',
        'desc': 'Audit de sécurité Active Directory, SMB, WinRM, LDAP',
        'binary': 'crackmapexec',
        'binary_alt': 'netexec',
        'install_cmd': ['apt-get', 'install', '-y', 'crackmapexec'],
        'check_cmd':   ['crackmapexec', '--help'],
        'options': {
            'protocol': {
                'label': 'Protocole cible',
                'desc':  'Protocole à auditer',
                'type': 'select',
                'options': [
                    {'value': 'smb',   'label': 'SMB – Partages, utilisateurs, policy'},
                    {'value': 'winrm', 'label': 'WinRM – Remote Management (port 5985)'},
                    {'value': 'ldap',  'label': 'LDAP – Active Directory'},
                    {'value': 'mssql', 'label': 'MSSQL – SQL Server'},
                    {'value': 'ssh',   'label': 'SSH'},
                    {'value': 'rdp',   'label': 'RDP'},
                ],
                'default': 'smb'
            },
            'shares': {
                'label': 'Énumérer les partages',
                'desc':  'Lister les partages SMB et leurs permissions',
                'type': 'bool', 'default': True
            },
            'users': {
                'label': 'Énumérer les utilisateurs',
                'desc':  'Lister les comptes du domaine',
                'type': 'bool', 'default': True
            },
            'pass_pol': {
                'label': 'Politique de mots de passe',
                'desc':  'Récupérer la politique de mots de passe du domaine',
                'type': 'bool', 'default': False
            },
            'signing': {
                'label': 'Vérifier SMB Signing',
                'desc':  'Vérifier si la signature SMB est requise (relay attack)',
                'type': 'bool', 'default': True
            },
        }
    },

    'impacket': {
        'name': 'Impacket',
        'desc': 'Suite d\'outils réseau Windows (SMB, Kerberos, LDAP, RPC)',
        'binary': 'impacket-smbclient',
        'install_cmd': ['pip3', 'install', 'impacket', '--break-system-packages'],
        'check_cmd':   ['impacket-smbclient', '--help'],
        'options': {
            'tool': {
                'label': 'Outil Impacket',
                'desc':  'Outil spécifique à utiliser',
                'type': 'select',
                'options': [
                    {'value': 'smbclient',  'label': 'smbclient – Accès partages SMB'},
                    {'value': 'smbmap',     'label': 'smbmap – Cartographie partages SMB'},
                    {'value': 'lookupsid',  'label': 'lookupsid – Énumération SID/utilisateurs'},
                    {'value': 'rpcdump',    'label': 'rpcdump – Dump des endpoints RPC'},
                    {'value': 'samrdump',   'label': 'samrdump – Dump comptes SAM'},
                    {'value': 'GetADUsers', 'label': 'GetADUsers – Utilisateurs Active Directory'},
                ],
                'default': 'smbclient'
            },
            'null_session': {
                'label': 'Session anonyme (null session)',
                'desc':  'Tenter la connexion sans identifiants',
                'type': 'bool', 'default': True
            },
            'port': {
                'label': 'Port SMB',
                'desc':  'Port du service SMB (445 ou 139)',
                'type': 'select',
                'options': [
                    {'value': '445', 'label': '445 (SMB standard)'},
                    {'value': '139', 'label': '139 (NetBIOS)'},
                ],
                'default': '445'
            },
        }
    },

    'hashcat': {
        'name': 'Hashcat',
        'desc': 'Cassage de hashs par GPU (utilisation hors ligne sur fichiers)',
        'binary': 'hashcat',
        'install_cmd': ['apt-get', 'install', '-y', 'hashcat'],
        'check_cmd':   ['hashcat', '--version'],
        'options': {
            'hash_type': {
                'label': 'Type de hash',
                'desc':  'Format du hash à casser (mode Hashcat)',
                'type': 'select',
                'options': [
                    {'value': '0',    'label': '0 – MD5'},
                    {'value': '100',  'label': '100 – SHA1'},
                    {'value': '1400', 'label': '1400 – SHA-256'},
                    {'value': '1700', 'label': '1700 – SHA-512'},
                    {'value': '1000', 'label': '1000 – NTLM (Windows)'},
                    {'value': '3200', 'label': '3200 – bcrypt'},
                    {'value': '13100','label': '13100 – Kerberos TGS (AS-REP)'},
                    {'value': '22000','label': '22000 – WPA2 (PMK)'},
                ],
                'default': '0'
            },
            'wordlist': {
                'label': 'Wordlist',
                'desc':  'Dictionnaire de mots de passe',
                'type': 'select',
                'options': [
                    {'value': '/usr/share/wordlists/rockyou.txt',     'label': 'rockyou.txt (14M)'},
                    {'value': '/usr/share/wordlists/fasttrack.txt',   'label': 'fasttrack.txt (222)'},
                    {'value': '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt', 'label': 'SecLists 10k'},
                ],
                'default': '/usr/share/wordlists/rockyou.txt'
            },
            'rules': {
                'label': 'Fichier de règles',
                'desc':  'Règles de mutation des mots de passe',
                'type': 'select',
                'options': [
                    {'value': '',                                          'label': 'Aucune règle'},
                    {'value': '/usr/share/hashcat/rules/best64.rule',     'label': 'best64 (règles efficaces)'},
                    {'value': '/usr/share/hashcat/rules/rockyou-30000.rule','label': 'rockyou-30000'},
                    {'value': '/usr/share/hashcat/rules/leetspeak.rule',  'label': 'leetspeak'},
                ],
                'default': '/usr/share/hashcat/rules/best64.rule'
            },
            'hash_file': {
                'label': 'Fichier de hashs',
                'desc':  'Chemin absolu vers le fichier contenant les hashs à casser',
                'type': 'text', 'default': '/tmp/hashes.txt'
            },
        }
    },
}

# Plugins standards (non-risqués)
STANDARD_PLUGINS = {
    'nmap': {'name': 'Nmap', 'desc': 'Port scanner (toujours inclus)'}
}

# Niveaux de scan Nmap
SCAN_LEVELS = {
    'quick': {'name': 'Quick', 'args': '-T4 -F', 'desc': 'Top 100 ports, ~2min', 'icon': 'zap'},
    'normal': {'name': 'Normal', 'args': '-sV -sC -T3', 'desc': 'Top 1000 + versions, ~5min', 'icon': 'scan-line'},
    'advanced': {'name': 'Advanced', 'args': '-sS -sV -sC -O -A -T4', 'desc': 'All TCP + OS, ~15min', 'icon': 'search'},
    'full': {'name': 'Full', 'args': '-sS -sU -sV -sC -O -A -T4 -p-', 'desc': 'TCP+UDP complete, ~30min', 'icon': 'shield'},
    'stealth': {'name': 'Stealth', 'args': '-sS -T2 -f', 'desc': 'Evasive SYN, ~10min', 'icon': 'eye-off'},
    'vulnerability': {'name': 'Vuln Scan', 'args': '-sV --script vuln -T4', 'desc': 'CVE detection, ~45min', 'icon': 'bug', 'danger': True},
    'exploit': {'name': 'Exploit', 'args': '-sV --script exploit,vuln -T4', 'desc': 'Exploit testing', 'icon': 'flame', 'danger': True},
    'brute': {'name': 'Brute Force', 'args': '-sV --script brute,auth -T4', 'desc': 'Auth brute force, ~1h', 'icon': 'key', 'danger': True}
}