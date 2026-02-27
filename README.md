# LAB-SEC — Cybersecurity Platform

<div align="center">

![LAB-SEC](https://img.shields.io/badge/LAB--SEC-v3.2.1-cyan?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=for-the-badge&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-Internal-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production-green?style=for-the-badge)

**Plateforme professionnelle de tests de pénétration, audit de sécurité et analyse de vulnérabilités.**

*Développée pour environnements de laboratoire et d'audit interne.*

</div>

---

## Table des matières

- [Présentation](#présentation)
- [Architecture](#architecture)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Authentification](#authentification)
- [Modules de scan](#modules-de-scan)
- [Modules à risque élevé](#modules-à-risque-élevé)
- [Rapports PDF](#rapports-pdf)
- [API REST](#api-rest)
- [Sécurité](#sécurité)
- [Structure du projet](#structure-du-projet)
- [Contribuer](#contribuer)

---

## Présentation

LAB-SEC est une plateforme web de cybersécurité complète conçue pour les ingénieurs sécurité et les administrateurs réseau. Elle centralise des outils open-source de pentest (Nmap, Nikto, SQLMap, Hydra, etc.) dans une interface web moderne et sécurisée, avec gestion des utilisateurs, journaux d'audit, rapports PDF professionnels et authentification RADIUS.

> ⚠️ **Avertissement légal** : Cette plateforme est réservée à un usage en environnement de test autorisé. Toute utilisation sur des systèmes sans autorisation explicite est illégale.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     NAVIGATEUR CLIENT                        │
│            Interface Web (HTML5 / JavaScript)                │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS (port 9010)
┌─────────────────────────▼───────────────────────────────────┐
│                   FLASK APPLICATION                          │
│                     app.py — v3.2.1                          │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  auth_bp  │  │reports_bp│  │ tools_bp │  │ admin_bp │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              CyberSecScanner (scanner.py)             │   │
│  │   ┌──────────────┐    ┌──────────────────────────┐   │   │
│  │   │  Nmap Engine │    │   RiskModuleManager      │   │   │
│  │   │ (python-nmap)│    │  (risk_scanner.py)       │   │   │
│  │   └──────────────┘    └──────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────┬──────────────────────────────────────────────┘
               │
┌──────────────▼──────────────┐    ┌──────────────────────────┐
│      SQLite Database        │    │    RADIUS Server          │
│       (labsec.db)           │    │ (Authentification externe) │
│  users / scans / risk_scans │    └──────────────────────────┘
│  alerts / cve_entries / logs│
└─────────────────────────────┘
```

Pour le diagramme draw.io complet, voir le fichier `LAB-SEC-Architecture.drawio` inclus dans ce dépôt.

---

## Fonctionnalités

### 🔍 Scanning réseau
| Fonctionnalité | Description |
|---|---|
| **Quick Scan** | Top 100 ports, ~2 min (`-T4 -F`) |
| **Normal Scan** | Top 1000 ports + détection de versions, ~5 min |
| **Advanced Scan** | TCP complet + OS fingerprinting, ~15 min |
| **Full Scan** | TCP + UDP complet, ~30 min |
| **Stealth Scan** | Mode évasif SYN (-T2 -f), ~10 min |
| **Vuln Scan** | Détection CVE via scripts NSE, ~45 min |
| **Exploit Scan** | Tests d'exploitation actifs (dangereux) |
| **Brute Force Scan** | Brute-force d'authentification via Nmap |

### 🛠️ Outils réseau intégrés
- **DNS Lookup** — résolution de noms, records A/MX/TXT/NS
- **WHOIS** — informations d'enregistrement de domaine
- **Traceroute** — cartographie du chemin réseau
- **Port Scanner** — scan TCP/UDP ciblé
- **SSL/TLS Inspector** — analyse des certificats et chiffrements
- **Quick Ping** — test de disponibilité multi-protocole

### 📊 Gestion & Reporting
- Historique complet des scans (Nmap + modules à risque)
- **Rapports PDF professionnels** avec CVSS scoring
- Base de données CVE intégrée avec mise à jour
- Tableau de bord statistiques en temps réel
- Alertes de sécurité avec niveaux de criticité

### 👥 Administration
- Gestion multi-utilisateurs avec rôles (admin / scanner / viewer)
- Journaux d'audit complets
- Sauvegarde automatique de la base de données (toutes les heures)
- Monitoring système (CPU, RAM, disque, uptime)
- Verrouillage des comptes après 5 tentatives échouées

---

## Prérequis

### Système
- **OS** : Debian / Ubuntu 20.04+ (recommandé), Kali Linux
- **Python** : 3.10 ou supérieur
- **Nmap** : 7.80+ (`apt install nmap`)
- **Accès root/sudo** pour l'installation des modules à risque

### Python (voir `requirements.txt`)
```
flask>=2.0.0
flask-cors>=3.0.10
python-nmap>=0.7.0
fpdf>=1.7.2
apscheduler>=3.9.0
python-whois>=0.8.0
python-dateutil>=2.8.2
requests>=2.28.0
pyrad>=2.1
APScheduler==3.10.4
cryptography==41.0.7
pyOpenSSL==23.3.0
reportlab==4.0.9
Pillow==12.1.1
```

---

## Installation

### 1. Cloner le dépôt
```bash
git clone https://github.com/LAB-INF0/lab-sec.git
cd lab-sec
```

### 2. Installer les dépendances Python
```bash
pip3 install -r requirements.txt --break-system-packages
```

### 3. Installer Nmap
```bash
sudo apt-get install -y nmap
```

### 4. (Optionnel) Certificats SSL
Placer vos certificats dans le dossier `certs/` :
```
certs/
├── cert.pem
└── key.pem
```
Sans certificats, l'application démarre en mode HTTP.

### 5. Démarrer l'application
```bash
# Démarrage simple
python3 app.py

# Démarrage avec configuration RADIUS (recommandé en production)
chmod +x start.sh && ./start.sh
```

L'application sera disponible sur : `http://localhost:9010` (ou `https://` si certificats présents)

---

## Configuration

### Variables d'environnement (`start.sh`)

| Variable | Description | Exemple |
|---|---|---|
| `RADIUS_SERVER` | Adresse du serveur RADIUS | `home.local` |
| `RADIUS_PORT` | Port RADIUS | `1812` |
| `RADIUS_SECRET` | Secret partagé RADIUS | `*****` |
| `RADIUS_TIMEOUT` | Timeout en secondes | `5` |
| `RADIUS_RETRIES` | Nombre de tentatives | `2` |
| `RADIUS_NAS_IDENTIFIER` | Identifiant NAS | `NFM` |
| `RADIUS_NAS_IP` | IP du NAS | `192.168.x.60` |
| `RADIUS_ALLOWED_GROUPS` | Groupes autorisés | `GRP-RAD-NFM` |
| `RADIUS_GROUP_ATTRIBUTE` | Attribut de groupe | `Class` |
| `HIGH_RISK_PASSWORD` | Mot de passe de déverrouillage des modules | `LabSec@2025!` |

### Paramètres `config.py`

| Paramètre | Valeur par défaut | Description |
|---|---|---|
| `SCAN_PORT` | `9010` | Port d'écoute de l'application |
| `SESSION_TIMEOUT` | `30` (minutes) | Durée des sessions |
| `DATABASE_FILE` | `data/labsec.db` | Chemin de la base SQLite |

---

## Authentification

LAB-SEC supporte deux modes d'authentification :

### Authentification locale
Comptes stockés localement en base de données avec hash SHA-256 + salt.

**Comptes par défaut :**
| Utilisateur | Mot de passe | Rôle |
|---|---|---|
| `admin` | `admin` | Administrateur |
| `viewer` | `viewer` | Lecture seule |

> ⚠️ **Changer les mots de passe par défaut en production !**
```bash
python3 reset_admin.py
```

### Authentification RADIUS
Intégration native via le protocole RADIUS (RFC 2865) avec support des attributs de groupe pour le contrôle d'accès.

```
Client ──► Flask App ──► RADIUS Server (PAP)
                              │
                         Vérification groupe
                         (attribut "Class")
```

### Rôles et permissions

| Rôle | Lecture | Scan | Admin |
|---|---|---|---|
| `viewer` | ✅ | ❌ | ❌ |
| `scanner` | ✅ | ✅ | ❌ |
| `admin` | ✅ | ✅ | ✅ |

---

## Modules de scan

### Niveaux de scan Nmap

```
Quick     ─► -T4 -F                          (Top 100 ports, ~2 min)
Normal    ─► -sV -sC -T3                     (Top 1000 + versions, ~5 min)
Advanced  ─► -sS -sV -sC -O -A -T4          (TCP + OS detect, ~15 min)
Full      ─► -sS -sU -sV -sC -O -A -T4 -p-  (TCP+UDP all ports, ~30 min)
Stealth   ─► -sS -T2 -f                      (Furtif, ~10 min)
Vuln      ─► -sV --script vuln -T4           (CVE detection, ~45 min) ⚠️
Exploit   ─► -sV --script exploit,vuln -T4   (Exploitation) ⚠️
Brute     ─► -sV --script brute,auth -T4     (Auth brute force) ⚠️
```

### Options avancées
- Sélection du type de scan (SYN, TCP Connect, UDP, ACK, FIN, XMAS, NULL)
- Plage de ports personnalisée
- Timing configurable (T0 à T5)
- Détection OS, versions, scripts NSE
- Mode sans ping (`-Pn`), fragmentation, traceroute

---

## Modules à risque élevé

Ces modules nécessitent un **déverrouillage explicite** avec mot de passe administrateur. Leur utilisation est journalisée.

### Nikto
Scanner de vulnérabilités web (headers HTTP, fichiers sensibles, CVE web).
```
Options : port, SSL, tuning (catégorie de tests), durée max
Tunings : Injection, XSS, SQLi, Upload, RCE, DoS, Mauvaise config...
```

### WhatWeb
Identification des technologies web (CMS, frameworks, serveurs, versions).
```
Options : niveau d'agressivité (1=passif → 4=brute-force), port, SSL, verbeux
```

### SQLMap
Détection et exploitation automatique des injections SQL.
```
Options : port, SSL, niveau d'intensité (1-5), niveau de risque (1-3), 
          profondeur de crawl, test des formulaires
```

### Dirb / Gobuster
Brute-force de répertoires et fichiers cachés sur serveur web.
```
Wordlists : common.txt, big.txt, small.txt, DirBuster, SecLists
Options : récursif, threads, extensions (php,html,txt,bak...)
```

### Hydra
Brute-force de services d'authentification réseau.
```
Services : SSH, FTP, RDP, SMB, MySQL, MSSQL, PostgreSQL, 
           HTTP Basic, HTTP Form, VNC, Telnet, POP3, IMAP, SNMP
Wordlists : fasttrack, unix_passwords, rockyou (14M)
```

### CrackMapExec / NetExec
Audit de sécurité Active Directory, SMB, WinRM, LDAP.
```
Protocoles : SMB, WinRM, LDAP, MSSQL, SSH, RDP
Fonctions  : énumération partages, utilisateurs, politique de mots de passe,
             vérification SMB Signing
```

### Impacket
Suite d'outils réseau Windows (SMB, Kerberos, LDAP, RPC).
```
Outils : smbclient, smbmap, lookupsid, rpcdump, samrdump, GetADUsers
Options : session anonyme (null session), port SMB (445/139)
```

### Hashcat
Cassage de hashs par dictionnaire/règles.
```
Types : MD5, SHA1, SHA-256, SHA-512, NTLM, bcrypt, 
        Kerberos TGS (AS-REP), WPA2
Wordlists : rockyou.txt (14M), fasttrack, SecLists
Règles    : best64, rockyou-30000, leetspeak
```

---

## Rapports PDF

Génération de rapports professionnels au format A4 incluant :

- **Page de garde** avec métadonnées, cible, date et niveau de scan
- **Résumé exécutif** avec score de risque global (CVSS)
- **Tableau des ports ouverts** avec services et versions détectées
- **Analyse des vulnérabilités** classées par criticité (Critical / High / Medium / Low / Info)
- **Détail des CVE** détectées avec score CVSS et description
- **Résultats des modules à risque** (Nikto, SQLMap, etc.)
- **Recommandations** de remédiation
- En-tête/pied de page avec numérotation et horodatage

```
GET /api/report/{scan_id}?format=pdf
```

---

## API REST

### Authentification
```
POST /api/auth/login          — Connexion (local ou RADIUS)
POST /api/auth/logout         — Déconnexion
GET  /api/auth/me             — Profil utilisateur courant
```

### Scans
```
POST /api/scan/nmap           — Démarrer un scan Nmap
POST /api/scan/risk           — Démarrer un scan de modules à risque
POST /api/scan/combined       — Scan combiné (Nmap + modules)
POST /api/scan/quick          — Ping rapide / test de connectivité
GET  /api/scan/{job_id}/status — Statut d'un scan
GET  /api/scan/{job_id}/result — Résultats d'un scan
POST /api/scan/{job_id}/stop  — Arrêter un scan
GET  /api/scan/active         — Scans en cours
GET  /api/scan/history        — Historique (filtre: type=nmap|risk|all)
GET  /api/scan/levels         — Niveaux de scan disponibles
```

### Modules à risque
```
GET  /api/risk/modules        — Liste des modules et statut d'installation
POST /api/risk/install        — Installer un module (admin)
POST /api/risk/check          — Vérifier si les modules sont installés
GET  /api/risk/options/{id}   — Options configurables d'un module
GET  /api/risk/scan-levels    — Niveaux de scan risk
```

### Modules — Verrouillage
```
GET  /api/modules/status      — Statut de déverrouillage
POST /api/modules/unlock      — Déverrouiller les modules (admin, ~1h)
POST /api/modules/lock        — Verrouiller les modules
```

### Outils réseau
```
POST /api/dns                 — Résolution DNS
POST /api/whois               — Recherche WHOIS
POST /api/traceroute          — Traceroute
POST /api/ssl                 — Inspection certificat SSL/TLS
```

### CVE
```
GET  /api/cve/search          — Recherche CVE (filtre: q, severity, limit)
POST /api/cve/update          — Mise à jour base CVE (admin)
```

### Administration
```
GET  /api/admin/users         — Liste des utilisateurs
POST /api/admin/users         — Créer un utilisateur
PUT  /api/admin/users/{id}    — Modifier un utilisateur
DEL  /api/admin/users/{id}    — Supprimer un utilisateur
GET  /api/system/info         — Infos système (CPU, RAM, disque)
GET  /api/logs/system         — Logs système
```

### Statistiques & Alertes
```
GET  /api/stats               — Statistiques globales
GET  /api/alerts              — Alertes récentes
GET  /api/health              — Health check
```

---

## Sécurité

### Mécanismes de protection
- **Sessions JWT** avec expiration configurable (30 min par défaut)
- **Verrouillage de compte** après 5 tentatives échouées (15 min)
- **Déverrouillage temporisé** des modules à risque (1h, mot de passe dédié)
- **Journal d'audit** de toutes les actions sensibles
- **Validation des cibles** avant tout scan (anti-SSRF)
- **CORS** configuré avec support des credentials
- **HTTPS** natif avec certificats SSL personnalisables
- **Roles RBAC** : viewer / scanner / admin

### Journaux d'audit
Toutes les actions sensibles sont tracées :
```
SCAN_STARTED    — Démarrage d'un scan
SCAN_STOPPED    — Arrêt manuel d'un scan
MODULES_UNLOCKED — Déverrouillage des modules à risque
UNLOCK_FAILED   — Échec de déverrouillage
LOGIN / LOGOUT  — Connexions/Déconnexions
USER_CREATED    — Création de compte
```

---

## Structure du projet

```
lab-sec/
├── app.py                  # Application Flask principale
├── config.py               # Configuration globale et modules
├── requirements.txt        # Dépendances Python
├── start.sh                # Script de démarrage (config RADIUS)
├── reset_admin.py          # Réinitialisation du compte admin
├── diag.py                 # Script de diagnostic système
├── dictionary.radius       # Dictionnaire attributs RADIUS
│
├── static/                 # Interface web (HTML5/JS)
│   ├── index.html          # Single Page Application
│   ├── favicon.ico
│   ├── site.webmanifest.json
│   └── *.png               # Icônes (PWA ready)
│
├── modules/
│   ├── __init__.py
│   ├── app.py              # Point d'entrée Flask
│   ├── auth.py             # Authentification (local + RADIUS)
│   ├── scanner.py          # Moteur de scan Nmap
│   ├── risk_scanner.py     # Gestionnaire des modules à risque
│   ├── reports.py          # Génération PDF (ReportLab)
│   ├── tools.py            # Outils réseau (DNS, WHOIS, SSL...)
│   ├── admin.py            # Administration utilisateurs & système
│   ├── database.py         # Gestion SQLite
│   ├── cve.py              # Base de données CVE
│   └── utils.py            # Utilitaires communs
│
├── data/                   # Données générées (gitignore)
│   ├── labsec.db           # Base de données SQLite
│   ├── reports/            # Rapports PDF générés
│   ├── backups/            # Sauvegardes DB automatiques
│   ├── logs/               # Journaux applicatifs
│   └── cve_database/       # Cache base de données CVE
│
└── certs/                  # Certificats SSL (gitignore)
    ├── cert.pem
    └── key.pem
```

---

## Contribuer

Ce projet est développé pour l'usage interne. Pour toute suggestion ou rapport de bug :

1. Ouvrir une issue sur [github.com/LAB-INF0](https://github.com/LAB-INF0)
2. Décrire le problème avec les logs associés (`data/logs/`)
3. Spécifier l'environnement (OS, Python version, Nmap version)

---

<div align="center">

**LAB-SEC v3.2.1** — Développé par [LAB-INF0](https://github.com/LAB-INF0)

*Usage réservé aux environnements de test autorisés.*

</div>
