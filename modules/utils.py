#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import socket
import ipaddress
import logging
from datetime import datetime

from config import LOGS_DIR

def setup_logging():
    """Setup logging configuration"""
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(LOGS_DIR, 'labsec.log')),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger('LAB-SEC')

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        # Fallback
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"

def validate_target(target):
    """Valide la cible d'un scan - accepte IP, IP:port, hostname, hostname:port, URL, CIDR."""
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if not target:
        return False

    # Retirer le protocole
    for prefix in ['http://', 'https://']:
        if target.startswith(prefix):
            target = target[len(prefix):]

    # Retirer le chemin
    target = target.split('/')[0]

    # Séparer host:port
    host = target
    if ':' in target:
        parts = target.rsplit(':', 1)
        try:
            port = int(parts[1])
            if not (1 <= port <= 65535):
                return False
            host = parts[0]
        except ValueError:
            pass

    if not host:
        return False

    # Adresses spéciales
    if host in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
        return True

    # Si ça ressemble à une IP (chiffres et points uniquement) -> valider strictement
    if re.match(r'^[\d\.]+$', host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    # CIDR
    if '/' in host:
        try:
            ipaddress.ip_network(host, strict=False)
            return True
        except ValueError:
            return False

    # IPv6
    if ':' in host or (host.startswith('[') and host.endswith(']')):
        try:
            ipaddress.ip_address(host.strip('[]'))
            return True
        except ValueError:
            return False

    # Hostname / domaine (lettres, chiffres, tirets, points)
    if len(host) >= 1:
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$', host):
            return True
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_]*$', host):
            return True

    return False


def format_duration(seconds):
    """Format duration in seconds to human readable"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{int(minutes)}m {int(secs)}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{int(hours)}h {int(minutes)}m"

def safe_string(text, max_length=100):
    """Safely truncate string"""
    if not text:
        return ''
    text = str(text)
    if len(text) > max_length:
        return text[:max_length] + '...'
    return text