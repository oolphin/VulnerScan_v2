#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import subprocess
import json
import re
import ssl
import hashlib
import ipaddress
import logging
import urllib.request
import urllib.error
from datetime import datetime
import platform
import shutil
import time

from flask import Blueprint, request, jsonify

# Imports absolus
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.auth import require_auth, require_scan
from modules.database import audit_log

logger = logging.getLogger('labsec')
tools_bp = Blueprint('tools', __name__)

# ============ DNS RESOLUTION ============
@tools_bp.route('/dns', methods=['POST'])
@require_auth
def dns_route():
    """DNS lookup endpoint"""
    data = request.json
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Nettoyer la cible
    for prefix in ['http://', 'https://']:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split('/')[0].split(':')[0].strip()
    
    result = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'records': {},
        'resolved_ips': []
    }
    
    # Try to resolve IP
    try:
        ips = []
        addrinfo = socket.getaddrinfo(target, None)
        for addr in addrinfo:
            ip = addr[4][0]
            if ip not in ips:
                ips.append(ip)
        result['resolved_ips'] = ips
    except Exception as e:
        result['dns_error'] = str(e)
    
    # Try reverse DNS for IP
    try:
        ipaddress.ip_address(target)
        try:
            hostname, aliases, addresses = socket.gethostbyaddr(target)
            result['reverse_dns'] = {
                'hostname': hostname,
                'aliases': aliases,
                'addresses': addresses
            }
        except:
            result['reverse_dns'] = None
    except:
        pass
    
    # Try common DNS record types
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    result['records'] = {}
    
    for rtype in record_types:
        try:
            if rtype in ['MX', 'TXT', 'NS', 'SOA']:
                cmd = ['dig', '+short', rtype, target]
            else:
                cmd = ['dig', '+short', target, rtype]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0 and proc.stdout.strip():
                records = [line.strip() for line in proc.stdout.split('\n') if line.strip()]
                if records:
                    result['records'][rtype] = records
        except:
            pass
    
    audit_log(request.current_user['username'], 'DNS', target, request.remote_addr)
    
    return jsonify(result)


# ============ SSL/TLS TEST ============
@tools_bp.route('/ssl-test', methods=['POST'])
@require_auth
def ssl_test_route():
    """SSL/TLS test endpoint with complete results"""
    data = request.json
    target = data.get('target', '').strip()
    port = data.get('port', 443)
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Clean target
    for prefix in ['http://', 'https://']:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split('/')[0].split(':')[0]
    
    result = {
        'target': target,
        'port': port,
        'timestamp': datetime.now().isoformat(),
        'certificate': {},
        'protocols': {},
        'ciphers': [],
        'vulnerabilities': [],
        'headers': {},
        'grade': 'Unknown',
        'score': 0,
        'summary': {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'protocols_supported': []
        }
    }
    
    try:
        # 1. Basic SSL connection to get certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                # Current connection info
                result['protocols']['negotiated'] = ssock.version()
                result['current_cipher'] = {
                    'name': cipher[0] if cipher else '',
                    'protocol': cipher[1] if cipher and len(cipher) > 1 else '',
                    'bits': cipher[2] if cipher and len(cipher) > 2 else 0
                }
                
                # Certificate details
                if cert:
                    # Subject
                    subject = {}
                    for item in cert.get('subject', []):
                        for key, value in item:
                            subject[key] = value
                    
                    # Issuer
                    issuer = {}
                    for item in cert.get('issuer', []):
                        for key, value in item:
                            issuer[key] = value
                    
                    # SAN
                    san = []
                    for item in cert.get('subjectAltName', []):
                        san.append(item[1])
                    
                    # Certificate fingerprint
                    der = ssock.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(der).hexdigest()
                    
                    # Parse dates
                    from email.utils import parsedate_to_datetime
                    not_before = parsedate_to_datetime(cert['notBefore'])
                    not_after = parsedate_to_datetime(cert['notAfter'])
                    days_remaining = (not_after - datetime.now(not_after.tzinfo)).days
                    total_validity = (not_after - not_before).days
                    
                    result['certificate'] = {
                        'subject': subject,
                        'issuer': issuer,
                        'serial_number': cert.get('serialNumber', ''),
                        'version': cert.get('version', ''),
                        'not_before': not_before.strftime('%Y-%m-%d %H:%M:%S'),
                        'not_after': not_after.strftime('%Y-%m-%d %H:%M:%S'),
                        'days_remaining': days_remaining,
                        'total_validity_days': total_validity,
                        'expired': days_remaining < 0,
                        'san': san,
                        'fingerprint_sha256': fingerprint
                    }
                    
                    # Check for long validity (>398 days)
                    if total_validity > 398:
                        result['vulnerabilities'].append({
                            'type': 'long_validity',
                            'severity': 'low',
                            'description': f'Certificate validity ({total_validity} days) exceeds recommended 398 days (Apple/Google requirement)',
                            'recommendation': 'Issue certificate with max 398 days validity'
                        })
        
        # 2. Check certificate trust
        try:
            context_verify = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=10) as sock:
                with context_verify.wrap_socket(sock, server_hostname=target) as ssock:
                    result['certificate']['trusted'] = True
                    result['certificate']['verified_chain'] = True
        except ssl.SSLCertVerificationError as e:
            result['certificate']['trusted'] = False
            result['certificate']['verification_error'] = str(e)
            result['vulnerabilities'].append({
                'type': 'untrusted_certificate',
                'severity': 'high',
                'description': f'Certificate not trusted by system: {str(e)[:100]}',
                'recommendation': 'Use certificate from trusted CA'
            })
        except Exception as e:
            result['certificate']['trusted'] = 'unknown'
        
        # 3. Test supported protocols using openssl if available
        if shutil.which('openssl'):
            protocols_to_test = {
                'ssl2': 'SSLv2',
                'ssl3': 'SSLv3',
                'tls1': 'TLS 1.0',
                'tls1_1': 'TLS 1.1',
                'tls1_2': 'TLS 1.2',
                'tls1_3': 'TLS 1.3'
            }
            
            for proto_flag, proto_name in protocols_to_test.items():
                try:
                    cmd = ['openssl', 's_client', f'-{proto_flag}', '-connect', f'{target}:{port}', '-brief']
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        input='Q\n'
                    )
                    
                    supported = proc.returncode == 0 and 'CONNECTED' in proc.stdout
                    result['protocols'][proto_name] = supported
                    
                    # Check for weak protocols
                    if supported and proto_flag in ['ssl2', 'ssl3', 'tls1', 'tls1_1']:
                        severity = 'critical' if proto_flag in ['ssl2', 'ssl3'] else 'high'
                        result['vulnerabilities'].append({
                            'type': 'weak_protocol',
                            'protocol': proto_name,
                            'severity': severity,
                            'description': f'Deprecated protocol {proto_name} is enabled',
                            'recommendation': f'Disable {proto_name} in server configuration'
                        })
                except:
                    result['protocols'][proto_name] = 'test_failed'
        
        # 4. Check security headers
        try:
            import http.client
            conn = http.client.HTTPSConnection(target, port, timeout=5)
            conn.request('HEAD', '/')
            response = conn.getresponse()
            
            headers = dict(response.getheaders())
            
            result['headers'] = {
                'server': headers.get('Server', ''),
                'strict_transport_security': headers.get('Strict-Transport-Security', ''),
                'x_frame_options': headers.get('X-Frame-Options', ''),
                'x_content_type_options': headers.get('X-Content-Type-Options', ''),
                'content_security_policy': headers.get('Content-Security-Policy', '')[:200],
                'referrer_policy': headers.get('Referrer-Policy', ''),
                'permissions_policy': headers.get('Permissions-Policy', '')[:100]
            }
            
            # Check HSTS
            if not headers.get('Strict-Transport-Security'):
                result['vulnerabilities'].append({
                    'type': 'missing_hsts',
                    'severity': 'medium',
                    'description': 'HTTP Strict Transport Security (HSTS) header missing',
                    'recommendation': 'Add Strict-Transport-Security header with max-age=31536000'
                })
            else:
                hsts = headers['Strict-Transport-Security']
                if 'max-age=' in hsts:
                    import re
                    max_age = re.search(r'max-age=(\d+)', hsts)
                    if max_age and int(max_age.group(1)) < 31536000:
                        result['vulnerabilities'].append({
                            'type': 'short_hsts',
                            'severity': 'low',
                            'description': f'HSTS max-age ({max_age.group(1)}) is less than recommended 1 year',
                            'recommendation': 'Set HSTS max-age to at least 31536000 (1 year)'
                        })
            
            # Check X-Frame-Options
            if not headers.get('X-Frame-Options'):
                result['vulnerabilities'].append({
                    'type': 'missing_x_frame_options',
                    'severity': 'medium',
                    'description': 'X-Frame-Options header missing - site may be vulnerable to clickjacking',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                })
            
            # Check X-Content-Type-Options
            if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
                result['vulnerabilities'].append({
                    'type': 'missing_x_content_type_options',
                    'severity': 'low',
                    'description': 'X-Content-Type-Options: nosniff header missing',
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                })
            
            conn.close()
            
        except Exception as e:
            result['headers_error'] = str(e)
        
        # 5. Calculate score and grade
        score = 100
        
        # Deduct for vulnerabilities
        for vuln in result['vulnerabilities']:
            score -= {
                'critical': 40,
                'high': 25,
                'medium': 15,
                'low': 5
            }.get(vuln.get('severity', 'low'), 5)
        
        # Deduct for expired certificate
        if result.get('certificate', {}).get('expired'):
            score -= 50
        
        # Deduct for untrusted certificate
        if result.get('certificate', {}).get('trusted') == False:
            score -= 30
        
        # Deduct for short remaining validity
        days = result.get('certificate', {}).get('days_remaining', 999)
        if isinstance(days, int) and 0 < days < 30:
            score -= 15
        
        score = max(0, min(100, score))
        result['score'] = score
        
        # Determine grade
        if score >= 90:
            result['grade'] = 'A+'
        elif score >= 80:
            result['grade'] = 'A'
        elif score >= 70:
            result['grade'] = 'B'
        elif score >= 60:
            result['grade'] = 'C'
        elif score >= 40:
            result['grade'] = 'D'
        else:
            result['grade'] = 'F'
        
        # Summary
        result['summary'] = {
            'total_vulnerabilities': len(result['vulnerabilities']),
            'critical': sum(1 for v in result['vulnerabilities'] if v.get('severity') == 'critical'),
            'high': sum(1 for v in result['vulnerabilities'] if v.get('severity') == 'high'),
            'medium': sum(1 for v in result['vulnerabilities'] if v.get('severity') == 'medium'),
            'low': sum(1 for v in result['vulnerabilities'] if v.get('severity') == 'low'),
            'protocols_supported': [k for k, v in result['protocols'].items() if v is True]
        }
        
    except ssl.SSLError as e:
        result['error'] = f"SSL Error: {str(e)}"
    except socket.timeout:
        result['error'] = "Connection timeout"
    except ConnectionRefusedError:
        result['error'] = "Connection refused"
    except Exception as e:
        result['error'] = str(e)
    
    return jsonify(result)


# ============ TRACEROUTE ============
@tools_bp.route('/traceroute', methods=['POST'])
@require_scan
def traceroute_route():
    data = request.json
    target = data.get('target', '').strip()
    advanced = data.get('advanced', False)

    if not target:
        return jsonify({'error': 'Target required'}), 400

    # Nettoyer la cible (retirer protocole/port)
    clean_target = target
    for prefix in ['http://', 'https://']:
        if clean_target.startswith(prefix):
            clean_target = clean_target[len(prefix):]
    clean_target = clean_target.split('/')[0].split(':')[0]

    result = {
        'target': clean_target,
        'timestamp': datetime.now().isoformat(),
        'advanced': advanced,
        'hops': [],
        'total_hops': 0,
        'latency_analysis': []
    }

    system = platform.system().lower()

    try:
        # Résoudre l'IP cible
        try:
            target_ip = socket.gethostbyname(clean_target)
            result['target_ip'] = target_ip
        except:
            target_ip = clean_target
            result['target_ip'] = clean_target

        if system == 'windows':
            traceroute_cmd = 'tracert'
            cmd = [traceroute_cmd, '-d', '-w', '2000', target_ip]
        else:
            # Linux/Unix
            if advanced and shutil.which('traceroute'):
                # Mode avancé avec TCP SYN
                cmd = ['traceroute', '-T', '-p', '80', '-n', '-w', '2', target_ip]
            elif shutil.which('traceroute'):
                # Mode standard
                cmd = ['traceroute', '-n', '-w', '2', target_ip]
            elif shutil.which('mtr'):
                # Fallback mtr
                cmd = ['mtr', '--report', '--report-cycles', '3', '-n', target_ip]
            else:
                return jsonify({'error': 'traceroute not installed. Install with: apt install traceroute'}), 500

        logger.info(f"Traceroute command: {' '.join(cmd)}")
        
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        raw_output = process.stdout or process.stderr
        result['raw'] = raw_output[:1000]  # Garder un extrait

        # Parser la sortie
        hops = []
        prev_rtt = None

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Format Linux traceroute: "1  192.168.1.1  1.234 ms  1.345 ms  1.456 ms"
            # Format Windows tracert: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            
            # Extraire le numéro de hop et le reste
            m = re.match(r'^\s*(\d+)\s+(.*)', line)
            if not m:
                continue

            hop_num = int(m.group(1))
            rest = m.group(2).strip()

            # Timeout: * * *
            if re.match(r'^[\*\s]+$', rest):
                hops.append({
                    'hop': hop_num,
                    'ip': '*',
                    'hostname': None,
                    'avg_rtt': None,
                    'host_type': 'unknown',
                    'asn': None
                })
                continue

            # Extraire IP
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', rest)
            if not ip_match:
                continue
                
            ip = ip_match.group(1)
            
            # Extraire les RTTs (ms)
            rtts = re.findall(r'(\d+\.?\d*)\s*ms', rest)
            if not rtts:
                # Format Windows "<1 ms"
                rtts = re.findall(r'<(\d+)\s*ms', rest)
                if rtts:
                    rtts = [float(rtts[0]) * 0.5]  # Approximation
            
            avg_rtt = round(sum(float(r) for r in rtts) / len(rtts), 2) if rtts else None

            # Classifier le type de nœud
            host_type = 'internet'
            if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                              '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                              '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                              '172.30.', '172.31.', '192.168.', '127.')):
                host_type = 'internal'
            elif avg_rtt and avg_rtt < 2:
                host_type = 'router'

            # Analyse de latence (saut anormal)
            if prev_rtt is not None and avg_rtt is not None:
                delta = avg_rtt - prev_rtt
                if delta > 50:
                    result['latency_analysis'].append({
                        'hop': hop_num,
                        'delay_ms': round(delta, 1),
                        'severity': 'high' if delta > 200 else 'medium',
                        'note': f"Latency spike +{round(delta,1)}ms"
                    })

            if avg_rtt is not None:
                prev_rtt = avg_rtt

            hops.append({
                'hop': hop_num,
                'ip': ip,
                'hostname': None,
                'avg_rtt': avg_rtt,
                'host_type': host_type,
                'asn': None
            })

        result['hops'] = hops
        result['total_hops'] = len(hops)

    except subprocess.TimeoutExpired:
        result['error'] = 'Traceroute timeout (>60s)'
    except Exception as e:
        logger.error(f"Traceroute error: {e}")
        result['error'] = str(e)

    return jsonify(result)


# ============ DISCOVERY ============
@tools_bp.route('/discover', methods=['POST'])
@require_scan
def discover_route():
    """Network discovery endpoint - Real Nmap discovery"""
    data = request.json
    network = data.get('network', '').strip()
    scan_ports = data.get('ports', False)
    scan_os = data.get('os', False)
    
    if not network:
        return jsonify({'error': 'Network required (e.g., 192.168.1.0/24)'}), 400
    
    try:
        # Vérifier si nmap est disponible
        import nmap
        nm = nmap.PortScanner()
        
        # Construire les arguments
        if scan_ports:
            args = '-sS -T4 --top-ports 100'  # Scan des ports courants
            if scan_os:
                args += ' -O'  # Détection OS
        else:
            args = '-sn'  # Ping scan only
        
        logger.info(f"Network discovery on {network} with args: {args}")
        
        # Lancer le scan
        nm.scan(hosts=network, arguments=args, timeout=300)
        
        hosts = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                host_info = {
                    'ip': host,
                    'status': 'up',
                    'hostname': nm[host].hostname() or '',
                    'mac': '',
                    'vendor': '',
                    'os': '',
                    'host_type': 'unknown',
                    'ports': []
                }
                
                # Récupérer l'adresse MAC
                if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                    host_info['mac'] = nm[host]['addresses']['mac']
                    if 'vendor' in nm[host] and nm[host]['vendor']:
                        host_info['vendor'] = list(nm[host]['vendor'].values())[0]
                
                # Détection OS
                if scan_os and 'osmatch' in nm[host] and nm[host]['osmatch']:
                    host_info['os'] = nm[host]['osmatch'][0].get('name', '')
                    # Déterminer le type d'hôte basé sur l'OS
                    os_lower = host_info['os'].lower()
                    if 'windows' in os_lower:
                        host_info['host_type'] = 'workstation' if '10' in os_lower or '11' in os_lower else 'server'
                    elif 'linux' in os_lower:
                        host_info['host_type'] = 'server'
                    elif 'router' in os_lower or 'ios' in os_lower:
                        host_info['host_type'] = 'router'
                    elif 'printer' in os_lower:
                        host_info['host_type'] = 'printer'
                
                # Récupérer les ports ouverts
                if scan_ports:
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_info = nm[host][proto][port]
                            if port_info['state'] == 'open':
                                host_info['ports'].append({
                                    'port': port,
                                    'protocol': proto,
                                    'service': port_info.get('name', 'unknown'),
                                    'state': 'open'
                                })
                
                hosts.append(host_info)
        
        return jsonify({
            'network': network,
            'hosts_found': len(hosts),
            'hosts': hosts,
            'timestamp': datetime.now().isoformat(),
            'simulated': False
        })
        
    except ImportError:
        return jsonify({'error': 'python-nmap module not installed. Install with: pip install python-nmap'}), 500
    except Exception as e:
        logger.error(f"Discovery error: {e}")
        return jsonify({
            'network': network,
            'hosts_found': 0,
            'hosts': [],
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


# ============ WHOIS (version améliorée pour correspondre à l'image) ============
def _whois_raw(server, query, timeout=15):
    """Requête WHOIS brute vers un serveur. Retourne le texte ou None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.send((query + "\r\n").encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"WHOIS raw error ({server}): {e}")
        return None

def _parse_whois_date(date_str):
    """Parse et formate une date WHOIS"""
    if not date_str:
        return None
    
    # Nettoyer la date
    date_str = date_str.strip()
    date_str = re.sub(r'\s+', ' ', date_str)
    date_str = date_str.split('(')[0].strip()  # Enlever les commentaires
    
    # Essayer différents formats
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y.%m.%d %H:%M:%S',
        '%d-%b-%Y %H:%M:%S',
        '%Y/%m/%d %H:%M:%S',
        '%Y-%m-%d',
        '%d/%m/%Y',
        '%m/%d/%Y'
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str[:19], fmt)
            return dt.strftime('%d/%m/%Y %H:%M:%S')
        except:
            continue
    
    return date_str

def _calculate_domain_age(creation_date):
    """Calcule l'âge du domaine en années et mois"""
    if not creation_date:
        return None
    
    try:
        # Parser la date de création
        for fmt in ['%d/%m/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d-%b-%Y %H:%M:%S']:
            try:
                creation = datetime.strptime(creation_date[:19], fmt)
                break
            except:
                continue
        else:
            return None
        
        now = datetime.now()
        delta = now - creation
        
        years = delta.days // 365
        months = (delta.days % 365) // 30
        
        if years > 0:
            return f"{years} ans, {months} mois"
        else:
            return f"{months} mois"
    except:
        return None

def _days_until_expiry(expiry_date):
    """Calcule le nombre de jours avant expiration"""
    if not expiry_date:
        return None
    
    try:
        for fmt in ['%d/%m/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d-%b-%Y %H:%M:%S']:
            try:
                expiry = datetime.strptime(expiry_date[:19], fmt)
                break
            except:
                continue
        else:
            return None
        
        now = datetime.now()
        delta = expiry - now
        return delta.days
    except:
        return None

def perform_complete_whois(domain):
    """WHOIS complet avec formatage amélioré"""
    # Serveurs WHOIS par TLD
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'fr': 'whois.nic.fr',
        'de': 'whois.denic.de',
        'uk': 'whois.nic.uk',
        'co.uk': 'whois.nic.uk',
        'eu': 'whois.eu',
        'info': 'whois.afilias.net',
        'io': 'whois.nic.io',
        'app': 'whois.nic.google',
        'dev': 'whois.nic.google',
        'cloud': 'whois.nic.cloud',
        'xyz': 'whois.nic.xyz',
        'online': 'whois.nic.online',
        'site': 'whois.nic.site',
        'tech': 'whois.nic.tech',
        'store': 'whois.nic.store',
        'me': 'whois.nic.me',
        'co': 'whois.nic.co',
        'ai': 'whois.nic.ai',
        'biz': 'whois.biz',
        'us': 'whois.nic.us',
        'ca': 'whois.cira.ca',
        'au': 'whois.auda.org.au',
        'jp': 'whois.jprs.jp',
        'nl': 'whois.domain-registry.nl',
        'it': 'whois.nic.it',
        'es': 'whois.nic.es',
        'br': 'whois.registro.br',
        'cn': 'whois.cnnic.cn',
        'ru': 'whois.tcinet.ru',
        'be': 'whois.dns.be',
        'ch': 'whois.nic.ch',
        'se': 'whois.iis.se',
        'no': 'whois.norid.no',
        'pl': 'whois.dns.pl',
        'cz': 'whois.nic.cz',
        'at': 'whois.nic.at',
        'hu': 'whois.nic.hu',
        'ro': 'whois.rotld.ro',
        'dk': 'whois.dk-hostmaster.dk',
        'fi': 'whois.fi',
        'pt': 'whois.dns.pt',
        'ie': 'whois.iedr.ie',
        'gr': 'whois.ripe.net',
        'nu': 'whois.iis.nu',
        'nz': 'whois.srs.net.nz',
        'za': 'whois.registry.net.za',
        'in': 'whois.registry.in',
        'sg': 'whois.sgnic.sg',
        'hk': 'whois.hkirc.hk',
        'tw': 'whois.twnic.net.tw',
        'kr': 'whois.kr',
        'mobi': 'whois.dotmobiregistry.net',
        'name': 'whois.nic.name',
        'pro': 'whois.registrypro.pro',
        'travel': 'whois.nic.travel',
        'museum': 'whois.museum',
        'coop': 'whois.nic.coop',
        'aero': 'whois.aero',
        'jobs': 'jobswhois.verisign-grs.com',
        'gov': 'whois.dotgov.gov',
        'edu': 'whois.educause.edu',
        'mil': 'whois.nic.mil',
        'int': 'whois.iana.org',
        'arpa': 'whois.iana.org',
    }

    # Patterns d'extraction WHOIS
    FIELD_PATTERNS = {
        'registrar': [r'Registrar:\s*(.+)', r'registrar:\s*(.+)'],
        'registrar_url': [r'Registrar URL:\s*(.+)', r'registrar-url:\s*(.+)'],
        'registrar_iana': [r'Registrar IANA ID:\s*(\d+)'],
        'dnssec': [r'DNSSEC:\s*(.+)', r'dnssec:\s*(.+)'],
    }
    
    DATE_PATTERNS = {
        'creation': [r'Creation Date:\s*(.+)', r'created:\s*(.+)',
                     r'Registered on:\s*(.+)', r'registration-date:\s*(.+)',
                     r'Created:\s*(.+)', r'created-date:\s*(.+)'],
        'expiry': [r'(?:Registry )?Expiry Date:\s*(.+)', r'expires?:\s*(.+)',
                   r'Expiration Date:\s*(.+)', r'expire-date:\s*(.+)',
                   r'paid-till:\s*(.+)'],
        'updated': [r'Updated Date:\s*(.+)', r'last-updated?:\s*(.+)',
                    r'Last Modified:\s*(.+)', r'changed:\s*(.+)',
                    r'Last updated:\s*(.+)'],
    }
    
    NS_PATTERNS = [r'Name Server:\s*(.+)', r'nserver:\s*(.+)',
                   r'Nameservers?:\s*(.+)', r'Name Servers?:\s*(.+)']
    
    STATUS_PATTERNS = [r'(?:Domain )?Status:\s*(.+)', r'status:\s*(.+)']

    # Construire le résultat
    parts = domain.split('.')
    tld = parts[-1].lower()
    sld = '.'.join(parts[-2:]).lower() if len(parts) >= 3 else ''
    whois_server = WHOIS_SERVERS.get(sld) or WHOIS_SERVERS.get(tld, 'whois.iana.org')

    result = {
        'domain': domain,
        'tld': tld,
        'whois_server': whois_server,
        'raw': '',
        'registrar': '',
        'registrar_url': '',
        'creation_date': '',
        'updated_date': '',
        'expiry_date': '',
        'domain_age': '',
        'days_until_expiration': None,
        'name_servers': [],
        'status': [],
        'dnssec': 'NON SIGNÉ',
        'registrant_email': '',
        'admin_email': '',
        'tech_email': '',
        'sources': []
    }

    # --- Tentative WHOIS ---
    raw_text = _whois_raw(whois_server, domain)
    if raw_text:
        result['raw'] = raw_text
        result['sources'].append(whois_server)

        # Vérifier si le serveur indique un autre serveur
        refer_match = re.search(r'^refer:\s*(.+)', raw_text, re.MULTILINE | re.IGNORECASE)
        whois2_match = re.search(r'^whois:\s*(.+)', raw_text, re.MULTILINE | re.IGNORECASE)
        secondary_server = None
        if refer_match:
            secondary_server = refer_match.group(1).strip()
        elif whois2_match:
            secondary_server = whois2_match.group(1).strip()

        if secondary_server and secondary_server != whois_server:
            raw2 = _whois_raw(secondary_server, domain)
            if raw2:
                raw_text = raw2
                result['raw'] = raw2
                result['whois_server'] = secondary_server
                result['sources'].append(secondary_server)

        lines = raw_text.split('\n')

        def _first_match(patterns_list, line):
            for p in patterns_list:
                m = re.search(p, line.strip(), re.IGNORECASE)
                if m:
                    return m.group(1).strip()
            return None

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('%') or stripped.startswith('#'):
                continue

            # Registrar
            if not result['registrar']:
                val = _first_match(FIELD_PATTERNS['registrar'], stripped)
                if val:
                    result['registrar'] = val

            # Registrar URL
            if not result['registrar_url']:
                val = _first_match(FIELD_PATTERNS['registrar_url'], stripped)
                if val:
                    result['registrar_url'] = val

            # Dates
            if not result['creation_date']:
                val = _first_match(DATE_PATTERNS['creation'], stripped)
                if val:
                    result['creation_date'] = _parse_whois_date(val)

            if not result['updated_date']:
                val = _first_match(DATE_PATTERNS['updated'], stripped)
                if val:
                    result['updated_date'] = _parse_whois_date(val)

            if not result['expiry_date']:
                val = _first_match(DATE_PATTERNS['expiry'], stripped)
                if val:
                    result['expiry_date'] = _parse_whois_date(val)

            # Name servers
            for p in NS_PATTERNS:
                m = re.search(p, stripped, re.IGNORECASE)
                if m:
                    ns = m.group(1).strip().lower().rstrip('.')
                    if ns and ns not in result['name_servers'] and '.' in ns:
                        result['name_servers'].append(ns)
                    break

            # Status
            for p in STATUS_PATTERNS:
                m = re.search(p, stripped, re.IGNORECASE)
                if m:
                    st = m.group(1).strip().split(' ')[0]
                    if st and st not in result['status']:
                        result['status'].append(st)
                    break

            # DNSSEC
            if not result['dnssec'] or result['dnssec'] == 'NON SIGNÉ':
                val = _first_match(FIELD_PATTERNS['dnssec'], stripped)
                if val:
                    result['dnssec'] = val.upper()

            # Emails de contact
            email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', stripped)
            if email_match:
                email = email_match.group(1).lower()
                if 'abuse' in email.lower():
                    result['registrant_email'] = email
                elif 'registrant' in stripped.lower() or 'owner' in stripped.lower():
                    result['registrant_email'] = email
                elif 'admin' in stripped.lower():
                    result['admin_email'] = email
                elif 'tech' in stripped.lower():
                    result['tech_email'] = email

    # Calculer l'âge du domaine
    if result['creation_date']:
        result['domain_age'] = _calculate_domain_age(result['creation_date'])

    # Calculer les jours avant expiration
    if result['expiry_date']:
        result['days_until_expiration'] = _days_until_expiry(result['expiry_date'])

    # Formater les statuts pour l'affichage
    formatted_status = []
    for status in result['status']:
        if 'transferprohibited' in status.lower():
            formatted_status.append('clientTransferProhibited - Protection contre le transfert')
        elif 'clientdeleteprohibited' in status.lower():
            formatted_status.append('clientDeleteProhibited - Protection contre la suppression')
        elif 'clientupdateprohibited' in status.lower():
            formatted_status.append('clientUpdateProhibited - Protection contre la modification')
        elif 'active' in status.lower():
            formatted_status.append('active - Domaine actif')
        elif 'ok' in status.lower():
            formatted_status.append('ok - Statut normal')
        else:
            formatted_status.append(status)

    result['formatted_status'] = formatted_status if formatted_status else ['Aucun statut spécial']

    return result


@tools_bp.route('/whois', methods=['POST'])
@require_auth
def whois_route():
    """WHOIS lookup avec formatage amélioré pour correspondre à l'image"""
    data = request.json
    target = data.get('target', '').strip()

    if not target:
        return jsonify({'error': 'Cible requise'}), 400

    # Nettoyer la cible
    for prefix in ['http://', 'https://']:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split('/')[0].split(':')[0].strip()

    if not target:
        return jsonify({'error': 'Cible invalide'}), 400

    logger.info(f"WHOIS lookup: {target}")
    result = perform_complete_whois(target)

    # Déterminer si c'est une IP
    try:
        ipaddress.ip_address(target)
        result['is_ip'] = True
    except ValueError:
        result['is_ip'] = False

    audit_log(request.current_user['username'], 'WHOIS', target, request.remote_addr)
    return jsonify(result)