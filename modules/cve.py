#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import urllib.request
from datetime import datetime
import logging

# Imports absolus
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.database import db_conn

logger = logging.getLogger('LAB-SEC')

def update_cve_db():
    """Update local CVE database with common vulnerabilities"""
    cves = [
        ('CVE-2017-0144', 'EternalBlue SMB RCE - Windows SMB v1 allows remote code execution via crafted packets', 'critical', 9.8, 'Windows SMB', '2017-03-16'),
        ('CVE-2019-0708', 'BlueKeep RDP RCE - Windows RDP allows unauthenticated remote code execution', 'critical', 9.8, 'Windows RDP', '2019-05-14'),
        ('CVE-2020-0796', 'SMBGhost - Windows SMBv3 compression buffer overflow allows RCE', 'critical', 10.0, 'Windows SMBv3', '2020-03-10'),
        ('CVE-2021-44228', 'Log4Shell - Apache Log4j2 JNDI injection allows remote code execution', 'critical', 10.0, 'Apache Log4j', '2021-12-10'),
        ('CVE-2014-0160', 'Heartbleed - OpenSSL heartbeat extension memory disclosure', 'critical', 7.5, 'OpenSSL', '2014-04-07'),
        ('CVE-2014-6271', 'Shellshock - GNU Bash arbitrary command execution via environment variables', 'critical', 9.8, 'GNU Bash', '2014-09-24'),
        ('CVE-2017-0143', 'EternalRomance - Windows SMBv1 transaction handling RCE', 'critical', 9.8, 'Windows SMB', '2017-03-16'),
        ('CVE-2020-1350', 'SIGRed - Windows DNS Server RCE via malicious DNS response', 'critical', 10.0, 'Windows DNS', '2020-07-14'),
        ('CVE-2021-34523', 'ProxyShell - Microsoft Exchange Server elevation of privilege', 'critical', 9.8, 'Microsoft Exchange', '2021-07-13'),
        ('CVE-2019-1181', 'DejaBlue - Windows RDP client/server RCE', 'critical', 9.8, 'Windows RDP', '2019-08-13'),
        ('CVE-2023-48795', 'Terrapin - SSH protocol prefix truncation attack', 'medium', 5.9, 'OpenSSH', '2023-12-18'),
        ('CVE-2022-0543', 'Redis Lua sandbox escape allows arbitrary command execution', 'critical', 10.0, 'Redis', '2022-02-18'),
        ('CVE-2024-3094', 'XZ Utils backdoor - malicious code in liblzma compromises SSH', 'critical', 10.0, 'xz-utils', '2024-03-29'),
        ('CVE-2024-21762', 'FortiOS out-of-bounds write allows remote code execution', 'critical', 9.8, 'Fortinet FortiOS', '2024-02-09'),
        ('CVE-2023-44487', 'HTTP/2 Rapid Reset DDoS attack vector', 'high', 7.5, 'HTTP/2', '2023-10-10'),
        ('CVE-2015-3306', 'ProFTPD mod_copy allows remote file copy without auth', 'critical', 10.0, 'ProFTPD', '2015-04-22'),
        ('CVE-2020-10188', 'Telnetd buffer overflow allows remote code execution', 'critical', 9.8, 'Telnet', '2020-03-06'),
        ('CVE-2003-0352', 'Windows DCOM RPC buffer overflow allows system-level access', 'critical', 10.0, 'Windows MSRPC', '2003-07-16'),
        ('CVE-2006-2369', 'RealVNC authentication bypass allows unauthenticated access', 'high', 7.5, 'VNC', '2006-05-15'),
        ('CVE-2012-2122', 'MySQL/MariaDB authentication bypass via timing attack', 'high', 7.5, 'MySQL', '2012-06-09'),
        ('CVE-2020-0618', 'SQL Server Reporting Services RCE via deserialization', 'high', 8.8, 'MS SQL Server', '2020-02-11'),
        ('CVE-2019-9193', 'PostgreSQL COPY TO/FROM PROGRAM allows OS command execution', 'critical', 9.8, 'PostgreSQL', '2019-04-01'),
        ('CVE-2020-7928', 'MongoDB server crash via malformed wire protocol message', 'high', 6.5, 'MongoDB', '2020-11-23'),
        ('CVE-2021-34527', 'PrintNightmare - Windows Print Spooler RCE', 'critical', 8.8, 'Windows Print Spooler', '2021-07-01'),
        ('CVE-2024-47575', 'FortiManager missing authentication for critical function', 'critical', 9.8, 'FortiManager', '2024-10-23'),
        ('CVE-2023-46805', 'Ivanti Connect Secure auth bypass allows RCE', 'critical', 8.2, 'Ivanti VPN', '2024-01-10'),
        ('CVE-2024-1709', 'ConnectWise ScreenConnect auth bypass allows full system access', 'critical', 10.0, 'ConnectWise', '2024-02-19'),
        ('CVE-2023-4966', 'Citrix Bleed - NetScaler session token disclosure', 'critical', 9.4, 'Citrix NetScaler', '2023-10-10'),
        ('CVE-2024-21887', 'Ivanti Connect Secure command injection', 'critical', 9.1, 'Ivanti VPN', '2024-01-10'),
        ('CVE-2023-22515', 'Atlassian Confluence broken access control allows admin creation', 'critical', 10.0, 'Atlassian Confluence', '2023-10-04'),
        ('CVE-2024-6387', 'regreSSHion - OpenSSH race condition allows unauthenticated RCE', 'high', 8.1, 'OpenSSH', '2024-07-01'),
    ]
    
    try:
        with db_conn() as conn:
            c = conn.cursor()
            count = 0
            
            for cve_id, desc, sev, cvss, prod, pub_date in cves:
                c.execute('''INSERT OR REPLACE INTO cve_entries 
                    (cve_id, description, severity, cvss_score, affected_products, published_date)
                    VALUES (?,?,?,?,?,?)''',
                    (cve_id, desc, sev, cvss, prod, pub_date))
                count += 1
            
            logger.info(f"CVE database updated: {count} entries")
            
            return {'success': True, 'entries': count, 'source': 'local_cache'}
            
    except Exception as e:
        logger.error(f"CVE update error: {e}")
        return {'error': str(e)}

def search_cves(keyword='', severity='', limit=50):
    """Search CVEs in database"""
    with db_conn() as conn:
        c = conn.cursor()
        
        query = "SELECT cve_id, description, severity, cvss_score, affected_products, published_date FROM cve_entries WHERE 1=1"
        params = []
        
        if keyword:
            query += " AND (cve_id LIKE ? OR description LIKE ? OR affected_products LIKE ?)"
            params.extend([f'%{keyword}%'] * 3)
        
        if severity:
            query += " AND severity=?"
            params.append(severity)
        
        query += " ORDER BY cvss_score DESC LIMIT ?"
        params.append(limit)
        
        c.execute(query, params)
        
        results = [{
            'cve_id': r[0],
            'description': r[1],
            'severity': r[2],
            'cvss_score': r[3],
            'products': r[4],
            'date': r[5]
        } for r in c.fetchall()]
        
        return results

def get_cve_stats():
    """Get CVE statistics"""
    with db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cve_entries")
        total = c.fetchone()[0]
        
        c.execute("SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity")
        by_severity = {r[0]: r[1] for r in c.fetchall()}
        
    return {'total': total, 'by_severity': by_severity}