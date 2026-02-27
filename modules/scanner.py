#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import nmap
import time
import logging
import threading
import re
from datetime import datetime

# Imports absolus
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SCAN_LEVELS
from modules.risk_scanner import RiskModuleManager

logger = logging.getLogger('LAB-SEC')

class CyberSecScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            self.risk_manager = RiskModuleManager()
            logger.info("Nmap initialized")
        except Exception as e:
            self.nm = None
            logger.error(f"Nmap not available: {e}")
        
        self.scan_jobs = {}
        self.lock = threading.RLock()
    
    def build_nmap_args(self, level, opts=None):
        """Construit les arguments nmap"""
        base = SCAN_LEVELS.get(level, SCAN_LEVELS['normal'])
        args = base['args']
        
        if opts:
            flags = {
                'syn_scan': '-sS', 'tcp_connect': '-sT', 'udp_scan': '-sU',
                'ack_scan': '-sA', 'fin_scan': '-sF', 'xmas_scan': '-sX',
                'null_scan': '-sN', 'no_ping': '-Pn', 'os_detect': '-O',
                'version_detect': '-sV', 'script_scan': '-sC', 'aggressive': '-A',
                'traceroute': '--traceroute', 'all_ports': '-p-', 'fragment': '-f',
                'verbose': '-v', 'reason': '--reason'
            }
            
            for k, v in flags.items():
                if opts.get(k) and v and v not in args:
                    args += f' {v}'
            
            if opts.get('port_range'):
                args += f' -p {opts["port_range"]}'
            
            if opts.get('timing'):
                args = re.sub(r'-T\d', '', args)
                args += f' -T{opts["timing"]}'
            
            if opts.get('vuln_scripts'):
                args += ' --script vuln'
        
        return args
    
    def start_nmap_scan(self, job_id, target, level, opts, user):
        """Démarre un scan nmap"""
        with self.lock:
            self.scan_jobs[job_id] = {
                'type': 'nmap',
                'status': 'running',
                'progress': 0,
                'target': target,
                'level': level,
                'timestamp': datetime.now().isoformat(),
                'user': user['username'],
                'user_id': user['user_id']
            }
        
        def run():
            try:
                if not self.nm:
                    self._update_job_error(job_id, 'Nmap not available')
                    return
                
                args = self.build_nmap_args(level, opts)
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id]['progress'] = 20
                
                logger.info(f"Nmap scan: {target} | args={args}")
                start = time.time()
                
                result = self.nm.scan(hosts=target, arguments=args, timeout=600)
                duration = time.time() - start
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id]['progress'] = 80
                
                # Analyser les résultats
                scan_result = self._analyze_nmap(result, target, level, duration, args)
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id].update({
                            'status': 'completed',
                            'results': scan_result,
                            'progress': 100,
                            'duration': duration
                        })
                
                # Sauvegarder en base
                try:
                    from modules.database import save_scan
                    save_scan({
                        'job_id': job_id,
                        'target': target,
                        'scan_level': level,
                        'scan_type': 'nmap',
                        'nmap_options': opts,
                        'timestamp': datetime.now().isoformat(),
                        'duration': f"{duration:.1f}s",
                        'open_ports': scan_result.get('open_ports', 0),
                        'services': scan_result.get('services', 0),
                        'vulnerabilities': scan_result.get('vulnerabilities', 'low'),
                        'risk_score': scan_result.get('risk_score', 0),
                        'status': 'completed',
                        'results': scan_result,
                        'user_id': user['user_id'],
                        'username': user['username']
                    })
                except Exception as db_error:
                    logger.error(f"Error saving scan to database: {db_error}")
                
            except Exception as e:
                logger.error(f"Nmap scan error: {e}")
                self._update_job_error(job_id, str(e))
        
        threading.Thread(target=run, daemon=True).start()
        return True
    
    def start_risk_scan(self, job_id, target, modules, module_options, user):
        """Démarre un scan de modules à risque"""
        with self.lock:
            self.scan_jobs[job_id] = {
                'type': 'risk',
                'status': 'running',
                'progress': 0,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'user': user['username'],
                'user_id': user['user_id']
            }
        
        def run():
            try:
                # Déléguer au risk manager
                self.risk_manager.start_risk_scan(job_id, target, modules, module_options, user)
                
                # Mettre à jour le statut périodiquement
                while True:
                    time.sleep(2)
                    risk_status = self.risk_manager.get_scan_status(job_id)
                    
                    if not risk_status:
                        with self.lock:
                            if job_id in self.scan_jobs:
                                self.scan_jobs[job_id]['status'] = 'failed'
                                self.scan_jobs[job_id]['progress'] = 100
                        break
                    
                    with self.lock:
                        if job_id in self.scan_jobs:
                            self.scan_jobs[job_id].update({
                                'status': risk_status.get('status', 'running'),
                                'progress': risk_status.get('progress', 0)
                            })
                    
                    if risk_status.get('status') in ('completed', 'failed', 'stopped'):
                        if risk_status.get('results'):
                            with self.lock:
                                if job_id in self.scan_jobs:
                                    self.scan_jobs[job_id]['results'] = risk_status['results']
                        break
                        
            except Exception as e:
                logger.error(f"Risk scan error: {e}")
                self._update_job_error(job_id, str(e))
        
        threading.Thread(target=run, daemon=True).start()
        return True
    
    def start_combined_scan(self, job_id, target, level, nmap_opts, modules, module_options, user):
        """Démarre un scan combiné (nmap + modules)"""
        with self.lock:
            self.scan_jobs[job_id] = {
                'type': 'combined',
                'status': 'running',
                'progress': 0,
                'target': target,
                'nmap_level': level,
                'modules': modules,
                'timestamp': datetime.now().isoformat(),
                'user': user['username'],
                'user_id': user['user_id']
            }
        
        def run():
            try:
                results = {'nmap': None, 'risk_modules': []}
                
                # Exécuter nmap
                if self.nm:
                    with self.lock:
                        if job_id in self.scan_jobs:
                            self.scan_jobs[job_id]['progress'] = 10
                    
                    args = self.build_nmap_args(level, nmap_opts)
                    logger.info(f"Nmap combined: {target}")
                    
                    nmap_start = time.time()
                    nmap_result = self.nm.scan(hosts=target, arguments=args, timeout=300)
                    nmap_duration = time.time() - nmap_start
                    
                    results['nmap'] = self._analyze_nmap(nmap_result, target, level, nmap_duration, args)
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id]['progress'] = 40
                
                # Exécuter les modules à risque si déverrouillés
                if modules:
                    with self.lock:
                        if job_id in self.scan_jobs:
                            self.scan_jobs[job_id]['progress'] = 50
                    
                    risk_results = self.risk_manager.run_multiple_modules(target, modules, module_options)
                    results['risk_modules'] = risk_results
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id]['progress'] = 90
                
                # Fusionner les résultats
                combined = self._merge_results(results)
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id].update({
                            'status': 'completed',
                            'results': combined,
                            'progress': 100
                        })
                
                # Sauvegarder
                try:
                    from modules.database import save_scan
                    save_scan({
                        'job_id': job_id,
                        'target': target,
                        'scan_level': level,
                        'scan_type': 'combined',
                        'nmap_options': nmap_opts,
                        'risk_module_options': module_options,
                        'timestamp': datetime.now().isoformat(),
                        'duration': combined.get('duration'),
                        'open_ports': combined.get('open_ports', 0),
                        'services': combined.get('services', 0),
                        'vulnerabilities': combined.get('vulnerabilities', 'low'),
                        'risk_score': combined.get('risk_score', 0),
                        'status': 'completed',
                        'results': combined,
                        'user_id': user['user_id'],
                        'username': user['username']
                    })
                except Exception as db_error:
                    logger.error(f"Error saving combined scan to database: {db_error}")
                
            except Exception as e:
                logger.error(f"Combined scan error: {e}")
                self._update_job_error(job_id, str(e))
        
        threading.Thread(target=run, daemon=True).start()
        return True
    
    def _merge_results(self, results):
        """Fusionne les résultats nmap et modules"""
        merged = {
            'target': results.get('nmap', {}).get('target', 'unknown'),
            'scan_level': 'combined',
            'timestamp': datetime.now().isoformat(),
            'duration': 'N/A',
            'open_ports': 0,
            'services': 0,
            'vulnerabilities': 'low',
            'risk_score': 0,
            'details': {
                'ports': [],
                'vulns': [],
                'services': [],
                'cves': [],
                'external_tools': []
            }
        }
        
        # Ajouter les résultats nmap
        if results.get('nmap'):
            nmap_res = results['nmap']
            merged['open_ports'] = nmap_res.get('open_ports', 0)
            merged['services'] = nmap_res.get('services', 0)
            merged['details']['ports'] = nmap_res.get('details', {}).get('ports', [])
            merged['details']['services'] = nmap_res.get('details', {}).get('services', [])
            merged['details']['cves'] = nmap_res.get('details', {}).get('cves', [])
            merged['details']['os'] = nmap_res.get('details', {}).get('os', {})
            
            # Ajouter les vulns nmap
            for v in nmap_res.get('details', {}).get('vulns', []):
                merged['details']['vulns'].append(v)
        
        # Ajouter les résultats des modules
        for module_result in results.get('risk_modules', []):
            merged['details']['external_tools'].append(module_result)
            for finding in module_result.get('findings', []):
                merged['details']['vulns'].append(finding)
        
        # Recalculer le risque
        vulns = merged['details']['vulns']
        if any(v.get('severity') == 'critical' for v in vulns):
            merged['vulnerabilities'] = 'critical'
            merged['risk_score'] = min(100, merged['open_ports'] * 2 + 60)
        elif any(v.get('severity') == 'high' for v in vulns):
            merged['vulnerabilities'] = 'high'
            merged['risk_score'] = min(100, merged['open_ports'] * 2 + 45)
        elif vulns:
            merged['vulnerabilities'] = 'medium'
            merged['risk_score'] = min(100, merged['open_ports'] * 2 + 25)
        else:
            merged['vulnerabilities'] = 'low'
            merged['risk_score'] = min(100, merged['open_ports'] * 2 + 5)
        
        return merged
    
    def _update_job_error(self, job_id, error):
        """Met à jour un job en erreur"""
        with self.lock:
            if job_id in self.scan_jobs:
                self.scan_jobs[job_id].update({
                    'status': 'failed',
                    'error': error,
                    'progress': 100
                })
    
    def _analyze_nmap(self, data, target, level, duration, args):
        """Analyse les résultats nmap"""
        result = {
            'target': target,
            'scan_level': level,
            'timestamp': datetime.now().isoformat(),
            'duration': f"{duration:.1f}s",
            'nmap_args': args,
            'status': 'completed',
            'simulated': False
        }
        
        if not data or 'scan' not in data:
            result.update({
                'open_ports': 0,
                'services': 0,
                'vulnerabilities': 'none',
                'risk_score': 0,
                'details': {'ports': [], 'vulns': [], 'services': [], 'cves': []},
                'error': 'No data'
            })
            return result
        
        scan_info = data.get('scan', {})
        host_info = next(iter(scan_info.values()), None) if scan_info else None
        
        if not host_info:
            result.update({
                'open_ports': 0,
                'services': 0,
                'vulnerabilities': 'none',
                'risk_score': 0,
                'details': {'ports': [], 'vulns': [], 'services': [], 'cves': []}
            })
            return result
        
        ports = []
        services_set = set()
        
        for proto in ['tcp', 'udp']:
            for port_num, port_info in host_info.get(proto, {}).items():
                if port_info.get('state') == 'open':
                    port_data = {
                        'port': port_num,
                        'protocol': proto,
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'state': 'open',
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'cpe': port_info.get('cpe', ''),
                        'script_results': {}
                    }
                    if 'script' in port_info:
                        port_data['script_results'] = dict(port_info['script'])
                    ports.append(port_data)
                    if port_info.get('name'):
                        services_set.add(port_info['name'])
        
        # Extraire les CVEs
        cves = self._extract_cves(ports, host_info.get('hostscript', []))
        
        # Détecter les vulnérabilités
        vulns = self._detect_vulns(ports, cves)
        
        # Calculer le risque
        risk_score = self._calc_risk(len(ports), vulns, len(services_set))
        
        # Traceroute
        trace = []
        if 'trace' in data.get('nmap', {}):
            for hop in data['nmap']['trace'].get('hop', []):
                trace.append({
                    'ttl': hop.get('ttl', ''),
                    'ip': hop.get('ipaddr', ''),
                    'hostname': hop.get('host', ''),
                    'rtt': hop.get('rtt', '')
                })
        
        result.update({
            'open_ports': len(ports),
            'services': len(services_set),
            'vulnerabilities': vulns['level'],
            'risk_score': risk_score,
            'details': {
                'ports': ports,
                'vulns': vulns['list'],
                'services': list(services_set),
                'cves': cves,
                'traceroute': trace,
                'nmap_command': f"nmap {args} {target}"
            }
        })
        
        return result
    
    def _extract_cves(self, ports, host_scripts):
        """Extrait les CVEs des résultats"""
        import re
        cves = []
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
        
        for port in ports:
            for script_name, output in port.get('script_results', {}).items():
                for match in cve_pattern.findall(str(output)):
                    cves.append({
                        'cve_id': match,
                        'source': f"port {port['port']}",
                        'script': script_name,
                        'details': str(output)[:300]
                    })
        
        if host_scripts:
            for script in (host_scripts if isinstance(host_scripts, list) else []):
                for match in cve_pattern.findall(str(script.get('output', ''))):
                    cves.append({
                        'cve_id': match,
                        'source': 'host',
                        'script': script.get('id', ''),
                        'details': str(script.get('output', ''))[:300]
                    })
        
        return cves
    
    def _detect_vulns(self, ports, cves):
        """Détecte les vulnérabilités à partir des ports et CVEs"""
        vulns = []
        vuln_level = 'low'
        
        # Vulnérabilités connues par port
        vuln_ports = {
            21: ('FTP', ['CVE-2015-3306'], 'high'),
            23: ('Telnet', ['CVE-2020-10188'], 'critical'),
            25: ('SMTP', ['CVE-2021-34523'], 'high'),
            53: ('DNS', ['CVE-2020-1350'], 'high'),
            135: ('MSRPC', ['CVE-2003-0352'], 'high'),
            139: ('NetBIOS', ['CVE-2017-0143'], 'critical'),
            445: ('SMB', ['CVE-2017-0144', 'CVE-2020-0796'], 'critical'),
            1433: ('MSSQL', ['CVE-2020-0618'], 'high'),
            3306: ('MySQL', ['CVE-2012-2122'], 'high'),
            3389: ('RDP', ['CVE-2019-0708'], 'critical'),
            5900: ('VNC', ['CVE-2006-2369'], 'high'),
            6379: ('Redis', ['CVE-2022-0543'], 'high'),
            27017: ('MongoDB', ['CVE-2020-7928'], 'high')
        }
        
        for port in ports:
            port_num = int(port.get('port', 0))
            if port_num in vuln_ports:
                service, cve_list, severity = vuln_ports[port_num]
                for cve in cve_list:
                    vulns.append({
                        'cve': cve,
                        'severity': severity,
                        'service': service,
                        'port': port_num,
                        'description': f'Potential vulnerability on {service} (port {port_num})',
                        'recommendation': f'Update {service} and apply security patches'
                    })
        
        for cve in cves:
            vulns.append({
                'cve': cve['cve_id'],
                'severity': 'high',
                'service': cve['source'],
                'port': 0,
                'description': cve['details'][:200],
                'recommendation': f'Apply patch for {cve["cve_id"]}'
            })
        
        if any(v['severity'] == 'critical' for v in vulns):
            vuln_level = 'critical'
        elif any(v['severity'] == 'high' for v in vulns):
            vuln_level = 'high'
        elif vulns:
            vuln_level = 'medium'
        
        return {'level': vuln_level, 'list': vulns}
    
    def _calc_risk(self, num_ports, vulns, num_services):
        """Calcule le score de risque"""
        score = 0
        
        if num_ports > 20:
            score += 40
        elif num_ports > 10:
            score += 30
        elif num_ports > 5:
            score += 20
        else:
            score += num_ports * 3
        
        vuln_score = {
            'critical': 60,
            'high': 45,
            'medium': 25,
            'low': 10
        }.get(vulns['level'], 5)
        score += vuln_score
        
        if num_services > 10:
            score += 20
        elif num_services > 5:
            score += 15
        else:
            score += 5
        
        return min(max(score, 0), 100)
    
    def get_scan_status(self, job_id):
        """Récupère le statut d'un scan"""
        with self.lock:
            if job_id in self.scan_jobs:
                return self.scan_jobs[job_id]
        
        # Vérifier dans les scans risk manager
        risk_status = self.risk_manager.get_scan_status(job_id)
        if risk_status:
            risk_status['type'] = 'risk'
            return risk_status
        
        return None
    
    def stop_scan(self, job_id):
        """Arrête un scan en cours"""
        stopped = False
        
        with self.lock:
            if job_id in self.scan_jobs:
                if self.scan_jobs[job_id]['status'] == 'running':
                    self.scan_jobs[job_id]['status'] = 'stopped'
                    stopped = True
        
        if not stopped:
            stopped = self.risk_manager.stop_scan(job_id)
        
        return stopped
    
    def get_active_scans(self):
        """Retourne la liste des scans actifs"""
        active = []
        
        with self.lock:
            # Scans du scanner principal
            for job_id, job in self.scan_jobs.items():
                if job.get('status') in ('running', 'pending'):
                    active.append({
                        'job_id': job_id,
                        'type': job.get('type', 'nmap'),
                        'target': job.get('target'),
                        'progress': job.get('progress', 0),
                        'user': job.get('user')
                    })
        
        # Scans du risk manager
        for job_id, job in self.risk_manager.scan_jobs.items():
            if job.get('status') in ('running', 'pending') and job_id not in [a['job_id'] for a in active]:
                active.append({
                    'job_id': job_id,
                    'type': 'risk',
                    'target': job.get('target'),
                    'progress': job.get('progress', 0),
                    'user': job.get('user')
                })
        
        return active