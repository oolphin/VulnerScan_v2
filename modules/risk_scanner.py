#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import shutil
import logging
import threading
import time
import json
import os
import re
from datetime import datetime

# Import absolu
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import HIGH_RISK_MODULES

logger = logging.getLogger('LAB-SEC')

class RiskModuleManager:
    """Gestionnaire des modules à risque"""
    
    def __init__(self):
        self.scan_jobs = {}
        self.module_status = {}
        self.lock = threading.RLock()
        self._check_all_modules()
    
    def _check_all_modules(self):
        """Vérifie l'installation de tous les modules"""
        for module_id, module_info in HIGH_RISK_MODULES.items():
            self.module_status[module_id] = self.check_module_installed(module_id)
    
    def check_module_installed(self, module_id):
        """Vérifie si un module est installé — supporte les binaires alternatifs et Snap."""
        if module_id not in HIGH_RISK_MODULES:
            return {'installed': False, 'error': 'Module inconnu'}
        
        module = HIGH_RISK_MODULES[module_id]
        
        # Binaires alternatifs acceptés par module
        ALT = {
            'crackmapexec': ['crackmapexec', 'netexec', 'nxc'],
            'dirb':         ['dirb', 'gobuster', 'ffuf'],
            'impacket':     [
                'impacket-smbclient', 'impacket-lookupsid', 'impacket-rpcdump', 
                'impacket-samrdump', 'impacket-GetADUsers', 'impacket-secretsdump',
                'smbclient.py', 'lookupsid.py', 'rpcdump.py', 'samrdump.py', 
                'GetADUsers.py', 'secretsdump.py',
                # Versions sans préfixe impacket-
                'smbclient', 'lookupsid', 'rpcdump', 'samrdump', 'GetADUsers', 'secretsdump'
            ],
            'hydra':        ['hydra', 'thc-hydra'],
            'sqlmap':       ['sqlmap', 'sqlmap.py'],
            'nikto':        ['nikto', 'nikto.pl'],
            'whatweb':      ['whatweb'],
            'hashcat':      ['hashcat', 'hashcat.bin'],
        }
        
        binaries = ALT.get(module_id, [module.get('binary', module_id)])
        
        # Ajouter /snap/bin au PATH pour la vérification
        env = os.environ.copy()
        current_path = env.get('PATH', '')
        snap_paths = ['/snap/bin', '/var/lib/snapd/snap/bin']
        
        for snap_path in snap_paths:
            if snap_path not in current_path and os.path.exists(snap_path):
                env['PATH'] = f"{snap_path}:{current_path}" if current_path else snap_path
        
        for binary in binaries:
            # Vérifier d'abord avec shutil.which (utilise le PATH mis à jour)
            cmd_path = shutil.which(binary)
            
            # Si pas trouvé, vérifier directement dans les chemins Snap
            if not cmd_path:
                for snap_path in snap_paths:
                    snap_binary = os.path.join(snap_path, binary)
                    if os.path.exists(snap_binary) and os.access(snap_binary, os.X_OK):
                        cmd_path = snap_binary
                        break
            
            if not cmd_path:
                continue
            
            # Construire la commande de vérification
            check_cmd = module.get('check_cmd')
            if check_cmd:
                # Remplacer le premier élément par le chemin complet
                actual_cmd = [cmd_path] + list(check_cmd[1:])
            else:
                # Commande par défaut
                actual_cmd = [cmd_path, '--version']
            
            try:
                result = subprocess.run(
                    actual_cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=8, 
                    env=env
                )
                out = (result.stdout or result.stderr or '').strip()
                version_line = out.split('\n')[0][:60] if out else binary
                
                logger.debug(f"Module {module_id} trouvé: {cmd_path} -> {version_line}")
                
                return {
                    'installed': True, 
                    'version': version_line, 
                    'binary': binary,
                    'path': cmd_path,
                    'error': None
                }
                
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout checking {module_id} with {binary}")
                continue
            except Exception as e:
                logger.error(f"Error checking {module_id} with {binary}: {e}")
                # On considère quand même installé si le binaire existe
                return {
                    'installed': True, 
                    'version': 'unknown', 
                    'binary': binary,
                    'path': cmd_path,
                    'error': None
                }
        
        # Aucun binaire trouvé
        primary = module.get('binary', module_id)
        logger.info(f"Module {module_id} non installé (cherché: {binaries})")
        return {
            'installed': False, 
            'error': f"'{primary}' non installé (cherché: {', '.join(binaries)})", 
            'version': None
        }
    
    def install_module(self, module_id):
        """Installe un module manquant"""
        if module_id not in HIGH_RISK_MODULES:
            return {'success': False, 'error': 'Module inconnu'}
        
        module = HIGH_RISK_MODULES[module_id]
        install_cmd = module.get('install_cmd')
        
        if not install_cmd:
            return {'success': False, 'error': 'Pas de commande d\'installation'}
        
        try:
            logger.info(f"Installation de {module_id}...")
            
            # Vérifier si on a les droits sudo pour apt
            cmd = install_cmd.copy()
            if cmd[0] == 'apt-get' and shutil.which('sudo'):
                cmd = ['sudo'] + cmd
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                with self.lock:
                    self.module_status[module_id] = self.check_module_installed(module_id)
                logger.info(f"Module {module_id} installé avec succès")
                return {'success': True, 'output': result.stdout[:500]}
            else:
                logger.error(f"Échec installation {module_id}: {result.stderr}")
                return {'success': False, 'error': result.stderr[:500]}
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout installation'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_module_info(self, module_id):
        """Retourne les informations détaillées d'un module"""
        if module_id not in HIGH_RISK_MODULES:
            return None
        
        module = HIGH_RISK_MODULES[module_id].copy()
        with self.lock:
            status = self.module_status.get(module_id, {'installed': False})
        module.update(status)
        return module
    
    def get_all_modules_status(self):
        """Retourne le statut de tous les modules"""
        result = {}
        for module_id in HIGH_RISK_MODULES:
            result[module_id] = self.get_module_info(module_id)
        return result
    
    def validate_module_options(self, module_id, options):
        """Valide et normalise les options d'un module."""
        if module_id not in HIGH_RISK_MODULES:
            return {'valid': False, 'error': 'Module inconnu'}

        module = HIGH_RISK_MODULES[module_id]
        validated = {}
        errors = []

        for opt_name, opt_config in module.get('options', {}).items():
            # Valeur fournie ou valeur par défaut
            value = options.get(opt_name)
            if value is None or value == '':
                value = opt_config.get('default', '')

            opt_type = opt_config.get('type', 'text')
            optional = opt_config.get('optional', False)

            if opt_type == 'int':
                # Champ optionnel vide → None (pas d'erreur)
                if value in ('', None):
                    if optional:
                        value = None
                    else:
                        errors.append(f"{opt_name}: valeur requise")
                else:
                    try:
                        value = int(value)
                        mn = opt_config.get('min')
                        mx = opt_config.get('max')
                        if mn is not None and value < mn:
                            errors.append(f"{opt_name}: minimum {mn}")
                        if mx is not None and value > mx:
                            errors.append(f"{opt_name}: maximum {mx}")
                    except (ValueError, TypeError):
                        errors.append(f"{opt_name}: doit être un nombre entier")

            elif opt_type == 'bool':
                value = bool(value)

            elif opt_type == 'select':
                # Les options peuvent être des strings OU des {'value':..,'label':..}
                raw_opts = opt_config.get('options', [])
                valid_values = [
                    o['value'] if isinstance(o, dict) else o
                    for o in raw_opts
                ]
                # Accepter aussi la valeur vide si optionnel
                if value not in valid_values and not (optional and value in ('', None)):
                    # Tentative de fallback sur la valeur par défaut
                    default = opt_config.get('default', '')
                    if default in valid_values:
                        value = default
                    elif valid_values:
                        value = valid_values[0]

            elif opt_type == 'file':
                # Ne pas bloquer si le fichier est absent — l'outil gèrera l'erreur
                # On avertit juste dans les logs
                if value and not os.path.exists(str(value)):
                    logger.warning(f"validate_module_options: fichier '{value}' introuvable pour {opt_name}")

            # Pour 'text' et autres types : pas de validation stricte

            validated[opt_name] = value

        if errors:
            return {'valid': False, 'errors': errors}
        return {'valid': True, 'options': validated}
    
    @staticmethod
    def _resolve_target(target, options):
        """Returns (host, port, url, use_ssl) from target string + options dict."""
        import re as _re
        raw = target.strip()
        scheme = None
        m = _re.match(r'^(https?)://(.*)', raw)
        if m:
            scheme, raw = m.group(1), m.group(2)
        host = raw.split('/')[0]
        port_in = None
        if ':' in host:
            parts = host.rsplit(':', 1)
            try:
                port_in = int(parts[1])
                host = parts[0]
            except ValueError:
                pass
        opt_p = options.get('port')
        try:
            port = int(opt_p) if opt_p not in ('', None) else port_in
        except (ValueError, TypeError):
            port = port_in
        use_ssl = bool(options.get('ssl', False)) or scheme == 'https'
        if port in (443, 8443):
            use_ssl = True
        base = f"{host}:{port}" if port else host
        url  = f"https://{base}" if use_ssl else f"http://{base}"
        return host, port, url, use_ssl

    def build_command(self, module_id, target, options):
        """Build the correct CLI command for each tool (respects real CLI options)."""
        if module_id not in HIGH_RISK_MODULES:
            return None
        host, port, url, use_ssl = self._resolve_target(target, options)
        maxtime = int(options.get('maxtime', 180))

        # ── Nikto ─────────────────────────────────────────────────────────
        if module_id == 'nikto':
            # nikto -h HOST [-p PORT] [-ssl] [-Tuning X] -maxtime N -nointeractive -ask no
            cmd = ['nikto', '-h', host, '-maxtime', str(maxtime),
                   '-nointeractive', '-ask', 'no', '-Format', 'txt']
            if port:
                cmd.extend(['-p', str(port)])
            if use_ssl:
                cmd.append('-ssl')
            tuning = str(options.get('tuning', '')).strip()
            if tuning:
                cmd.extend(['-Tuning', tuning])

        # ── WhatWeb ────────────────────────────────────────────────────────
        elif module_id == 'whatweb':
            # WhatWeb 0.5.5 — NO --timeout, --open-timeout, --read-timeout flags
            # Valid: --color=never, -a LEVEL, --max-threads N, --wait N, -v, URL
            aggression = str(options.get('aggression', '3'))
            cmd = ['whatweb', '--color=never', '-a', aggression,
                   '--max-threads', '1', url]
            if options.get('verbose', False):
                cmd.append('-v')

        # ── SQLMap ─────────────────────────────────────────────────────────
        elif module_id == 'sqlmap':
            # sqlmap --timeout = socket timeout (valid), --connection-timeout does NOT exist
            scan_url = url.rstrip('/') + '/'
            cmd = ['sqlmap', '-u', scan_url, '--batch',
                   '--crawl',  str(options.get('crawl', 1)),
                   '--level',  str(options.get('level', 1)),
                   '--risk',   str(options.get('risk', 1)),
                   '--output-dir=/tmp/sqlmap_labsec',
                   '--random-agent',
                   '--timeout', str(min(maxtime, 30)),
                   '--retries', '1']
            if use_ssl:
                cmd.append('--force-ssl')
            if options.get('forms', True):
                cmd.append('--forms')

        # ── Dirb / Gobuster ────────────────────────────────────────────────
        elif module_id == 'dirb':
            wl = str(options.get('wordlist', '/usr/share/dirb/wordlists/common.txt'))
            for alt in [wl,
                        '/usr/share/dirb/wordlists/common.txt',
                        '/usr/share/wordlists/dirb/common.txt']:
                if os.path.exists(alt):
                    wl = alt
                    break
            threads   = int(options.get('threads', 10))
            recursive = bool(options.get('recursive', False))
            exts      = str(options.get('extensions', '')).strip()
            if shutil.which('gobuster'):
                # gobuster does support --timeout
                cmd = ['gobuster', 'dir', '-u', url, '-w', wl,
                       '-t', str(threads), '-q', '--no-error',
                       '--timeout', f'{min(maxtime,10)}s']
                if use_ssl:
                    cmd.append('-k')
                if exts:
                    cmd.extend(['-x', exts])
            else:
                # dirb has no --timeout. Options: URL WL [-S silent] [-r no-recurse] [-X .ext]
                cmd = ['dirb', url, wl, '-S']
                if not recursive:
                    cmd.append('-r')
                if exts:
                    cmd.extend(['-X', '.' + ',.'.join(exts.split(','))])

        # ── Hydra ──────────────────────────────────────────────────────────
        elif module_id == 'hydra':
            service  = str(options.get('service', 'ssh'))
            wl_pass  = str(options.get('wordlist', '/usr/share/wordlists/fasttrack.txt'))
            wl_user  = str(options.get('userlist', '/usr/share/wordlists/metasploit/unix_users.txt'))
            threads  = int(options.get('threads', 4))
            stop_ok  = bool(options.get('stop_on_success', True))
            cmd = ['hydra']
            cmd.extend(['-L', wl_user] if os.path.exists(wl_user) else ['-l', 'admin'])
            cmd.extend(['-P', wl_pass] if os.path.exists(wl_pass) else ['-p', 'password'])
            cmd.extend(['-t', str(threads), '-w', '10', '-e', 'nsr'])
            if stop_ok:
                cmd.append('-f')
            if port and service not in ('http-get', 'http-post-form', 'https-post-form'):
                cmd.extend(['-s', str(port)])
            cmd.append(f'{service}://{host}')

        # ── CrackMapExec / NetExec ─────────────────────────────────────────
        elif module_id == 'crackmapexec':
            protocol = str(options.get('protocol', 'smb'))
            binary   = next((b for b in ('crackmapexec', 'netexec', 'nxc') if shutil.which(b)),
                            'crackmapexec')
            cmd = [binary, protocol, host]
            if port:
                cmd.extend(['-p', str(port)])
            if options.get('shares', True) and protocol == 'smb':
                cmd.append('--shares')
            if options.get('users', True):
                cmd.append('--users')
            if options.get('pass_pol', False) and protocol in ('smb', 'ldap'):
                cmd.append('--pass-pol')

        # ── Impacket ──────────────────────────────────────────────────────
        elif module_id == 'impacket':
            tool      = str(options.get('tool', 'smbclient'))
            smb_port  = str(options.get('port', '445'))
            null_args = ['-no-pass'] if options.get('null_session', True) else []
            
            # Mapping des outils Impacket avec leurs commandes exactes
            maps = {
                'smbclient':   ['impacket-smbclient',  f'//{host}/'] + null_args + ['-port', smb_port],
                'lookupsid':   ['impacket-lookupsid',  f'guest@{host}', '-no-pass', '-port', smb_port],
                'rpcdump':     ['impacket-rpcdump',    '-port', smb_port, host],
                'samrdump':    ['impacket-samrdump',   host],
                'GetADUsers':  ['impacket-GetADUsers', '-all', '-no-pass', '-dc-ip', host, '/'],
                'secretsdump': ['impacket-secretsdump', f'{host}', '-no-pass'],
            }
            
            # Alternatives sans préfixe impacket-
            alt_maps = {
                'smbclient':   ['smbclient.py',  f'//{host}/'] + null_args + ['-port', smb_port],
                'lookupsid':   ['lookupsid.py',  f'guest@{host}', '-no-pass', '-port', smb_port],
                'rpcdump':     ['rpcdump.py',    '-port', smb_port, host],
                'samrdump':    ['samrdump.py',   host],
                'GetADUsers':  ['GetADUsers.py', '-all', '-no-pass', '-dc-ip', host, '/'],
                'secretsdump': ['secretsdump.py', f'{host}', '-no-pass'],
            }
            
            # Chercher le binaire disponible
            cmd = None
            for cmd_list in [maps.get(tool), alt_maps.get(tool)]:
                if not cmd_list:
                    continue
                binary_to_check = cmd_list[0]
                if shutil.which(binary_to_check) or os.path.exists(f"/snap/bin/{binary_to_check}"):
                    cmd = cmd_list
                    break
            
            # Si toujours pas trouvé, utiliser la commande par défaut
            if not cmd:
                cmd = maps.get(tool, maps['smbclient'])

        # ── Hashcat ───────────────────────────────────────────────────────
        elif module_id == 'hashcat':
            hfile = str(options.get('hash_file', '/tmp/hashes.txt'))
            if not os.path.exists(hfile):
                return ['echo', f'Hashcat: fichier "{hfile}" introuvable. Configurer hash_file dans les options.']
            rules = str(options.get('rules', '')).strip()
            cmd   = ['hashcat', '-m', str(options.get('hash_type','0')),
                     hfile, str(options.get('wordlist','/usr/share/wordlists/rockyou.txt')),
                     '--force', '--quiet', '--status']
            if rules and os.path.exists(rules):
                cmd.extend(['-r', rules])

        else:
            cmd = ['echo', f'Module {module_id} non configure']

        logger.debug(f"CMD [{module_id}]: {' '.join(str(x) for x in cmd)}")
        return cmd

    def run_module(self, module_id, target, options, timeout=300):
        """Exécute un module avec capture complète de la sortie et gestion robuste des erreurs."""
        with self.lock:
            installed = self.module_status.get(module_id, {}).get('installed', False)
        
        if not installed:
            return {
                'module': module_id,
                'status': 'not_installed',
                'error': f"Module '{module_id}' non installé. Utiliser le gestionnaire de modules pour l'installer.",
                'output': None,
                'findings': [],
                'duration': 0
            }

        cmd = self.build_command(module_id, target, options)
        if not cmd:
            return {
                'module': module_id,
                'status': 'error',
                'error': 'Commande invalide',
                'findings': [],
                'duration': 0
            }

        # Vérifier que le binaire existe avant de lancer
        binary = cmd[0]
        
        # Vérifier d'abord avec shutil.which
        cmd_path = shutil.which(binary)
        
        # Si pas trouvé, vérifier dans /snap/bin
        if not cmd_path and binary != 'echo':
            snap_path = f"/snap/bin/{binary}"
            if os.path.exists(snap_path):
                cmd_path = snap_path
        
        if not cmd_path and binary != 'echo':
            return {
                'module': module_id,
                'status': 'not_installed',
                'error': f"Binaire '{binary}' introuvable dans PATH. Vérifier l'installation.",
                'output': None,
                'findings': [],
                'duration': 0
            }
        
        # Mettre à jour la commande avec le chemin complet
        if cmd_path and cmd_path != binary:
            cmd[0] = cmd_path

        logger.info(f"Exécution {module_id} sur {target}: {' '.join(str(x) for x in cmd)}")
        start_time = time.time()

        try:
            env = os.environ.copy()
            env['TERM'] = 'dumb'  # Éviter les codes couleur ANSI parasites
            
            # Ajouter /snap/bin au PATH
            current_path = env.get('PATH', '')
            snap_paths = ['/snap/bin', '/var/lib/snapd/snap/bin']
            for snap_path in snap_paths:
                if snap_path not in current_path and os.path.exists(snap_path):
                    env['PATH'] = f"{snap_path}:{current_path}" if current_path else snap_path

            process = subprocess.Popen(
                [str(x) for x in cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
                cwd='/tmp'
            )

            stdout_lines = []
            stderr_lines = []
            process_finished = threading.Event()

            def read_stream(pipe, lines_list):
                try:
                    for line in iter(pipe.readline, ''):
                        lines_list.append(line)
                except Exception:
                    pass
                finally:
                    pipe.close()
                    if pipe == process.stdout:
                        process_finished.set()

            t_out = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines), daemon=True)
            t_err = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines), daemon=True)
            t_out.start()
            t_err.start()

            try:
                # Attendre la fin du processus avec timeout
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                duration = round(time.time() - start_time, 2)
                logger.warning(f"{module_id} timeout après {duration}s")
                return {
                    'module': module_id,
                    'status': 'timeout',
                    'error': f'Timeout après {timeout}s — l\'outil a été arrêté. '
                             f'Augmenter le timeout ou réduire la portée du scan.',
                    'output': ''.join(stdout_lines)[:2000] or None,
                    'findings': [],
                    'duration': duration
                }

            # Attendre que les threads de lecture aient fini
            process_finished.wait(timeout=5)
            t_out.join(timeout=2)
            t_err.join(timeout=2)

            full_output  = ''.join(stdout_lines)
            error_output = ''.join(stderr_lines)
            duration     = round(time.time() - start_time, 2)
            returncode   = process.returncode

            logger.info(f"{module_id} terminé en {duration}s (rc={returncode}), "
                        f"stdout={len(full_output)}b stderr={len(error_output)}b")

            # Certains outils écrivent sur stderr (whatweb, hydra verbose…)
            combined_output = full_output if full_output.strip() else error_output

            # Codes de retour non-fatals par outil (rc != 0 mais pas une erreur réelle)
            NON_FATAL_RC = {
                'nikto':   [0, 1, 2],  # rc=2 = no host/port found, still valid
                'whatweb': [0],
                'dirb':    [0, 1],
                'gobuster':[0, 1],
                'hydra':   [0, 1, 255],
                'sqlmap':  [0, 1],
                'crackmapexec': [0, 1],
                'impacket':[0, 1],
            }
            
            # Détecter les erreurs applicatives réelles (sortie vide + message d'erreur explicite)
            low_combined = combined_output.lower()
            if (not full_output.strip()
                    and returncode not in NON_FATAL_RC.get(module_id, [0, 1, 2])
                    and any(k in low_combined for k in ['error:', 'fatal:', 'exception', 'permission denied'])):
                return {
                    'module': module_id,
                    'status': 'error',
                    'error': (error_output or full_output)[:500],
                    'output': combined_output[:3000],
                    'findings': [],
                    'duration': duration
                }

            findings = self._parse_findings(module_id, full_output, error_output, target)

            return {
                'module': module_id,
                'status': 'completed',
                'output': combined_output[:8000],
                'full_output': full_output,
                'error_output': error_output[:1000] if error_output.strip() else '',
                'findings': findings,
                'returncode': returncode,
                'duration': duration,
                'command': ' '.join(str(x) for x in cmd)
            }

        except FileNotFoundError:
            return {
                'module': module_id,
                'status': 'not_installed',
                'error': f"'{cmd[0]}' introuvable. Installer le module via le gestionnaire.",
                'findings': [],
                'duration': round(time.time() - start_time, 2)
            }
        except PermissionError:
            return {
                'module': module_id,
                'status': 'error',
                'error': f"Permission refusée pour exécuter '{cmd[0]}'. Vérifier les droits (sudo ?).",
                'findings': [],
                'duration': round(time.time() - start_time, 2)
            }
        except Exception as e:
            logger.error(f"run_module {module_id} exception: {e}", exc_info=True)
            return {
                'module': module_id,
                'status': 'error',
                'error': str(e),
                'findings': [],
                'duration': round(time.time() - start_time, 2)
            }
    
    def _parse_findings(self, module_id, stdout, stderr, target=''):
        """Parse les résultats réels de chaque outil pour extraire des findings structurés."""
        findings = []
        combined = stdout + '\n' + stderr
        low = combined.lower()

        # ── Nikto ──────────────────────────────────────────────────────────
        if module_id == 'nikto':
            for line in stdout.split('\n'):
                line = line.rstrip()
                # Les findings Nikto commencent par "+ " ou "- "
                if not (line.startswith('+ ') or line.startswith('- ')):
                    continue
                # Ignorer les lignes d'info générales
                skip_keywords = ['target ip:', 'target hostname:', 'target port:',
                                  'start time:', 'end time:', 'host(s) tested',
                                  'nikto v', 'ssl info', 'no cgi directories found',
                                  '0 error(s)']
                low_line = line.lower()
                if any(k in low_line for k in skip_keywords):
                    continue

                severity = 'info'
                if any(w in low_line for w in ['remote code', 'rce', 'command inject', 'backdoor',
                                                'shell', 'arbitrary code', 'exec(', 'passthru']):
                    severity = 'critical'
                elif any(w in low_line for w in ['sql inject', 'xss', 'cross-site script',
                                                   'file inclus', 'path travers', 'directory travers',
                                                   'unrestricted file upload', 'csrf']):
                    severity = 'high'
                elif any(w in low_line for w in ['outdated', 'vulnerable', 'default file',
                                                   'default password', 'sensitive', 'exposure',
                                                   'information disclosure', 'cleartext', 'cve-',
                                                   'osvdb-', 'insecure', 'weak']):
                    severity = 'medium'

                findings.append({
                    'tool': 'nikto', 'severity': severity,
                    'description': line.strip()[:300],
                    'recommendation': 'Analyser et corriger la configuration du serveur web.'
                })

        # ── SQLMap ──────────────────────────────────────────────────────────
        elif module_id == 'sqlmap':
            for line in stdout.split('\n'):
                low_line = line.lower()
                if 'parameter' in low_line and 'injectable' in low_line:
                    findings.append({
                        'tool': 'sqlmap', 'severity': 'critical',
                        'description': f'Injection SQL confirmée : {line.strip()[:250]}',
                        'recommendation': 'Utiliser des requêtes préparées (prepared statements). Corriger immédiatement.'
                    })
                elif 'sql injection' in low_line and ('found' in low_line or 'identified' in low_line):
                    findings.append({
                        'tool': 'sqlmap', 'severity': 'critical',
                        'description': line.strip()[:250],
                        'recommendation': 'Injection SQL détectée. Utiliser des requêtes paramétrées.'
                    })
                elif 'vulnerable' in low_line and ('injection' in low_line or 'sqli' in low_line):
                    findings.append({
                        'tool': 'sqlmap', 'severity': 'critical',
                        'description': line.strip()[:250],
                        'recommendation': 'Injection SQL confirmée.'
                    })
                elif any(t in low_line for t in ['boolean-based', 'time-based', 'error-based',
                                                    'union query', 'stacked queries']):
                    findings.append({
                        'tool': 'sqlmap', 'severity': 'critical',
                        'description': f'Technique SQLi détectée : {line.strip()[:250]}',
                        'recommendation': 'Corriger les paramètres vulnérables.'
                    })
            # Pas de vuln = info
            if not findings:
                if 'all tested parameters do not appear to be injectable' in low:
                    findings.append({
                        'tool': 'sqlmap', 'severity': 'info',
                        'description': 'Aucune injection SQL détectée sur les paramètres testés.',
                        'recommendation': 'Continuer les bonnes pratiques de développement sécurisé.'
                    })

        # ── Dirb / Gobuster ─────────────────────────────────────────────────
        elif module_id == 'dirb':
            for line in stdout.split('\n'):
                line = line.rstrip()
                # Gobuster format: /path (Status: 200) [Size: 1234]
                m_gob = re.search(r'^(/\S*)\s+\(Status:\s*(\d+)\)', line)
                # Dirb format: + http://host/path (CODE:200|SIZE:1234)
                m_dirb = re.search(r'\+\s+(https?://\S+)\s+\(CODE:(\d+)', line)

                code, path = None, None
                if m_gob:
                    path, code = m_gob.group(1), int(m_gob.group(2))
                elif m_dirb:
                    path, code = m_dirb.group(1), int(m_dirb.group(2))

                if path and code:
                    severity = 'info'
                    desc_pfx = ''
                    sensitive_paths = ['admin', 'administrator', 'backup', 'config', 'database',
                                       'passwd', 'password', 'secret', 'private', 'git', '.env',
                                       'phpinfo', 'phpmyadmin', 'wp-admin', 'manager', 'console',
                                       'actuator', 'api', 'swagger', 'debug', 'test', 'shell']
                    low_path = path.lower()
                    if any(s in low_path for s in sensitive_paths):
                        severity = 'high' if code == 200 else 'medium'
                        desc_pfx = '[SENSIBLE] '
                    elif code == 200:
                        severity = 'medium'
                    elif code in [301, 302, 403]:
                        severity = 'low'

                    findings.append({
                        'tool': 'dirb', 'severity': severity,
                        'description': f'{desc_pfx}Ressource découverte : {path} (HTTP {code})',
                        'recommendation': 'Vérifier si cette ressource doit être accessible. Restreindre si nécessaire.'
                    })

        # ── Hydra ────────────────────────────────────────────────────────────
        elif module_id == 'hydra':
            for line in stdout.split('\n'):
                low_line = line.lower()
                # Hydra success format: [PORT][service] host: X login: Y password: Z
                m = re.search(r'\[(\d+)\]\[(\w[\w-]*)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)', line)
                if m:
                    findings.append({
                        'tool': 'hydra', 'severity': 'critical',
                        'description': (f"Identifiants valides trouvés — "
                                        f"Service: {m.group(2)} Port: {m.group(1)} "
                                        f"Login: {m.group(4)} Password: {m.group(5)}"),
                        'recommendation': 'Changer immédiatement ces identifiants. Appliquer une politique de mot de passe forte et MFA.'
                    })
                elif 'valid password found' in low_line or 'login found' in low_line:
                    findings.append({
                        'tool': 'hydra', 'severity': 'critical',
                        'description': f'Identifiants valides : {line.strip()[:200]}',
                        'recommendation': 'Changer immédiatement ces identifiants.'
                    })
            if not findings:
                if '0 valid password found' in low or 'no valid password' in low:
                    findings.append({
                        'tool': 'hydra', 'severity': 'info',
                        'description': 'Aucun identifiant valide trouvé avec la wordlist testée.',
                        'recommendation': 'Tester avec des wordlists plus complètes. Mettre en place un blocage après N tentatives.'
                    })

        # ── CrackMapExec ──────────────────────────────────────────────────────
        elif module_id == 'crackmapexec':
            for line in stdout.split('\n'):
                low_line = line.lower()
                if 'pwn3d!' in low_line:
                    findings.append({
                        'tool': 'crackmapexec', 'severity': 'critical',
                        'description': f'Compromis (Pwn3d!) : {line.strip()[:200]}',
                        'recommendation': 'Système compromis. Isoler immédiatement et réinitialiser.'
                    })
                elif '(signing:false)' in low_line:
                    findings.append({
                        'tool': 'crackmapexec', 'severity': 'high',
                        'description': 'SMB Signing désactivé — vulnérable aux attaques de type Relay.',
                        'recommendation': 'Activer la signature SMB obligatoire (GPO : Microsoft network server: Digitally sign communications).'
                    })
                elif 'read' in low_line and 'write' in low_line and 'sharename' not in low_line:
                    findings.append({
                        'tool': 'crackmapexec', 'severity': 'high',
                        'description': f'Partage SMB en lecture/écriture : {line.strip()[:200]}',
                        'recommendation': 'Restreindre les permissions des partages SMB.'
                    })
                elif 'read' in low_line and ('share' in low_line or '\\\\' in line):
                    findings.append({
                        'tool': 'crackmapexec', 'severity': 'medium',
                        'description': f'Partage SMB accessible en lecture : {line.strip()[:200]}',
                        'recommendation': 'Vérifier les permissions des partages SMB.'
                    })
                elif re.search(r'\[user\]|\[+\].*user', low_line):
                    findings.append({
                        'tool': 'crackmapexec', 'severity': 'low',
                        'description': f'Utilisateur énuméré : {line.strip()[:200]}',
                        'recommendation': 'Restreindre l\'énumération des comptes AD.'
                    })

        # ── WhatWeb ───────────────────────────────────────────────────────────
        elif module_id == 'whatweb':
            # WhatWeb output: URL StatusCode [Technologies, ...]
            tech_found = []
            for line in stdout.split('\n'):
                line = line.rstrip()
                if not line or line.startswith('#'):
                    continue
                # Ligne principale WhatWeb
                if 'http' in line.lower() and ('[' in line or 'Status' in line):
                    # Extraire les technologies
                    techs_raw = re.findall(r'(\w[\w\-\.]+)\[([^\]]*)\]', line)
                    techs_named = [t[0] for t in techs_raw if len(t[0]) > 2
                                   and t[0] not in ['http', 'https', 'www', 'Status']]

                    # Version parsée
                    versions = re.findall(r'(\w[\w\s\-\.]+)\[([0-9][0-9\.]+[a-zA-Z0-9\-\.]*)\]', line)

                    for name, ver in versions:
                        if len(name) > 2:
                            tech_found.append(f"{name} v{ver}")
                            findings.append({
                                'tool': 'whatweb', 'severity': 'info',
                                'description': f'Technologie identifiée : {name} version {ver}',
                                'recommendation': f'Vérifier que {name} {ver} est à jour. Masquer les informations de version.'
                            })

                    # Technologies sans version
                    for tech in techs_named:
                        if not any(tech in t for t in tech_found):
                            if tech not in ['GET', 'HEAD', 'OK', 'Redirect']:
                                tech_found.append(tech)

                    # Détecter les serveurs/frameworks sensibles
                    low_line = line.lower()
                    if 'apache' in low_line:
                        apache_ver = re.search(r'apache[/\s\[]+([0-9\.]+)', low_line)
                        if apache_ver:
                            findings.append({
                                'tool': 'whatweb', 'severity': 'medium',
                                'description': f'Apache v{apache_ver.group(1)} détecté — vérifier si à jour.',
                                'recommendation': 'Maintenir Apache à jour. Masquer la version avec ServerTokens Prod.'
                            })
                    if 'wordpress' in low_line:
                        wp_ver = re.search(r'wordpress[/\s\[]+([0-9\.]+)', low_line)
                        findings.append({
                            'tool': 'whatweb', 'severity': 'medium',
                            'description': f'WordPress{" v"+wp_ver.group(1) if wp_ver else ""} détecté.',
                            'recommendation': 'Maintenir WordPress et ses plugins à jour. Désactiver xmlrpc.php.'
                        })
                    if 'joomla' in low_line:
                        findings.append({
                            'tool': 'whatweb', 'severity': 'medium',
                            'description': 'CMS Joomla détecté.',
                            'recommendation': 'Maintenir Joomla à jour. Auditer les extensions installées.'
                        })
                    if 'phpmy' in low_line or 'phpmyadmin' in low_line:
                        findings.append({
                            'tool': 'whatweb', 'severity': 'high',
                            'description': 'phpMyAdmin exposé publiquement.',
                            'recommendation': 'Restreindre l\'accès phpMyAdmin aux seules IPs autorisées.'
                        })

                    # Résumé global si aucun finding spécifique
                    if not findings and tech_found:
                        findings.append({
                            'tool': 'whatweb', 'severity': 'info',
                            'description': f'Technologies détectées : {", ".join(tech_found[:15])}',
                            'recommendation': 'Vérifier les versions et appliquer les mises à jour disponibles.'
                        })

            # Erreurs WhatWeb
            for line in (stdout + '\n' + stderr).split('\n'):
                low_line = line.lower()
                if 'error opening' in low_line or 'connection refused' in low_line:
                    findings.append({
                        'tool': 'whatweb', 'severity': 'info',
                        'description': f'Impossible de se connecter : {line.strip()[:200]}',
                        'recommendation': 'Vérifier que le service HTTP/HTTPS est accessible depuis cette machine.'
                    })
                    break

        # ── Impacket ──────────────────────────────────────────────────────────
        elif module_id == 'impacket':
            for line in combined.split('\n'):
                low_line = line.lower()
                if 'anonymous' in low_line and ('success' in low_line or 'login' in low_line):
                    findings.append({
                        'tool': 'impacket', 'severity': 'critical',
                        'description': 'Accès SMB anonyme (null session) accepté.',
                        'recommendation': 'Désactiver les null sessions SMB. Activer la signature SMB.'
                    })
                elif 'sharename' in low_line or ('disk' in low_line and '\\' in line):
                    findings.append({
                        'tool': 'impacket', 'severity': 'medium',
                        'description': f'Partage SMB énuméré : {line.strip()[:200]}',
                        'recommendation': 'Restreindre les partages SMB aux utilisateurs autorisés.'
                    })
                elif 'user' in low_line and 'rid' in low_line:
                    findings.append({
                        'tool': 'impacket', 'severity': 'low',
                        'description': f'Utilisateur SMB énuméré : {line.strip()[:200]}',
                        'recommendation': 'Restreindre l\'énumération des utilisateurs SMB.'
                    })

        return findings
    
    def run_multiple_modules(self, target, modules, options_per_module=None, timeout_per_module=300):
        """Exécute plusieurs modules en parallèle"""
        results = []
        threads = []
        results_lock = threading.Lock()
        
        def run_module_thread(module_id):
            options = {}
            if options_per_module and module_id in options_per_module:
                options = options_per_module[module_id]
            
            result = self.run_module(module_id, target, options, timeout_per_module)
            with results_lock:
                results.append(result)
        
        for module_id in modules:
            if module_id in HIGH_RISK_MODULES:
                thread = threading.Thread(target=run_module_thread, args=(module_id,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
        
        # Attendre que tous les threads finissent
        for thread in threads:
            thread.join(timeout=timeout_per_module + 30)
        
        return results
    
    def start_risk_scan(self, job_id, target, modules, module_options, user):
        """Démarre un scan de modules à risque"""
        with self.lock:
            self.scan_jobs[job_id] = {
                'status': 'running',
                'progress': 0,
                'target': target,
                'modules': modules,
                'timestamp': datetime.now().isoformat(),
                'user': user['username'],
                'user_id': user['user_id']
            }
        
        def run():
            try:
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id]['progress'] = 20
                
                # Vérifier que tous les modules sont installés
                missing_modules = []
                for module_id in modules:
                    with self.lock:
                        status = self.module_status.get(module_id, {})
                    if not status.get('installed'):
                        missing_modules.append(module_id)
                
                if missing_modules:
                    with self.lock:
                        if job_id in self.scan_jobs:
                            self.scan_jobs[job_id].update({
                                'status': 'failed',
                                'error': f"Modules manquants: {', '.join(missing_modules)}"
                            })
                    return
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id]['progress'] = 40
                
                # Exécuter les modules
                results = self.run_multiple_modules(target, modules, module_options)
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id]['progress'] = 90
                
                # Compiler les résultats
                all_findings = []
                for result in results:
                    all_findings.extend(result.get('findings', []))
                
                start_time = datetime.fromisoformat(self.scan_jobs[job_id]['timestamp']).timestamp()
                duration_s = time.time() - start_time

                # Calculer la sévérité globale
                sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                top_sev = 'low'
                for f in all_findings:
                    s = f.get('severity', 'low')
                    if sev_order.get(s, 4) < sev_order.get(top_sev, 4):
                        top_sev = s

                scan_result = {
                    'type': 'risk',
                    'target': target,
                    'timestamp': datetime.now().isoformat(),
                    'duration': f"{duration_s:.1f}s",
                    'modules_executed': len(results),
                    'total_findings': len(all_findings),
                    'module_results': results,
                    'findings': all_findings,
                    # Champs compatibles avec l'affichage nmap pour le rapport PDF
                    'risk_score': sum(10 if f.get('severity')=='critical' else 5 if f.get('severity')=='high' else 2 if f.get('severity')=='medium' else 1 for f in all_findings),
                    'vulnerabilities': top_sev,
                    'open_ports': 0,
                    'services': 0,
                }
                
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id].update({
                            'status': 'completed',
                            'results': scan_result,
                            'progress': 100
                        })
                
                # Sauvegarder en base
                try:
                    from modules.database import save_risk_scan
                    save_risk_scan({
                        'job_id': job_id,
                        'target': target,
                        'modules': modules,
                        'module_options': module_options,
                        'timestamp': datetime.now().isoformat(),
                        'duration': scan_result['duration'],
                        'status': 'completed',
                        'results': scan_result,
                        'user_id': user['user_id'],
                        'username': user['username']
                    })
                except Exception as db_error:
                    logger.error(f"Error saving risk scan to database: {db_error}")
                
            except Exception as e:
                logger.error(f"Risk scan error: {e}")
                with self.lock:
                    if job_id in self.scan_jobs:
                        self.scan_jobs[job_id].update({
                            'status': 'failed',
                            'error': str(e)
                        })
        
        threading.Thread(target=run, daemon=True).start()
        return job_id
    
    def get_scan_status(self, job_id):
        """Récupère le statut d'un scan"""
        with self.lock:
            return self.scan_jobs.get(job_id)
    
    def stop_scan(self, job_id):
        """Arrête un scan en cours"""
        with self.lock:
            if job_id in self.scan_jobs and self.scan_jobs[job_id]['status'] == 'running':
                self.scan_jobs[job_id]['status'] = 'stopped'
                return True
        return False