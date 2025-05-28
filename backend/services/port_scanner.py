# backend/services/port_scanner.py
import nmap
import subprocess
import sys
import socket
import platform
import os
import json
import time
from urllib.parse import urlparse

class PortScanner:
    def __init__(self):
        self.scan_profiles = {
            'intense': {
                'name': 'Intense scan',
                'description': 'Comprehensive scan with OS detection, version detection, script scanning, and traceroute',
                'args': '-T4 -A -v',
                'estimated_time': '5-15 minutes'
            },
            'intense_plus_udp': {
                'name': 'Intense scan plus UDP',
                'description': 'Same as intense but includes top UDP ports',
                'args': '-sS -sU -T4 -A -v',
                'estimated_time': '10-30 minutes'
            },
            'intense_all_tcp': {
                'name': 'Intense scan, all TCP ports',
                'description': 'Scans all 65535 TCP ports with intensive options',
                'args': '-p 1-65535 -T4 -A -v',
                'estimated_time': '20-60 minutes'
            },
            'intense_no_ping': {
                'name': 'Intense scan, no ping',
                'description': 'Intense scan without host discovery (good for firewalled hosts)',
                'args': '-T4 -A -v -Pn',
                'estimated_time': '5-15 minutes'
            },
            'ping_scan': {
                'name': 'Ping scan',
                'description': 'Only discover online hosts, no port scanning',
                'args': '-sn',
                'estimated_time': '10-30 seconds'
            },
            'quick_scan': {
                'name': 'Quick scan',
                'description': 'Scan top 100 ports quickly',
                'args': '-T4 -F',
                'estimated_time': '30-60 seconds'
            },
            'quick_scan_plus': {
                'name': 'Quick scan plus',
                'description': 'Quick scan with service version detection',
                'args': '-sV -T4 -O -F --version-light',
                'estimated_time': '1-3 minutes'
            },
            'quick_traceroute': {
                'name': 'Quick traceroute',
                'description': 'Quick scan with traceroute',
                'args': '-sn --traceroute',
                'estimated_time': '1-2 minutes'
            },
            'regular_scan': {
                'name': 'Regular scan',
                'description': 'Basic port scan of top 1000 ports',
                'args': '',
                'estimated_time': '1-5 minutes'
            },
            'slow_comprehensive': {
                'name': 'Slow comprehensive scan',
                'description': 'Comprehensive scan with stealth and evasion techniques',
                'args': '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"',
                'estimated_time': '30-60 minutes'
            }
        }
        
        self.scan_techniques = {
            'tcp_syn': '-sS',
            'tcp_connect': '-sT', 
            'tcp_ack': '-sA',
            'tcp_window': '-sW',
            'tcp_maimon': '-sM',
            'udp': '-sU',
            'tcp_null': '-sN',
            'tcp_fin': '-sF',
            'tcp_xmas': '-sX',
            'sctp_init': '-sY',
            'sctp_cookie': '-sZ'
        }
        
        self.timing_templates = {
            'paranoid': '-T0',
            'sneaky': '-T1', 
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5'
        }
        
        self.host_discovery = {
            'ping_disable': '-Pn',
            'ping_icmp': '-PE',
            'ping_timestamp': '-PP',
            'ping_netmask': '-PM', 
            'ping_tcp_syn': '-PS',
            'ping_tcp_ack': '-PA',
            'ping_udp': '-PU',
            'ping_sctp': '-PY',
            'arp_ping': '-PR'
        }
        
        self.script_categories = {
            'default': '--script=default',
            'safe': '--script=safe',
            'intrusive': '--script=intrusive',
            'malware': '--script=malware',
            'discovery': '--script=discovery',
            'version': '--script=version',
            'vuln': '--script=vuln',
            'auth': '--script=auth',
            'brute': '--script=brute',
            'exploit': '--script=exploit'
        }
        
        try:
            # Set nmap path untuk Windows
            if platform.system() == 'Windows':
                nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
                if os.path.exists(nmap_path):
                    os.environ['PATH'] = os.environ['PATH'] + os.pathsep + os.path.dirname(nmap_path)
                    nmap.nmap.NMAP_PATH = nmap_path
            
            self.scanner = nmap.PortScanner()
            version_info = self.scanner.nmap_version()
            print(f"Nmap version: {version_info}")
        except nmap.PortScannerError as e:
            print(f"PortScannerError: {e}")
            possible_paths = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe", 
                r"C:\Nmap\nmap.exe"
            ]
            
            nmap_found = False
            for path in possible_paths:
                if os.path.exists(path):
                    print(f"Found nmap at: {path}")
                    nmap.nmap.NMAP_PATH = path
                    nmap_found = True
                    break
            
            if not nmap_found:
                raise Exception("Nmap is not found. Please install from https://nmap.org/download.html")
            
            self.scanner = nmap.PortScanner()
            
        except Exception as e:
            print(f"Error initializing nmap: {e}")
            raise Exception(f"Failed to initialize nmap: {str(e)}")
    
    def get_scan_profiles(self):
        """Return available scan profiles"""
        return self.scan_profiles
    
    def get_scan_options(self):
        """Return all available scan options"""
        return {
            'profiles': self.scan_profiles,
            'techniques': self.scan_techniques,
            'timing': self.timing_templates,
            'host_discovery': self.host_discovery,
            'scripts': self.script_categories
        }
    
    def extract_host_from_url(self, target):
        """Extract hostname or IP from URL"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.hostname
        return target
    
    def build_nmap_arguments(self, scan_options):
        """Build nmap arguments from scan options"""
        arguments = []
        
        # Check if using a predefined profile
        if 'profile' in scan_options and scan_options['profile'] in self.scan_profiles:
            profile = self.scan_profiles[scan_options['profile']]
            return profile['args'].split()
        
        # Custom scan building
        scan_type = scan_options.get('scan_type', 'basic')
        
        # Scan technique
        technique = scan_options.get('technique', 'tcp_connect')
        if technique in self.scan_techniques:
            arguments.append(self.scan_techniques[technique])
        else:
            arguments.append('-sT')  # Default to TCP connect
        
        # Port specification
        port_option = scan_options.get('port_option', 'common')
        if port_option == 'common':
            top_ports = scan_options.get('top_ports', '1000')
            arguments.extend(['--top-ports', top_ports])
        elif port_option == 'range':
            port_range = scan_options.get('port_range', '1-1000')
            arguments.extend(['-p', port_range])
        elif port_option == 'list':
            port_list = scan_options.get('port_list', '80,443')
            arguments.extend(['-p', port_list])
        elif port_option == 'all':
            arguments.extend(['-p', '1-65535'])
        
        # Timing template
        timing = scan_options.get('timing', 'normal')
        if timing in self.timing_templates:
            arguments.append(self.timing_templates[timing])
        
        # Host discovery
        host_disc = scan_options.get('host_discovery', 'ping_disable')
        if host_disc in self.host_discovery:
            arguments.append(self.host_discovery[host_disc])
        
        # Service and OS detection
        if scan_options.get('detect_service', False):
            arguments.append('-sV')
        if scan_options.get('detect_os', False):
            arguments.append('-O')
        if scan_options.get('aggressive', False):
            arguments.append('-A')
        
        # Script scanning
        script_category = scan_options.get('script_category')
        if script_category and script_category in self.script_categories:
            arguments.append(self.script_categories[script_category])
        
        # Custom scripts
        custom_scripts = scan_options.get('custom_scripts')
        if custom_scripts:
            arguments.append(f'--script={custom_scripts}')
        
        # Additional options
        if scan_options.get('traceroute', False):
            arguments.append('--traceroute')
        if scan_options.get('verbose', False):
            arguments.append('-v')
        if scan_options.get('reason', False):
            arguments.append('--reason')
        
        # Output options
        if scan_options.get('no_dns', True):
            arguments.append('-n')
        
        return arguments
    
    def scan(self, target, scan_options=None):
        """Perform port scan with enhanced options"""
        if scan_options is None:
            scan_options = {}
        
        original_target = target
        target = self.extract_host_from_url(target)
        
        print(f"Original target: {original_target}")
        print(f"Extracted host: {target}")
        print(f"Scan options: {scan_options}")
        
        try:
            if not target:
                return {
                    'status': 'error',
                    'message': 'Target cannot be empty'
                }
            
            # Validate target
            try:
                ip_address = socket.gethostbyname(target)
                print(f"Resolved {target} to {ip_address}")
            except socket.gaierror:
                print(f"Cannot resolve hostname: {target}")
                return {
                    'status': 'error',
                    'message': f'Cannot resolve hostname: {target}'
                }
            
            # Build arguments
            arguments = self.build_nmap_arguments(scan_options)
            argument_string = ' '.join(arguments)
            
            print(f"Executing scan with arguments: {argument_string}")
            print(f"Target: {target}")
            
            # Get profile info if used
            profile_info = None
            if 'profile' in scan_options and scan_options['profile'] in self.scan_profiles:
                profile_info = self.scan_profiles[scan_options['profile']]
            
            # Perform scan
            start_time = time.time()
            self.scanner.scan(
                hosts=target,
                arguments=argument_string,
                timeout=300  # 5 minute timeout
            )
            end_time = time.time()
            scan_duration = end_time - start_time
            
            # Process results
            results = []
            all_hosts = self.scanner.all_hosts()
            
            print(f"Scan completed. Hosts found: {all_hosts}")
            
            if not all_hosts:
                results.append({
                    'host': target,
                    'status': 'up (assumed)', 
                    'hostnames': [{'name': target, 'type': 'user'}],
                    'ports': [],
                    'scan_info': {
                        'scan_args': argument_string,
                        'profile_used': profile_info['name'] if profile_info else 'Custom',
                        'note': 'No open ports found in the scanned range or host is down.'
                    }
                })
            else:
                for host in all_hosts:
                    host_result = {
                        'host': host,
                        'status': self.scanner[host].state(),
                        'hostnames': self.scanner[host].get('hostnames', []),
                        'ports': [],
                        'scan_info': {
                            'scan_args': argument_string,
                            'profile_used': profile_info['name'] if profile_info else 'Custom'
                        }
                    }
                    
                    # Port information
                    open_ports = 0
                    closed_ports = 0
                    filtered_ports = 0
                    
                    for proto in self.scanner[host].all_protocols():
                        for port in self.scanner[host][proto].keys():
                            port_info = self.scanner[host][proto][port]
                            state = port_info['state']
                            
                            if state == 'open':
                                open_ports += 1
                            elif state == 'closed':
                                closed_ports += 1
                            elif state == 'filtered':
                                filtered_ports += 1
                            
                            port_data = {
                                'port': port,
                                'protocol': proto,
                                'state': state,
                                'service': port_info.get('name', ''),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'reason': port_info.get('reason', ''),
                                'conf': port_info.get('conf', '')
                            }
                            
                            # Add script results if available
                            if 'script' in port_info:
                                port_data['scripts'] = port_info['script']
                            
                            host_result['ports'].append(port_data)
                    
                    # Summary
                    host_result['summary'] = {
                        'total_ports_scanned': len(host_result['ports']),
                        'open_ports': open_ports,
                        'closed_ports': closed_ports,
                        'filtered_ports': filtered_ports
                    }
                    
                    # OS information
                    if 'osmatch' in self.scanner[host] and self.scanner[host]['osmatch']:
                        host_result['os'] = []
                        for osmatch in self.scanner[host]['osmatch'][:3]:
                            host_result['os'].append({
                                'name': osmatch.get('name', 'Unknown'),
                                'accuracy': osmatch.get('accuracy', '0'),
                                'line': osmatch.get('line', ''),
                                'osclass': osmatch.get('osclass', [])
                            })
                    
                    # Traceroute information
                    if 'trace' in self.scanner[host]:
                        host_result['traceroute'] = {
                            'hops': self.scanner[host]['trace'].get('hops', []),
                            'port': self.scanner[host]['trace'].get('port', ''),
                            'protocol': self.scanner[host]['trace'].get('proto', '')
                        }
                    
                    results.append(host_result)
            
            return {
                'status': 'success',
                'results': results,
                'scan_info': {
                    'command': f"nmap {argument_string} {target}",
                    'elapsed_time': f"{scan_duration:.2f}s",
                    'hosts_up': self.scanner.scanstats().get('uphosts', 0),
                    'hosts_down': self.scanner.scanstats().get('downhosts', 0),
                    'hosts_total': self.scanner.scanstats().get('totalhosts', 0),
                    'profile_used': profile_info['name'] if profile_info else 'Custom',
                    'profile_description': profile_info['description'] if profile_info else 'Custom scan configuration'
                }
            }
            
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                'status': 'error',
                'message': f'Scan failed: {str(e)}'
            }