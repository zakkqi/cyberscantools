# backend/services/subdomain_scanner.py
import socket
import dns.resolver
import requests
import whois
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import re
import json
from datetime import datetime
import time

class SubdomainScanner:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Simplified wordlists
        self.wordlists = {
            'quick': ['www', 'mail', 'ftp', 'api', 'admin', 'blog', 'dev', 'test', 'staging'],
            'standard': self.load_standard_wordlist(),
            'comprehensive': self.load_comprehensive_wordlist()
        }
        
    def load_standard_wordlist(self):
        """Load standard wordlist with commonly found subdomains"""
        return [
            'www', 'mail', 'ftp', 'api', 'admin', 'blog', 'dev', 'test', 'staging',
            'app', 'cdn', 'assets', 'static', 'media', 'images', 'upload', 'download',
            'portal', 'dashboard', 'panel', 'console', 'secure', 'login', 'auth',
            'support', 'help', 'docs', 'wiki', 'news', 'store', 'shop', 'payment',
            'beta', 'alpha', 'demo', 'sandbox', 'vpn', 'remote', 'backup'
        ]
    
    def load_comprehensive_wordlist(self):
        """Load comprehensive wordlist"""
        standard = self.load_standard_wordlist()
        additional = []
        
        # Add numbered variations
        for i in range(1, 6):
            additional.extend([f'www{i}', f'mail{i}', f'api{i}', f'dev{i}', f'test{i}'])
        
        # Add environment prefixes
        envs = ['prod', 'production', 'stage', 'staging', 'dev', 'development', 'test', 'testing']
        services = ['api', 'app', 'web', 'admin', 'portal']
        
        for env in envs:
            for service in services:
                additional.extend([f'{env}-{service}', f'{env}.{service}'])
        
        return list(set(standard + additional))
    
    def scan(self, target, options=None):
        """Main scan function with essential features only"""
        if options is None:
            options = {}
            
        start_time = time.time()
        domain = self.clean_domain(target)
        
        results = {
            'target': domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'summary': {
                'total_found': 0,
                'resolved': 0,
                'unique_ips': 0,
                'scan_duration': 0
            },
            'dns_records': {},
            'whois_info': None
        }
        
        found_subdomains = set()
        
        try:
            # 1. DNS Enumeration (Essential)
            if options.get('dns_enumeration', True):
                wordlist_type = options.get('wordlist', 'standard')
                wordlist = self.wordlists.get(wordlist_type, self.wordlists['standard'])
                
                print(f"Performing DNS enumeration with {len(wordlist)} words...")
                dns_subdomains = self.dns_enumeration(domain, wordlist)
                found_subdomains.update(dns_subdomains)
            
            # 2. Certificate Transparency (Essential)
            if options.get('certificate_transparency', True):
                print("Searching Certificate Transparency logs...")
                ct_subdomains = self.search_certificate_transparency(domain)
                found_subdomains.update(ct_subdomains)
            
            # 3. DNS Records (Important)
            if options.get('dns_records', True):
                print("Querying DNS records...")
                results['dns_records'] = self.get_dns_records(domain)
            
            # 4. WHOIS Info (Optional but useful)
            if options.get('whois_info', False):
                print("Getting WHOIS information...")
                results['whois_info'] = self.get_whois_info(domain)
            
            # Process found subdomains
            print(f"Processing {len(found_subdomains)} potential subdomains...")
            processed_subdomains = []
            unique_ips = set()
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for subdomain in found_subdomains:
                    futures.append(
                        executor.submit(self.process_subdomain, subdomain, options.get('check_http', False))
                    )
                
                for future in futures:
                    subdomain_info = future.result()
                    if subdomain_info:
                        processed_subdomains.append(subdomain_info)
                        if subdomain_info['ip']:
                            unique_ips.add(subdomain_info['ip'])
            
            # Sort and filter results
            processed_subdomains.sort(key=lambda x: x['domain'])
            
            # Filter unresolved if requested
            if not options.get('include_unresolved', True):
                processed_subdomains = [s for s in processed_subdomains if s['resolved']]
            
            results['subdomains'] = processed_subdomains
            results['summary'] = {
                'total_found': len(processed_subdomains),
                'resolved': len([s for s in processed_subdomains if s['resolved']]),
                'unique_ips': len(unique_ips),
                'scan_duration': round(time.time() - start_time, 2)
            }
            
            return {'status': 'success', 'results': results}
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def clean_domain(self, domain):
        """Clean and validate domain"""
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        return domain
    
    def dns_enumeration(self, domain, wordlist):
        """Perform DNS enumeration using wordlist"""
        found_subdomains = set()
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for word in wordlist:
                subdomain = f"{word}.{domain}"
                futures.append(executor.submit(self.check_subdomain, subdomain))
            
            for future in futures:
                result = future.result()
                if result:
                    found_subdomains.add(result)
        
        return found_subdomains
    
    def check_subdomain(self, subdomain):
        """Check if subdomain exists via DNS"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            return None
    
    def search_certificate_transparency(self, domain):
        """Search Certificate Transparency logs"""
        subdomains = set()
        
        try:
            response = requests.get(
                f'https://crt.sh/?q=%.{domain}&output=json', 
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (Compatible Scanner)'}
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip()
                        if name.endswith(domain) and name != domain and not name.startswith('*'):
                            subdomains.add(name)
        except Exception as e:
            print(f"Error querying Certificate Transparency: {e}")
        
        return subdomains
    
    def get_dns_records(self, domain):
        """Get essential DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
        
        return records
    
    def process_subdomain(self, subdomain, check_http=False):
        """Process individual subdomain"""
        result = {
            'domain': subdomain,
            'ip': None,
            'resolved': False,
            'http_status': None,
            'https_status': None
        }
        
        try:
            # Resolve IP
            answers = self.resolver.resolve(subdomain, 'A')
            if answers:
                result['ip'] = str(answers[0])
                result['resolved'] = True
                
                # Optional HTTP check
                if check_http:
                    result['http_status'] = self.check_http_status(subdomain, 'http')
                    result['https_status'] = self.check_http_status(subdomain, 'https')
        except:
            pass
        
        return result
    
    def check_http_status(self, subdomain, protocol):
        """Check HTTP/HTTPS status"""
        try:
            response = requests.get(
                f'{protocol}://{subdomain}', 
                timeout=5, 
                allow_redirects=False,
                verify=False
            )
            return response.status_code
        except:
            return None
    
    def get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': str(w.registrar) if w.registrar else 'Unknown',
                'creation_date': str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) if w.creation_date else 'Unknown',
                'expiration_date': str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) if w.expiration_date else 'Unknown',
                'organization': str(w.org) if w.org else 'Unknown'
            }
        except Exception as e:
            print(f"Error getting WHOIS info: {e}")
            return None