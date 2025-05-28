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

class SubdomainScanner:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
        # Wordlists
        self.wordlists = {
            'small': ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api'],
            'default': self.load_default_wordlist(),
            'large': self.load_large_wordlist()
        }
        
        # External APIs for subdomain discovery
        self.external_apis = {
            'crtsh': 'https://crt.sh/?q=%.{}&output=json',
            'certspotter': 'https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names',
            'threatcrowd': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}'
        }
        
    def load_default_wordlist(self):
        """Load default wordlist - you can load from file"""
        default_words = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'blog', 'dev', 'staging', 'test',
            'portal', 'secure', 'admin', 'login', 'cdn', 'media', 'assets', 'images', 'img',
            'news', 'upload', 'downloads', 'vpn', 'remote', 'cloud', 'git', 'svn', 'hg', 'db',
            'mysql', 'postgres', 'redis', 'elastic', 'search', 'app', 'apps', 'mobile', 'm',
            'help', 'support', 'contact', 'about', 'status', 'stats', 'analytics', 'dashboard'
        ]
        return default_words
    
    def load_large_wordlist(self):
        """Load large wordlist - in real implementation, load from file"""
        # Extend default wordlist
        large_words = self.load_default_wordlist()
        
        # Add variations
        for i in range(1, 10):
            large_words.extend([
                f'www{i}', f'mail{i}', f'ns{i}', f'server{i}', f'node{i}',
                f'api{i}', f'app{i}', f'web{i}', f'dev{i}', f'test{i}'
            ])
        
        # Add common variations
        prefixes = ['dev-', 'test-', 'staging-', 'prod-', 'demo-', 'beta-', 'alpha-']
        base_words = ['app', 'api', 'portal', 'admin', 'console', 'dashboard']
        
        for prefix in prefixes:
            for word in base_words:
                large_words.append(prefix + word)
                
        return list(set(large_words))  # Remove duplicates
    
    def scan(self, target, options=None):
        """Main scan function"""
        if options is None:
            options = {}
            
        print(f"Starting subdomain scan for {target}")
        
        # Clean domain
        domain = self.clean_domain(target)
        
        results = {
            'target': domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'totalFound': 0,
            'resolvedCount': 0,
            'uniqueIPs': set(),
            'technologiesDetected': 0,
            'dnsRecords': {},
            'whoisInfo': None,
            'technologyOverview': {}
        }
        
        found_subdomains = set()
        
        # 1. DNS Enumeration with wordlist
        if options.get('wordlist'):
            wordlist_type = options.get('wordlist', 'default')
            if wordlist_type == 'custom':
                wordlist = options.get('customWordlist', '').split('\n')
            else:
                wordlist = self.wordlists.get(wordlist_type, self.wordlists['default'])
                
            print(f"Performing DNS enumeration with {len(wordlist)} words...")
            dns_subdomains = self.dns_enumeration(domain, wordlist)
            found_subdomains.update(dns_subdomains)
        
        # 2. Certificate Transparency Logs
        if options.get('certificateTransparency', True):
            print("Searching Certificate Transparency logs...")
            ct_subdomains = self.search_certificate_transparency(domain)
            found_subdomains.update(ct_subdomains)
        
        # 3. External APIs
        if options.get('useExternalAPIs', True):
            print("Querying external APIs...")
            api_subdomains = self.query_external_apis(domain)
            found_subdomains.update(api_subdomains)
        
        # 4. Google Search (simulated - in real implementation would use Google API)
        if options.get('searchEngineQueries', True):
            print("Performing search engine queries...")
            search_subdomains = self.search_engines(domain)
            found_subdomains.update(search_subdomains)
        
        # 5. DNS Records interrogation
        if options.get('interrogateDNS', True):
            print("Interrogating DNS records...")
            results['dnsRecords'] = self.interrogate_dns_records(domain)
        
        # 6. Generate permutations
        if options.get('generatePermutations', True):
            print("Generating subdomain permutations...")
            permutations = self.generate_permutations(list(found_subdomains), domain)
            found_subdomains.update(permutations)
        
        # Process found subdomains
        print(f"Processing {len(found_subdomains)} potential subdomains...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for subdomain in found_subdomains:
                futures.append(
                    executor.submit(self.process_subdomain, subdomain, domain, options)
                )
            
            for future in futures:
                subdomain_info = future.result()
                if subdomain_info:
                    results['subdomains'].append(subdomain_info)
                    if subdomain_info['resolved']:
                        results['resolvedCount'] += 1
                        if subdomain_info['ip']:
                            results['uniqueIPs'].add(subdomain_info['ip'])
        
        # WHOIS Information
        if options.get('includeWhois', True):
            print("Getting WHOIS information...")
            results['whoisInfo'] = self.get_whois_info(domain)
        
        # Technology detection
        if options.get('detectTechnologies', True):
            print("Detecting technologies...")
            self.detect_technologies(results)
        
        # Include unresolved subdomains
        if not options.get('includeUnresolved', False):
            results['subdomains'] = [s for s in results['subdomains'] if s['resolved']]
        
        # Final stats
        results['totalFound'] = len(results['subdomains'])
        results['uniqueIPs'] = len(results['uniqueIPs'])
        
        return {
            'status': 'success',
            'results': results
        }
    
    def clean_domain(self, domain):
        """Clean and validate domain"""
        domain = domain.lower().strip()
        if domain.startswith('http://') or domain.startswith('https://'):
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
        """Check if subdomain exists"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            return None
    
    def search_certificate_transparency(self, domain):
        """Search Certificate Transparency logs"""
        subdomains = set()
        
        try:
            # Query crt.sh
            response = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    names = name_value.split('\n')
                    for name in names:
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
        except Exception as e:
            print(f"Error querying crt.sh: {e}")
        
        return subdomains
    
    def query_external_apis(self, domain):
        """Query external APIs for subdomain information"""
        subdomains = set()
        
        # ThreadCrowd API
        try:
            response = requests.get(
                f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('subdomains'):
                    subdomains.update(data['subdomains'])
        except Exception as e:
            print(f"Error querying ThreatCrowd: {e}")
        
        return subdomains
    
    def search_engines(self, domain):
        """Search engines for subdomains (simulated)"""
        # In real implementation, would use search APIs
        # This is a placeholder
        return set()
    
    def interrogate_dns_records(self, domain):
        """Get various DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
        
        return records
    
    def generate_permutations(self, subdomains, domain):
        """Generate permutations of found subdomains"""
        permutations = set()
        
        for subdomain in subdomains:
            parts = subdomain.replace(f'.{domain}', '').split('.')
            if len(parts) > 0:
                base = parts[-1]
                
                # Add number variations
                for i in range(1, 5):
                    permutations.add(f"{base}{i}.{domain}")
                    
                # Add common prefixes
                prefixes = ['dev', 'test', 'stage', 'prod', 'beta']
                for prefix in prefixes:
                    permutations.add(f"{prefix}-{base}.{domain}")
                    permutations.add(f"{prefix}.{base}.{domain}")
        
        return permutations
    
    def process_subdomain(self, subdomain, domain, options):
        """Process individual subdomain"""
        result = {
            'domain': subdomain,
            'ip': None,
            'resolved': False,
            'technologies': [],
            'source': 'DNS'
        }
        
        try:
            # Resolve IP
            answers = self.resolver.resolve(subdomain, 'A')
            if answers:
                result['ip'] = str(answers[0])
                result['resolved'] = True
        except:
            pass
        
        # Detect technologies if enabled and resolved
        if result['resolved'] and options.get('detectTechnologies', True):
            result['technologies'] = self.detect_web_technologies(subdomain)
        
        return result
    
    def detect_web_technologies(self, subdomain):
        """Detect web technologies"""
        technologies = []
        
        try:
            response = requests.get(f'http://{subdomain}', timeout=5)
            headers = response.headers
            
            # Server detection
            if 'Server' in headers:
                technologies.append(headers['Server'])
            
            # X-Powered-By
            if 'X-Powered-By' in headers:
                technologies.append(headers['X-Powered-By'])
            
            # Check response content for technology indicators
            content = response.text.lower()
            
            # Common technology indicators
            tech_indicators = {
                'WordPress': ['wp-content', 'wp-includes'],
                'jQuery': ['jquery.min.js', 'jquery-'],
                'Bootstrap': ['bootstrap.min.css', 'bootstrap.min.js'],
                'Angular': ['ng-app', 'angular.min.js'],
                'React': ['react.min.js', 'react-dom.min.js'],
                'Vue.js': ['vue.min.js', 'v-for=', 'v-if=']
            }
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator in content:
                        technologies.append(tech)
                        break
        except:
            pass
        
        return list(set(technologies))
    
    def get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'Registrar': w.registrar,
                'Created': str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
                'Expires': str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
                'Updated': str(w.updated_date[0]) if isinstance(w.updated_date, list) else str(w.updated_date),
                'Organization': w.org
            }
        except Exception as e:
            print(f"Error getting WHOIS info: {e}")
            return None
    
    def detect_technologies(self, results):
        """Aggregate technology detection results"""
        tech_count = {}
        
        for subdomain in results['subdomains']:
            for tech in subdomain.get('technologies', []):
                if tech not in tech_count:
                    tech_count[tech] = 0
                tech_count[tech] += 1
        
        results['technologiesDetected'] = len(tech_count)
        
        # Categorize technologies
        categories = {
            'Web Servers': ['Apache', 'Nginx', 'IIS', 'LiteSpeed'],
            'Languages': ['PHP', 'ASP.NET', 'Python', 'Ruby'],
            'Frameworks': ['WordPress', 'Laravel', 'Django', 'Express'],
            'Frontend': ['jQuery', 'Bootstrap', 'React', 'Vue.js', 'Angular']
        }
        
        tech_overview = {}
        for category, techs in categories.items():
            items = []
            for tech in techs:
                if tech in tech_count:
                    items.append({'name': tech, 'count': tech_count[tech]})
            if items:
                tech_overview[category] = items
        
        results['technologyOverview'] = tech_overview