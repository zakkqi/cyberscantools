# backend/services/poisoning_scanner.py
import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urlparse, quote
from fake_useragent import UserAgent
import hashlib

class PoisoningScanner:
    def __init__(self):
        self.gambling_keywords = [
            'slot', 'judi', 'togel', 'casino', 'poker', 'jackpot', 'gacor',
            'maxwin', 'scatter', 'bonus', 'deposit', 'withdraw', 'bandar',
            'agen', 'situs', 'daftar', 'link', 'rtp'
        ]
        
        self.drug_keywords = [
            'viagra', 'cialis', 'obat kuat', 'obat aborsi', 'cytotec',
            'obat pelangsing', 'tanpa resep', 'apotek online'
        ]
        
        self.googlebot_ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        self.normal_ua = UserAgent().chrome
        
    def scan(self, target, options=None):
        if options is None:
            options = {}
            
        print(f"Starting SEO poisoning scan for {target}")
        
        # Clean domain
        domain = self.clean_domain(target)
        
        results = {
            'target': domain,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'poisoning_detected': False,
            'risk_level': 'Low',
            'cloaking_detected': False,
            'serp_manipulation': [],
            'compromised_pages': [],
            'suspicious_content': [],
            'blacklist_status': [],
            'recommendations': []
        }
        
        # 1. Check SERP manipulation
        if options.get('checkSERP', True):
            print("Checking search engine results...")
            results['serp_manipulation'] = self.check_serp_manipulation(domain)
        
        # 2. Check for cloaking
        if options.get('checkSERP', True):  # Using checkSERP option
            print("Checking for cloaking...")
            cloaking_results = self.detect_cloaking(domain)
            results['cloaking_detected'] = cloaking_results['detected']
            results['cloaking_details'] = cloaking_results.get('details', [])
        
        # 3. Scan for malicious content
        if options.get('checkMaliciousSEO', True):
            print("Scanning for malicious SEO content...")
            results['suspicious_content'] = self.scan_malicious_content(domain)
        
        # 4. Check blacklist status
        if options.get('checkBlacklist', True):
            print("Checking blacklist status...")
            results['blacklist_status'] = self.check_blacklist_status(domain)
        
        # 5. Check for phishing
        if options.get('checkPhishing', True):
            print("Checking for phishing indicators...")
            results['phishing_indicators'] = self.check_phishing_indicators(domain)
        
        # 6. Check redirects
        if options.get('checkRedirects', True):
            print("Checking for malicious redirects...")
            results['redirect_analysis'] = self.analyze_redirects(domain)
        
        # Calculate risk level
        results['risk_level'] = self.calculate_risk_level(results)
        
        # Generate recommendations
        results['recommendations'] = self.generate_recommendations(results)
        
        # Set overall detection status
        if results['risk_level'] in ['High', 'Critical']:
            results['poisoning_detected'] = True
        
        return {
            'status': 'success',
            'results': results
        }
    
    def clean_domain(self, domain):
        """Clean and normalize domain"""
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
        return domain
    
    def check_serp_manipulation(self, domain):
        """Check for SERP manipulation using search queries"""
        manipulations = []
        
        # Google search queries to check
        search_queries = [
            f'site:{domain} slot',
            f'site:{domain} judi online',
            f'site:{domain} casino',
            f'site:{domain} togel',
            f'site:{domain} poker'
        ]
        
        for query in search_queries:
            try:
                # Simulate Google search (in production, use Google Custom Search API)
                google_url = f"https://www.google.com/search?q={quote(query)}"
                
                headers = {
                    'User-Agent': self.normal_ua,
                    'Accept-Language': 'en-US,en;q=0.9'
                }
                
                response = requests.get(google_url, headers=headers, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract search results
                results = soup.find_all('div', class_='g')
                
                for result in results[:5]:  # Check first 5 results
                    title_elem = result.find('h3')
                    snippet_elem = result.find('span', class_='st') or result.find('div', class_='VwiC3b')
                    
                    if title_elem and snippet_elem:
                        title = title_elem.get_text()
                        snippet = snippet_elem.get_text()
                        
                        # Check for gambling keywords in SERP
                        if self.contains_suspicious_keywords(title + ' ' + snippet):
                            # Get the actual URL
                            link_elem = result.find('a')
                            if link_elem and 'href' in link_elem.attrs:
                                url = link_elem['href']
                                
                                # Check if actual page has gambling content
                                actual_content = self.check_actual_page(url)
                                
                                if not actual_content['has_gambling']:
                                    manipulations.append({
                                        'query': query,
                                        'url': url,
                                        'serp_title': title,
                                        'serp_snippet': snippet,
                                        'manipulation_type': 'SERP poisoning',
                                        'severity': 'High'
                                    })
                
                time.sleep(2)  # Respect rate limits
                
            except Exception as e:
                print(f"Error checking SERP for query '{query}': {e}")
        
        return manipulations
    
    def detect_cloaking(self, domain):
        """Detect cloaking by comparing different user agents"""
        result = {
            'detected': False,
            'details': []
        }
        
        test_paths = ['/', '/index.php', '/index.html']
        
        for path in test_paths:
            url = f'https://{domain}{path}'
            
            try:
                # Request as Googlebot
                googlebot_response = requests.get(
                    url,
                    headers={'User-Agent': self.googlebot_ua},
                    timeout=10,
                    allow_redirects=True
                )
                googlebot_content = googlebot_response.text
                googlebot_hash = hashlib.md5(googlebot_content.encode()).hexdigest()
                
                # Request as normal user
                normal_response = requests.get(
                    url,
                    headers={'User-Agent': self.normal_ua},
                    timeout=10,
                    allow_redirects=True
                )
                normal_content = normal_response.text
                normal_hash = hashlib.md5(normal_content.encode()).hexdigest()
                
                # Check for differences
                if googlebot_hash != normal_hash:
                    # Analyze the differences
                    googlebot_suspicious = self.contains_suspicious_keywords(googlebot_content)
                    normal_suspicious = self.contains_suspicious_keywords(normal_content)
                    
                    if googlebot_suspicious and not normal_suspicious:
                        result['detected'] = True
                        result['details'].append({
                            'path': path,
                            'googlebot_content_suspicious': True,
                            'normal_content_suspicious': False,
                            'content_hash_different': True,
                            'severity': 'Critical'
                        })
                
            except Exception as e:
                print(f"Error checking cloaking for {url}: {e}")
        
        return result
    
    def scan_malicious_content(self, domain):
        """Scan for malicious SEO content"""
        suspicious_findings = []
        
        # Common paths that get compromised
        paths_to_check = [
            '/',
            '/wp-content/uploads/',
            '/images/',
            '/assets/',
            '/media/',
            '/files/',
            '/download/',
            '/.well-known/'
        ]
        
        for path in paths_to_check:
            url = f'https://{domain}{path}'
            
            try:
                response = requests.get(url, headers={'User-Agent': self.normal_ua}, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Check for hidden text
                    hidden_elements = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden'))
                    
                    for element in hidden_elements:
                        if self.contains_suspicious_keywords(element.get_text()):
                            suspicious_findings.append({
                                'type': 'hidden_content',
                                'path': path,
                                'content': element.get_text()[:100],
                                'severity': 'High'
                            })
                    
                    # Check for suspicious meta tags
                    meta_tags = soup.find_all('meta')
                    for meta in meta_tags:
                        content_attr = meta.get('content', '')
                        if self.contains_suspicious_keywords(content_attr):
                            suspicious_findings.append({
                                'type': 'suspicious_meta',
                                'path': path,
                                'content': content_attr,
                                'severity': 'Medium'
                            })
                    
                    # Check for obfuscated JavaScript
                    scripts = soup.find_all('script')
                    for script in scripts:
                        script_content = script.get_text()
                        if self.is_obfuscated_javascript(script_content):
                            suspicious_findings.append({
                                'type': 'obfuscated_javascript',
                                'path': path,
                                'content': script_content[:100],
                                'severity': 'High'
                            })
                    
            except Exception as e:
                print(f"Error scanning {url}: {e}")
        
        return suspicious_findings
    
    def check_blacklist_status(self, domain):
        """Check if domain is blacklisted"""
        blacklist_results = []
        
        # Google Safe Browsing (simplified - in production use API)
        safe_browsing_url = f"https://transparencyreport.google.com/safe-browsing/search?url={domain}"
        
        try:
            # This is a simplified check
            blacklist_results.append({
                'service': 'Google Safe Browsing',
                'status': 'Check manually',
                'url': safe_browsing_url
            })
        except Exception as e:
            print(f"Error checking blacklist: {e}")
        
        return blacklist_results
    
    def check_phishing_indicators(self, domain):
        """Check for phishing indicators"""
        indicators = []
        
        try:
            response = requests.get(f'https://{domain}', headers={'User-Agent': self.normal_ua}, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for fake login forms
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                password_inputs = [inp for inp in inputs if inp.get('type') == 'password']
                
                if password_inputs:
                    action = form.get('action', '')
                    # Check if form submits to external domain
                    if action and not domain in action:
                        indicators.append({
                            'type': 'suspicious_form',
                            'action': action,
                            'severity': 'High'
                        })
            
            # Check for suspicious iframes
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                src = iframe.get('src', '')
                if src and self.is_suspicious_url(src):
                    indicators.append({
                        'type': 'suspicious_iframe',
                        'src': src,
                        'severity': 'Medium'
                    })
            
        except Exception as e:
            print(f"Error checking phishing indicators: {e}")
        
        return indicators
    
    def analyze_redirects(self, domain):
        """Analyze redirect chains"""
        redirect_info = {
            'has_redirects': False,
            'chain': [],
            'suspicious': False
        }
        
        try:
            response = requests.get(
                f'https://{domain}',
                headers={'User-Agent': self.normal_ua},
                timeout=10,
                allow_redirects=False
            )
            
            redirect_count = 0
            current_url = f'https://{domain}'
            
            while response.status_code in [301, 302, 303, 307, 308] and redirect_count < 10:
                redirect_count += 1
                location = response.headers.get('Location', '')
                
                redirect_info['chain'].append({
                    'from': current_url,
                    'to': location,
                    'status': response.status_code
                })
                
                if self.is_suspicious_url(location):
                    redirect_info['suspicious'] = True
                
                current_url = location
                response = requests.get(
                    location,
                    headers={'User-Agent': self.normal_ua},
                    timeout=10,
                    allow_redirects=False
                )
            
            redirect_info['has_redirects'] = redirect_count > 0
            
        except Exception as e:
            print(f"Error analyzing redirects: {e}")
        
        return redirect_info
    
    def contains_suspicious_keywords(self, text):
        """Check if text contains suspicious keywords"""
        if not text:
            return False
            
        text_lower = text.lower()
        
        # Check gambling keywords
        for keyword in self.gambling_keywords:
            if keyword in text_lower:
                return True
        
        # Check drug keywords
        for keyword in self.drug_keywords:
            if keyword in text_lower:
                return True
        
        return False
    
    def check_actual_page(self, url):
        """Check actual page content"""
        result = {
            'has_gambling': False,
            'has_drugs': False,
            'error': None
        }
        
        try:
            response = requests.get(url, headers={'User-Agent': self.normal_ua}, timeout=10)
            content = response.text
            
            result['has_gambling'] = self.contains_suspicious_keywords(content)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def is_obfuscated_javascript(self, script_content):
        """Check if JavaScript is obfuscated"""
        if not script_content:
            return False
        
        # Common obfuscation patterns
        patterns = [
            r'eval\s*\(',
            r'unescape\s*\(',
            r'String\.fromCharCode',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'[a-zA-Z]{1,2}=[a-zA-Z]{1,2}\[[a-zA-Z]{1,2}\]'
        ]
        
        for pattern in patterns:
            if re.search(pattern, script_content):
                return True
        
        # Check for high entropy (random-looking strings)
        if len(script_content) > 100:
            unique_chars = len(set(script_content))
            if unique_chars / len(script_content) > 0.7:
                return True
        
        return False
    
    def is_suspicious_url(self, url):
        """Check if URL is suspicious"""
        suspicious_patterns = [
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Free TLDs
            r'bit\.ly', r'tinyurl',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[^\s]*slot[^\s]*', r'[^\s]*judi[^\s]*'  # Gambling domains
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def calculate_risk_level(self, results):
        """Calculate overall risk level"""
        score = 0
        
        # SERP manipulation is critical
        if results.get('serp_manipulation'):
            score += 40
        
        # Cloaking is very serious
        if results.get('cloaking_detected'):
            score += 50
        
        # Suspicious content
        if results.get('suspicious_content'):
            score += 20 * len(results['suspicious_content'])
        
        # Phishing indicators
        if results.get('phishing_indicators'):
            score += 30
        
        # Suspicious redirects
        redirect_info = results.get('redirect_analysis', {})
        if redirect_info.get('suspicious'):
            score += 25
        
        if score >= 80:
            return 'Critical'
        elif score >= 50:
            return 'High'
        elif score >= 30:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_recommendations(self, results):
        """Generate recommendations based on findings"""
        recommendations = []
        
        if results.get('serp_manipulation'):
            recommendations.append("CRITICAL: Your site appears in search results with gambling/illegal content. Submit reconsideration request to Google immediately.")
            recommendations.append("Check Google Search Console for manual actions or security issues.")
            recommendations.append("Scan your website files for unauthorized modifications.")
        
        if results.get('cloaking_detected'):
            recommendations.append("CRITICAL: Cloaking detected. Your server is showing different content to search engines vs users.")
            recommendations.append("Check .htaccess file for malicious rules.")
            recommendations.append("Review server configuration for user-agent based redirects.")
        
        if results.get('suspicious_content'):
            recommendations.append("Remove all hidden content and suspicious JavaScript from your pages.")
            recommendations.append("Update all CMS plugins and themes to latest versions.")
            recommendations.append("Change all admin passwords and check for unauthorized users.")
        
        if results.get('phishing_indicators'):
            recommendations.append("Remove suspicious forms and iframes from your website.")
            recommendations.append("Ensure all forms submit to your own domain.")
        
        redirect_info = results.get('redirect_analysis', {})
        if redirect_info.get('suspicious'):
            recommendations.append("Review and clean up redirect chains.")
            recommendations.append("Remove any redirects to suspicious domains.")
        
        if not recommendations:
            recommendations.append("No immediate threats detected. Continue monitoring your site regularly.")
        
        return recommendations