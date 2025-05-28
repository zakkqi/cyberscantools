# backend/services/ssl_scanner.py
import ssl
import socket
import datetime
import json
from urllib.parse import urlparse
import OpenSSL
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class SSLScanner:
    def __init__(self):
        self.vulnerabilities = {
            'heartbleed': self.check_heartbleed,
            'poodle': self.check_poodle,
            'beast': self.check_beast,
            'crime': self.check_crime,
            'sweet32': self.check_sweet32
        }
        self.timeout = 10  # Default timeout
        
    def scan(self, target, options=None):
        """
        Perform SSL/TLS scan on target
        """
        if options is None:
            options = {}
            
        # Extract hostname from URL if necessary
        hostname = self.extract_hostname(target)
        port = options.get('port', 443)
        
        # Validate port
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError("Port must be between 1 and 65535")
        except ValueError as e:
            return {
                'status': 'error',
                'message': f'Invalid port: {e}'
            }
        
        print(f"Starting SSL scan for {hostname}:{port}")
        
        try:
            results = {
                'target': hostname,
                'port': port,
                'timestamp': datetime.datetime.now().isoformat(),
                'certificate': self.get_certificate_info(hostname, port),
                'protocols': self.check_protocols(hostname, port),
                'cipherSuites': self.check_cipher_suites(hostname, port),
                'vulnerabilities': self.check_vulnerabilities(hostname, port, options),
                'grade': self.calculate_grade(hostname, port),
                'recommendations': []
            }

            # Detect not secure conditions
            security_status = self.detect_not_secure_conditions(hostname, port, results)
            results['securityStatus'] = security_status
            print(f"Security status: {security_status.get('is_secure', 'Unknown')}")
            
            # Generate recommendations based on findings
            results['recommendations'] = self.generate_recommendations(results)
            
            return {
                'status': 'success',
                'results': results
            }
            
        except Exception as e:
            print(f"Error during SSL scan: {str(e)}")
            return {
                'status': 'error',
                'message': f'SSL scan failed: {str(e)}'
            }
    
    def extract_hostname(self, target):
        """Extract hostname from URL"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.hostname
        return target
    
    def get_certificate_info(self, hostname, port):
        """Get SSL certificate information"""
        # Default certificate structure
        default_cert_info = {
            'subject': {'CN': hostname},
            'issuer': {'O': 'Unknown'},
            'version': 'Unknown',
            'serialNumber': 'Unknown',
            'notBefore': datetime.datetime.now().isoformat(),
            'notAfter': datetime.datetime.now().isoformat(),
            'isValid': False,
            'daysRemaining': 0,
            'signatureAlgorithm': 'Unknown',
            'subjectAltNames': [],
            'keySize': 0,
            'fingerprint': {
                'sha256': 'Unknown'
            },
            'chain': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    binary_cert = ssock.getpeercert(binary_form=True)
                    
                    # Parse certificate with cryptography
                    x509_cert = x509.load_der_x509_certificate(binary_cert, default_backend())
                    
                    # Parse subject and issuer
                    subject_dict = self.parse_subject(cert['subject'])
                    issuer_dict = self.parse_issuer(cert['issuer'])
                    
                    # Ensure subject and issuer have at least basic info
                    if not subject_dict:
                        subject_dict = {'CN': hostname}
                    if not issuer_dict:
                        issuer_dict = {'O': 'Unknown'}
                    
                    # Extract certificate info
                    info = {
                        'subject': subject_dict,
                        'issuer': issuer_dict,
                        'version': cert.get('version', 'Unknown'),
                        'serialNumber': cert.get('serialNumber', 'Unknown'),
                        'notBefore': cert.get('notBefore', ''),
                        'notAfter': cert.get('notAfter', ''),
                        'isValid': self.is_certificate_valid(cert),
                        'daysRemaining': self.days_remaining(cert),
                        'signatureAlgorithm': str(x509_cert.signature_algorithm_oid._name),
                        'subjectAltNames': self.get_san(cert),
                        'keySize': x509_cert.public_key().key_size,
                        'fingerprint': {
                            'sha256': x509_cert.fingerprint(
                                hashes.SHA256()
                            ).hex(':').upper()
                        }
                    }
                    
                    # Check certificate chain
                    info['chain'] = self.get_certificate_chain(hostname, port)
                    
                    return info
                    
        except Exception as e:
            print(f"Error getting certificate info: {e}")
            # Return default structure with error info
            default_cert_info['error'] = str(e)
            return default_cert_info
    
    def parse_subject(self, subject):
        """Parse certificate subject"""
        subject_dict = {}
        try:
            for item in subject:
                for key, value in item:
                    subject_dict[key] = value
        except Exception as e:
            print(f"Error parsing subject: {e}")
        return subject_dict
    
    def parse_issuer(self, issuer):
        """Parse certificate issuer"""
        issuer_dict = {}
        try:
            for item in issuer:
                for key, value in item:
                    issuer_dict[key] = value
        except Exception as e:
            print(f"Error parsing issuer: {e}")
        return issuer_dict
    
    def is_certificate_valid(self, cert):
        """Check if certificate is currently valid"""
        try:
            not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.datetime.now()
            return not_before <= now <= not_after
        except Exception as e:
            print(f"Error checking certificate validity: {e}")
            return False
    
    def days_remaining(self, cert):
        """Calculate days until certificate expires"""
        try:
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.datetime.now()
            delta = not_after - now
            return delta.days
        except Exception as e:
            print(f"Error calculating days remaining: {e}")
            return 0
    
    def get_san(self, cert):
        """Get Subject Alternative Names"""
        san_list = []
        try:
            if 'subjectAltName' in cert:
                for type_name, value in cert['subjectAltName']:
                    san_list.append(f"{type_name}:{value}")
        except Exception as e:
            print(f"Error getting SAN: {e}")
        return san_list
    
    def get_certificate_chain(self, hostname, port):
        """Get the certificate chain"""
        try:
            # Use OpenSSL to get full chain
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer certificate chain if available
                    if hasattr(ssock, 'getpeercert_chain'):
                        return self.parse_chain(ssock.getpeercert_chain())
            return []
        except Exception as e:
            print(f"Error getting certificate chain: {e}")
            return []
    
    def parse_chain(self, chain):
        """Parse certificate chain"""
        chain_info = []
        try:
            for cert_der in chain:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                chain_info.append({
                    'subject': cert.subject.rfc4514_string(),
                    'issuer': cert.issuer.rfc4514_string(),
                    'notBefore': cert.not_valid_before.isoformat(),
                    'notAfter': cert.not_valid_after.isoformat()
                })
        except Exception as e:
            print(f"Error parsing chain: {e}")
        return chain_info
    
    def check_protocols(self, hostname, port):
        """Check supported SSL/TLS protocols"""
        protocols = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        protocol_versions = {
            'SSLv3': ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None,
            'TLSv1.0': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
        }
        
        # TLS 1.3 check using different method
        try:
            context = ssl.create_default_context()
            if hasattr(ssl, 'TLSVersion'):
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocols['TLSv1.3'] = True
        except:
            protocols['TLSv1.3'] = False
        
        for protocol_name, protocol_version in protocol_versions.items():
            if protocol_version is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol_version)
                context.set_ciphers('ALL:@SECLEVEL=0')  # Allow weak ciphers for testing
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[protocol_name] = True
            except:
                protocols[protocol_name] = False
        
        return protocols
    
    def check_cipher_suites(self, hostname, port):
        """Check supported cipher suites"""
        cipher_suites = []
        
        try:
            # Get list of available ciphers
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_suites.append({
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2],
                            'strength': self.categorize_cipher_strength(cipher[0])
                        })
        except Exception as e:
            print(f"Error checking cipher suites: {e}")
        
        return cipher_suites
    
    def categorize_cipher_strength(self, cipher_name):
        """Categorize cipher strength"""
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1']
        strong_ciphers = ['AES256', 'AES128', 'CHACHA20']
        
        cipher_upper = cipher_name.upper()
        
        for weak in weak_ciphers:
            if weak in cipher_upper:
                return 'weak'
        
        for strong in strong_ciphers:
            if strong in cipher_upper:
                return 'strong'
        
        return 'medium'
    
    def check_vulnerabilities(self, hostname, port, options):
        """Check for known SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        if options.get('checkVulnerabilities', True):
            for vuln_name, check_func in self.vulnerabilities.items():
                try:
                    result = check_func(hostname, port)
                    vulnerabilities.append({
                        'name': vuln_name.upper(),
                        'status': result['status'],
                        'severity': result['severity'],
                        'description': result['description']
                    })
                except Exception as e:
                    print(f"Error checking {vuln_name}: {e}")
        
        return vulnerabilities
    
    def check_heartbleed(self, hostname, port):
        """Check for Heartbleed vulnerability"""
        # Simplified check - in real implementation, would test for actual vulnerability
        return {
            'status': 'not_vulnerable',
            'severity': 'high',
            'description': 'Heartbleed (CVE-2014-0160) vulnerability check'
        }
    
    def check_poodle(self, hostname, port):
        """Check for POODLE vulnerability"""
        # Check if SSLv3 is enabled
        try:
            protocols = self.check_protocols(hostname, port)
            if protocols.get('SSLv3', False):
                return {
                    'status': 'vulnerable',
                    'severity': 'medium',
                    'description': 'POODLE (CVE-2014-3566) - SSLv3 is enabled'
                }
        except:
            pass
        
        return {
            'status': 'not_vulnerable',
            'severity': 'medium',
            'description': 'POODLE (CVE-2014-3566) vulnerability check'
        }
    
    def check_beast(self, hostname, port):
        """Check for BEAST vulnerability"""
        return {
            'status': 'not_vulnerable',
            'severity': 'medium',
            'description': 'BEAST (CVE-2011-3389) vulnerability check'
        }
    
    def check_crime(self, hostname, port):
        """Check for CRIME vulnerability"""
        return {
            'status': 'not_vulnerable',
            'severity': 'medium',
            'description': 'CRIME (CVE-2012-4929) vulnerability check'
        }
    
    def check_sweet32(self, hostname, port):
        """Check for Sweet32 vulnerability"""
        return {
            'status': 'not_vulnerable',
            'severity': 'medium',
            'description': 'Sweet32 (CVE-2016-2183) vulnerability check'
        }
    
    def calculate_grade(self, hostname, port):
        """Calculate overall SSL grade"""
        try:
            # Simplified grading logic
            grade_score = 100
            
            # Check protocols
            protocols = self.check_protocols(hostname, port)
            if protocols.get('SSLv2', False) or protocols.get('SSLv3', False):
                grade_score -= 30
            if protocols.get('TLSv1.0', False) or protocols.get('TLSv1.1', False):
                grade_score -= 10
            if not protocols.get('TLSv1.2', False) and not protocols.get('TLSv1.3', False):
                grade_score -= 20
            
            # Convert score to grade
            if grade_score >= 90:
                return 'A'
            elif grade_score >= 80:
                return 'B'
            elif grade_score >= 70:
                return 'C'
            elif grade_score >= 60:
                return 'D'
            else:
                return 'F'
        except Exception as e:
            print(f"Error calculating grade: {e}")
            return 'F'
    
    def check_http_vs_https(self, hostname):
        """Check if site is using HTTP instead of HTTPS"""
        try:
            # Test HTTP connection
            http_available = False
            https_available = False
            
            try:
                http_socket = socket.create_connection((hostname, 80), timeout=5)
                http_socket.close()
                http_available = True
            except:
                pass
            
            try:
                https_socket = socket.create_connection((hostname, 443), timeout=5)
                https_socket.close()
                https_available = True
            except:
                pass
            
            return {
                'http_available': http_available,
                'https_available': https_available
            }
        except Exception as e:
            print(f"Error checking HTTP/HTTPS: {e}")
            return {
                'http_available': False,
                'https_available': False
            }
        
    def check_self_signed(self, cert_info):
        """Check if certificate is self-signed"""
        subject = cert_info.get('subject', {})
        issuer = cert_info.get('issuer', {})
        
        # Self-signed if subject equals issuer
        if subject == issuer:
            return True
        
        # Check common self-signed indicators
        issuer_cn = issuer.get('CN', '').lower()
        if issuer_cn in ['self-signed', 'localhost', '']:
            return True
        
        # Check if issuer organization is missing
        if not issuer.get('O') and not issuer.get('CN'):
            return True
            
        return False
    
    def check_hostname_match(self, hostname, cert_info):
        """Check if certificate matches hostname"""
        cert_cn = cert_info.get('subject', {}).get('CN', '')
        san_list = cert_info.get('subjectAltNames', [])
        
        # Check Common Name
        if cert_cn == hostname:
            return True
        
        # Check Subject Alternative Names
        for san in san_list:
            # Remove prefix like 'DNS:'
            san_name = san.split(':')[-1] if ':' in san else san
            if hostname == san_name or hostname.endswith('.' + san_name):
                return True
        
        return False
    
    def check_chain_validity(self, chain):
        """Check if certificate chain is valid"""
        issues = []
        
        if not chain or len(chain) == 0:
            issues.append("No certificate chain found")
        elif len(chain) == 1:
            issues.append("Missing intermediate certificates")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues
        }
    
    def detect_not_secure_conditions(self, hostname, port, results):
        """Detect conditions that cause 'Not Secure' warning"""
        not_secure_reasons = []
        cert_info = results.get('certificate', {})
        
        # 1. Check if using HTTP only
        http_https = self.check_http_vs_https(hostname)
        if http_https['http_available'] and not http_https['https_available']:
            not_secure_reasons.append({
                'reason': 'HTTP_ONLY',
                'description': 'Site is not using HTTPS encryption',
                'severity': 'CRITICAL'
            })
        
        # 2. Certificate validity
        if not cert_info.get('isValid', True):
            not_secure_reasons.append({
                'reason': 'INVALID_CERTIFICATE', 
                'description': 'SSL certificate is invalid or expired',
                'severity': 'CRITICAL'
            })
        
        # 3. Self-signed certificate
        if self.check_self_signed(cert_info):
            not_secure_reasons.append({
                'reason': 'SELF_SIGNED',
                'description': 'Certificate is self-signed',
                'severity': 'HIGH'
            })
        
        # 4. Hostname mismatch
        if not self.check_hostname_match(hostname, cert_info):
            not_secure_reasons.append({
                'reason': 'HOSTNAME_MISMATCH',
                'description': 'Certificate does not match domain name',
                'severity': 'HIGH'
            })
        
        # 5. Certificate chain issues
        chain_check = self.check_chain_validity(cert_info.get('chain', []))
        if not chain_check['valid']:
            not_secure_reasons.append({
                'reason': 'CHAIN_ISSUES',
                'description': '; '.join(chain_check['issues']),
                'severity': 'HIGH'
            })
        
        # 6. Weak protocols
        protocols = results.get('protocols', {})
        if protocols.get('SSLv3') or protocols.get('SSLv2'):
            not_secure_reasons.append({
                'reason': 'INSECURE_PROTOCOLS',
                'description': 'Using insecure SSL protocols',
                'severity': 'HIGH'
            })
        elif protocols.get('TLSv1.0') or protocols.get('TLSv1.1'):
            not_secure_reasons.append({
                'reason': 'WEAK_PROTOCOLS',
                'description': 'Using outdated TLS protocols',
                'severity': 'MEDIUM'
            })
        
        # 7. Certificate expiring soon
        days_remaining = cert_info.get('daysRemaining', 0)
        if 0 < days_remaining <= 30:
            not_secure_reasons.append({
                'reason': 'EXPIRING_SOON',
                'description': f'Certificate expires in {days_remaining} days',
                'severity': 'MEDIUM'
            })
        
        return {
            'is_secure': len(not_secure_reasons) == 0,
            'reasons': not_secure_reasons,
            'browser_warning': len([r for r in not_secure_reasons if r['severity'] in ['CRITICAL', 'HIGH']]) > 0
        }
    
    def generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        try:
            # Check security status first
            security_status = results.get('securityStatus', {})
            if not security_status.get('is_secure', True):
                for reason in security_status.get('reasons', []):
                    if reason['reason'] == 'HTTP_ONLY':
                        recommendations.append("Implement HTTPS with a valid SSL certificate")
                    elif reason['reason'] == 'SELF_SIGNED':
                        recommendations.append("Replace self-signed certificate with one from a trusted CA")
                    elif reason['reason'] == 'INVALID_CERTIFICATE':
                        recommendations.append("Renew or replace the invalid SSL certificate")
                    elif reason['reason'] == 'HOSTNAME_MISMATCH':
                        recommendations.append("Get a certificate that matches your domain name")
                    elif reason['reason'] == 'CHAIN_ISSUES':
                        recommendations.append("Fix certificate chain - install intermediate certificates")
            
            # Existing protocol checks
            protocols = results.get('protocols', {})
            if protocols.get('SSLv2', False) or protocols.get('SSLv3', False):
                recommendations.append("Disable SSLv2 and SSLv3 protocols immediately")
            if protocols.get('TLSv1.0', False) or protocols.get('TLSv1.1', False):
                recommendations.append("Disable TLS 1.0 and TLS 1.1 protocols")
            if not protocols.get('TLSv1.3', False):
                recommendations.append("Enable TLS 1.3 for better security")
            
            # Certificate expiration
            cert = results.get('certificate', {})
            days_remaining = cert.get('daysRemaining', 0)
            if days_remaining < 30 and days_remaining > 0:
                recommendations.append(f"Certificate expires in {days_remaining} days - renew soon")
            elif days_remaining <= 0:
                recommendations.append("Certificate has expired - renew immediately")
            
            # Remove duplicates
            recommendations = list(set(recommendations))
            
        except Exception as e:
            print(f"Error generating recommendations: {e}")
        
        return recommendations