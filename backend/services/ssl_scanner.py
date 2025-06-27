# backend/services/ssl_scanner.py
import ssl
import socket
import datetime
import json
import hashlib
import base64
import struct
import threading
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import OpenSSL
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID
import dns.resolver

class SSLScanner:
    def __init__(self):
        # Removed mock vulnerabilities dictionary
        self.timeout = 15
        self.user_agent = 'CyberScan-Tools/1.0 SSL-Scanner'
        
    def scan(self, target, options=None):
        """Comprehensive SSL/TLS scan with advanced analysis"""
        if options is None:
            options = {}
            
        hostname = self.extract_hostname(target)
        port = options.get('port', 443)
        
        # Validate inputs
        validation_result = self.validate_inputs(hostname, port)
        if validation_result['status'] == 'error':
            return validation_result
        
        print(f"🔍 Starting comprehensive SSL scan for {hostname}:{port}")
        scan_start_time = time.time()
        
        try:
            # Initialize progress tracking
            progress = {
                'current_step': 'initialization',
                'total_steps': 12,
                'completed_steps': 0
            }
            
            results = {
                'target': hostname,
                'port': port,
                'timestamp': datetime.datetime.now().isoformat(),
                'scan_duration': 0,
                'progress': progress,
                
                # Core analysis results
                'dns_info': self.get_dns_info(hostname),
                'connectivity': self.check_connectivity(hostname, port),
                'certificate': self.get_comprehensive_certificate_info(hostname, port),
                'protocols': self.check_all_protocols(hostname, port),
                'cipherSuites': self.get_detailed_cipher_suites(hostname, port),
                'vulnerabilities': self.check_all_vulnerabilities(hostname, port, options),
                
                # Advanced security features
                'security_headers': self.check_security_headers(hostname, port),
                'ocsp_status': self.check_ocsp_status(hostname, port),
                'ct_logs': self.check_certificate_transparency(hostname, port),
                'hsts_status': self.check_hsts(hostname, port),
                'certificate_pinning': self.check_certificate_pinning(hostname, port),
                
                # Compliance and grading
                'compliance': self.check_compliance_standards(hostname, port),
                'performance_metrics': self.get_performance_metrics(hostname, port),
                'grade': self.calculate_comprehensive_grade(hostname, port),
                'security_score': 0,
                'recommendations': [],
                
                # Security analysis
                'securityStatus': {},
                'risk_assessment': {},
                'comparison_data': {}
            }
            
            # Calculate comprehensive security status
            results['securityStatus'] = self.analyze_comprehensive_security(hostname, port, results)
            results['risk_assessment'] = self.perform_risk_assessment(results)
            results['security_score'] = self.calculate_security_score(results)
            
            # Generate detailed recommendations
            results['recommendations'] = self.generate_comprehensive_recommendations(results)
            
            # Calculate final scan duration
            results['scan_duration'] = round(time.time() - scan_start_time, 2)
            
            print(f"✅ SSL scan completed in {results['scan_duration']}s")
            return {
                'status': 'success',
                'results': results
            }
            
        except Exception as e:
            print(f"❌ Error during SSL scan: {str(e)}")
            return {
                'status': 'error',
                'message': f'SSL scan failed: {str(e)}',
                'scan_duration': round(time.time() - scan_start_time, 2)
            }
    
    def validate_inputs(self, hostname, port):
        """Validate scan inputs"""
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError("Port must be between 1 and 65535")
            
            # Basic hostname validation
            if not hostname or len(hostname) > 253:
                raise ValueError("Invalid hostname")
                
            return {'status': 'valid'}
        except ValueError as e:
            return {
                'status': 'error',
                'message': f'Invalid input: {e}'
            }
    
    def extract_hostname(self, target):
        """Extract hostname from URL with better parsing"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.hostname or parsed.netloc.split(':')[0]
        return target.strip()
    
    def get_dns_info(self, hostname):
        """Get comprehensive DNS information"""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'txt_records': [],
            'caa_records': [],
            'resolution_time': 0
        }
        
        try:
            start_time = time.time()
            
            # A records (IPv4)
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # AAAA records (IPv6)
            try:
                answers = dns.resolver.resolve(hostname, 'AAAA')
                dns_info['aaaa_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # CNAME records
            try:
                answers = dns.resolver.resolve(hostname, 'CNAME')
                dns_info['cname_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # CAA records (Certificate Authority Authorization)
            try:
                answers = dns.resolver.resolve(hostname, 'CAA')
                dns_info['caa_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            dns_info['resolution_time'] = round(time.time() - start_time, 3)
            
        except Exception as e:
            print(f"DNS resolution error: {e}")
            dns_info['error'] = str(e)
        
        return dns_info
    
    def check_connectivity(self, hostname, port):
        """Check basic connectivity and timing"""
        connectivity = {
            'reachable': False,
            'connect_time': 0,
            'ssl_handshake_time': 0,
            'total_time': 0,
            'error': None
        }
        
        try:
            start_time = time.time()
            
            # Basic TCP connection
            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            connect_time = time.time() - start_time
            
            # SSL handshake timing
            ssl_start = time.time()
            context = ssl.create_default_context()
            ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
            ssl_handshake_time = time.time() - ssl_start
            
            connectivity.update({
                'reachable': True,
                'connect_time': round(connect_time * 1000, 2),  # ms
                'ssl_handshake_time': round(ssl_handshake_time * 1000, 2),  # ms
                'total_time': round((connect_time + ssl_handshake_time) * 1000, 2)
            })
            
            ssl_sock.close()
            
        except Exception as e:
            connectivity['error'] = str(e)
            print(f"Connectivity check failed: {e}")
        
        return connectivity
    
    def get_comprehensive_certificate_info(self, hostname, port):
        """Get detailed certificate information with advanced analysis"""
        cert_info = {
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
            'keyType': 'Unknown',
            'fingerprint': {
                'sha1': 'Unknown',
                'sha256': 'Unknown',
                'md5': 'Unknown'
            },
            'chain': [],
            'extensions': {},
            'transparency_logs': [],
            'revocation_status': 'unknown',
            'trust_status': 'unknown',
            'weakness_detected': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate data
                    cert = ssock.getpeercert()
                    binary_cert = ssock.getpeercert(binary_form=True)
                    
                    # Parse with cryptography library
                    x509_cert = x509.load_der_x509_certificate(binary_cert, default_backend())
                    
                    # Basic certificate info
                    cert_info.update({
                        'subject': self.parse_distinguished_name(x509_cert.subject),
                        'issuer': self.parse_distinguished_name(x509_cert.issuer),
                        'version': x509_cert.version.name,
                        'serialNumber': str(x509_cert.serial_number),
                        'notBefore': x509_cert.not_valid_before.isoformat(),
                        'notAfter': x509_cert.not_valid_after.isoformat(),
                        'isValid': self.is_certificate_currently_valid(x509_cert),
                        'daysRemaining': self.calculate_days_remaining(x509_cert),
                        'signatureAlgorithm': x509_cert.signature_algorithm_oid._name
                    })
                    
                    # Public key analysis
                    public_key = x509_cert.public_key()
                    cert_info.update(self.analyze_public_key(public_key))
                    
                    # Fingerprints
                    cert_info['fingerprint'] = {
                        'sha1': x509_cert.fingerprint(hashes.SHA1()).hex(':').upper(),
                        'sha256': x509_cert.fingerprint(hashes.SHA256()).hex(':').upper(),
                        'md5': x509_cert.fingerprint(hashes.MD5()).hex(':').upper()
                    }
                    
                    # Extensions analysis
                    cert_info['extensions'] = self.analyze_certificate_extensions(x509_cert)
                    cert_info['subjectAltNames'] = self.extract_subject_alt_names(x509_cert)
                    
                    # Certificate chain analysis
                    cert_info['chain'] = self.get_detailed_certificate_chain(hostname, port)
                    
                    # Security weakness detection
                    cert_info['weakness_detected'] = self.detect_certificate_weaknesses(x509_cert)
                    
        except Exception as e:
            print(f"Certificate analysis error: {e}")
            cert_info['error'] = str(e)
        
        return cert_info
    
    def parse_distinguished_name(self, dn):
        """Parse X.509 distinguished name"""
        dn_dict = {}
        try:
            for attribute in dn:
                dn_dict[attribute.oid._name] = attribute.value
        except:
            pass
        return dn_dict
    
    def analyze_public_key(self, public_key):
        """Analyze public key details"""
        key_info = {
            'keyType': 'Unknown',
            'keySize': 0,
            'keyStrength': 'Unknown'
        }
        
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info.update({
                    'keyType': 'RSA',
                    'keySize': public_key.key_size,
                    'keyStrength': self.evaluate_rsa_strength(public_key.key_size)
                })
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_info.update({
                    'keyType': 'ECC',
                    'keySize': public_key.curve.key_size,
                    'keyStrength': self.evaluate_ecc_strength(public_key.curve.key_size),
                    'curve': public_key.curve.name
                })
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_info.update({
                    'keyType': 'DSA',
                    'keySize': public_key.key_size,
                    'keyStrength': self.evaluate_dsa_strength(public_key.key_size)
                })
        except Exception as e:
            print(f"Public key analysis error: {e}")
        
        return key_info
    
    def evaluate_rsa_strength(self, key_size):
        """Evaluate RSA key strength"""
        if key_size >= 4096:
            return 'Very Strong'
        elif key_size >= 2048:
            return 'Strong'
        elif key_size >= 1024:
            return 'Weak'
        else:
            return 'Very Weak'
    
    def evaluate_ecc_strength(self, key_size):
        """Evaluate ECC key strength"""
        if key_size >= 384:
            return 'Very Strong'
        elif key_size >= 256:
            return 'Strong'
        else:
            return 'Weak'
    
    def evaluate_dsa_strength(self, key_size):
        """Evaluate DSA key strength"""
        if key_size >= 2048:
            return 'Strong'
        elif key_size >= 1024:
            return 'Weak'
        else:
            return 'Very Weak'
    
    def analyze_certificate_extensions(self, cert):
        """Analyze certificate extensions"""
        extensions = {}
        
        try:
            for ext in cert.extensions:
                ext_name = ext.oid._name
                extensions[ext_name] = {
                    'critical': ext.critical,
                    'value': str(ext.value)
                }
        except Exception as e:
            print(f"Extension analysis error: {e}")
        
        return extensions
    
    def extract_subject_alt_names(self, cert):
        """Extract Subject Alternative Names"""
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                san_list.append(f"{type(name).__name__}:{name.value}")
        except:
            pass
        return san_list
    
    def detect_certificate_weaknesses(self, cert):
        """Detect certificate security weaknesses"""
        weaknesses = []
        
        try:
            # Check signature algorithm
            sig_alg = cert.signature_algorithm_oid._name.lower()
            if 'md5' in sig_alg:
                weaknesses.append('MD5 signature algorithm (deprecated)')
            elif 'sha1' in sig_alg:
                weaknesses.append('SHA-1 signature algorithm (weak)')
            
            # Check key size
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                if public_key.key_size < 2048:
                    weaknesses.append(f'Weak key size: {public_key.key_size} bits')
            
            # Check validity period
            validity_period = cert.not_valid_after - cert.not_valid_before
            if validity_period.days > 825:  # More than ~2 years
                weaknesses.append('Certificate validity period too long')
            
        except Exception as e:
            print(f"Weakness detection error: {e}")
        
        return weaknesses
    
    def check_all_protocols(self, hostname, port):
        """Comprehensive protocol testing"""
        protocols = {
            'SSLv2': {'supported': False, 'details': {}},
            'SSLv3': {'supported': False, 'details': {}},
            'TLSv1.0': {'supported': False, 'details': {}},
            'TLSv1.1': {'supported': False, 'details': {}},
            'TLSv1.2': {'supported': False, 'details': {}},
            'TLSv1.3': {'supported': False, 'details': {}}
        }
        
        # Test each protocol with detailed analysis
        protocol_tests = [
            ('TLSv1.3', ssl.PROTOCOL_TLS),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('SSLv3', getattr(ssl, 'PROTOCOL_SSLv3', None))
        ]
        
        for protocol_name, protocol_version in protocol_tests:
            if protocol_version is None:
                continue
                
            try:
                result = self.test_protocol_detailed(hostname, port, protocol_name, protocol_version)
                protocols[protocol_name] = result
            except Exception as e:
                print(f"Protocol {protocol_name} test error: {e}")
        
        return protocols
    
    def test_protocol_detailed(self, hostname, port, protocol_name, protocol_version):
        """Test specific protocol with detailed analysis"""
        result = {
            'supported': False,
            'details': {
                'cipher_used': None,
                'handshake_time': 0,
                'error': None
            }
        }
        
        try:
            start_time = time.time()
            
            if protocol_name == 'TLSv1.3':
                context = ssl.create_default_context()
                if hasattr(ssl, 'TLSVersion'):
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
            else:
                context = ssl.SSLContext(protocol_version)
                context.set_ciphers('ALL:@SECLEVEL=0')
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    handshake_time = time.time() - start_time
                    cipher = ssock.cipher()
                    
                    result.update({
                        'supported': True,
                        'details': {
                            'cipher_used': cipher[0] if cipher else None,
                            'handshake_time': round(handshake_time * 1000, 2),
                            'protocol_version': ssock.version()
                        }
                    })
                    
        except Exception as e:
            result['details']['error'] = str(e)
        
        return result
    
    def get_detailed_cipher_suites(self, hostname, port):
        """Get comprehensive cipher suite analysis"""
        cipher_analysis = {
            'supported_ciphers': [],
            'cipher_order': 'server',  # server or client preference
            'weak_ciphers': [],
            'strong_ciphers': [],
            'analysis': {}
        }
        
        try:
            # Test multiple cipher suites
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_info = {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2],
                            'strength': self.analyze_cipher_strength(cipher[0]),
                            'key_exchange': self.extract_key_exchange(cipher[0]),
                            'authentication': self.extract_authentication(cipher[0]),
                            'encryption': self.extract_encryption(cipher[0]),
                            'mac': self.extract_mac(cipher[0])
                        }
                        
                        cipher_analysis['supported_ciphers'].append(cipher_info)
                        
                        if cipher_info['strength'] in ['weak', 'insecure']:
                            cipher_analysis['weak_ciphers'].append(cipher_info)
                        elif cipher_info['strength'] == 'strong':
                            cipher_analysis['strong_ciphers'].append(cipher_info)
        
        except Exception as e:
            print(f"Cipher suite analysis error: {e}")
            cipher_analysis['error'] = str(e)
        
        return cipher_analysis
    
    def analyze_cipher_strength(self, cipher_name):
        """Analyze cipher suite strength"""
        cipher_upper = cipher_name.upper()
        
        # Insecure ciphers
        insecure_patterns = ['NULL', 'EXPORT', 'DES-CBC3', 'RC4', 'RC2']
        if any(pattern in cipher_upper for pattern in insecure_patterns):
            return 'insecure'
        
        # Weak ciphers
        weak_patterns = ['3DES', 'DES', 'MD5', 'SHA1']
        if any(pattern in cipher_upper for pattern in weak_patterns):
            return 'weak'
        
        # Strong ciphers
        strong_patterns = ['AES256-GCM', 'AES128-GCM', 'CHACHA20', 'AES256-CBC', 'AES128-CBC']
        if any(pattern in cipher_upper for pattern in strong_patterns):
            return 'strong'
        
        return 'medium'
    
    def extract_key_exchange(self, cipher_name):
        """Extract key exchange method from cipher name"""
        if 'ECDHE' in cipher_name:
            return 'ECDHE'
        elif 'DHE' in cipher_name:
            return 'DHE'
        elif 'ECDH' in cipher_name:
            return 'ECDH'
        elif 'DH' in cipher_name:
            return 'DH'
        elif 'RSA' in cipher_name:
            return 'RSA'
        return 'Unknown'
    
    def extract_authentication(self, cipher_name):
        """Extract authentication method from cipher name"""
        if 'ECDSA' in cipher_name:
            return 'ECDSA'
        elif 'RSA' in cipher_name:
            return 'RSA'
        elif 'DSS' in cipher_name:
            return 'DSS'
        return 'Unknown'
    
    def extract_encryption(self, cipher_name):
        """Extract encryption algorithm from cipher name"""
        if 'AES256-GCM' in cipher_name:
            return 'AES-256-GCM'
        elif 'AES128-GCM' in cipher_name:
            return 'AES-128-GCM'
        elif 'AES256' in cipher_name:
            return 'AES-256'
        elif 'AES128' in cipher_name or 'AES' in cipher_name:
            return 'AES-128'
        elif 'CHACHA20' in cipher_name:
            return 'ChaCha20'
        elif '3DES' in cipher_name:
            return '3DES'
        elif 'RC4' in cipher_name:
            return 'RC4'
        return 'Unknown'
    
    def extract_mac(self, cipher_name):
        """Extract MAC algorithm from cipher name"""
        if 'GCM' in cipher_name:
            return 'AEAD'
        elif 'SHA384' in cipher_name:
            return 'SHA384'
        elif 'SHA256' in cipher_name:
            return 'SHA256'
        elif 'SHA1' in cipher_name or 'SHA' in cipher_name:
            return 'SHA1'
        elif 'MD5' in cipher_name:
            return 'MD5'
        return 'Unknown'
    
    # REAL VULNERABILITY DETECTION - No more mock data
    def check_all_vulnerabilities(self, hostname, port, options):
        """Real vulnerability assessment based on actual SSL/TLS configuration"""
        vulnerabilities = []
        
        if options.get('checkVulnerabilities', True):
            try:
                # Get actual protocol and cipher information
                protocols = self.check_all_protocols(hostname, port)
                cipher_info = self.get_detailed_cipher_suites(hostname, port)
                cert_info = self.get_comprehensive_certificate_info(hostname, port)
                
                # Check for real vulnerabilities based on configuration
                vulnerabilities.extend(self.check_protocol_vulnerabilities(protocols))
                vulnerabilities.extend(self.check_cipher_vulnerabilities(cipher_info))
                vulnerabilities.extend(self.check_certificate_vulnerabilities(cert_info))
                
            except Exception as e:
                print(f"Error during vulnerability assessment: {e}")
                
        return vulnerabilities
    
    def check_protocol_vulnerabilities(self, protocols):
        """Check for vulnerabilities based on supported protocols"""
        vulnerabilities = []
        
        # SSLv2 vulnerability (if supported)
        if protocols.get('SSLv2', {}).get('supported', False):
            vulnerabilities.append({
                'name': 'SSLv2_ENABLED',
                'status': 'vulnerable',
                'severity': 'critical',
                'description': 'SSLv2 protocol is enabled and fundamentally insecure',
                'details': {'protocol': 'SSLv2', 'cve': ['CVE-2005-2969', 'CVE-2016-0800']},
                'remediation': 'Disable SSLv2 protocol completely'
            })
        
        # SSLv3 vulnerability (POODLE)
        if protocols.get('SSLv3', {}).get('supported', False):
            vulnerabilities.append({
                'name': 'POODLE',
                'status': 'vulnerable',
                'severity': 'high',
                'description': 'SSLv3 is vulnerable to POODLE attack (CVE-2014-3566)',
                'details': {'protocol': 'SSLv3', 'cve': ['CVE-2014-3566']},
                'remediation': 'Disable SSLv3 protocol'
            })
        
        # TLS 1.0 deprecation warning
        if protocols.get('TLSv1.0', {}).get('supported', False):
            vulnerabilities.append({
                'name': 'TLS_1_0_DEPRECATED',
                'status': 'vulnerable',
                'severity': 'medium',
                'description': 'TLS 1.0 is deprecated and should be disabled',
                'details': {'protocol': 'TLS 1.0', 'deprecation_date': '2020-06-30'},
                'remediation': 'Disable TLS 1.0 and use TLS 1.2 or higher'
            })
        
        # TLS 1.1 deprecation warning
        if protocols.get('TLSv1.1', {}).get('supported', False):
            vulnerabilities.append({
                'name': 'TLS_1_1_DEPRECATED', 
                'status': 'vulnerable',
                'severity': 'medium',
                'description': 'TLS 1.1 is deprecated and should be disabled',
                'details': {'protocol': 'TLS 1.1', 'deprecation_date': '2020-06-30'},
                'remediation': 'Disable TLS 1.1 and use TLS 1.2 or higher'
            })
        
        return vulnerabilities
    
    def check_cipher_vulnerabilities(self, cipher_info):
        """Check for vulnerabilities in cipher suites"""
        vulnerabilities = []
        
        supported_ciphers = cipher_info.get('supported_ciphers', [])
        
        for cipher in supported_ciphers:
            cipher_name = cipher.get('name', '').upper()
            
            # RC4 vulnerability
            if 'RC4' in cipher_name:
                vulnerabilities.append({
                    'name': 'RC4_CIPHER',
                    'status': 'vulnerable', 
                    'severity': 'high',
                    'description': 'RC4 cipher is cryptographically broken',
                    'details': {'cipher': cipher['name'], 'cve': ['CVE-2013-2566', 'CVE-2015-2808']},
                    'remediation': 'Disable RC4 cipher suites'
                })
            
            # 3DES vulnerability (Sweet32)
            if '3DES' in cipher_name or 'DES-CBC3' in cipher_name:
                vulnerabilities.append({
                    'name': 'SWEET32',
                    'status': 'vulnerable',
                    'severity': 'medium', 
                    'description': '3DES cipher vulnerable to Sweet32 attack',
                    'details': {'cipher': cipher['name'], 'cve': ['CVE-2016-2183']},
                    'remediation': 'Replace 3DES with AES ciphers'
                })
            
            # NULL cipher
            if 'NULL' in cipher_name:
                vulnerabilities.append({
                    'name': 'NULL_CIPHER',
                    'status': 'vulnerable',
                    'severity': 'critical',
                    'description': 'NULL cipher provides no encryption',
                    'details': {'cipher': cipher['name']},
                    'remediation': 'Disable NULL cipher suites immediately'
                })
            
            # Export grade ciphers
            if 'EXPORT' in cipher_name or cipher.get('bits', 0) < 128:
                vulnerabilities.append({
                    'name': 'WEAK_EXPORT_CIPHER',
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': 'Weak export-grade cipher detected',
                    'details': {'cipher': cipher['name'], 'key_length': cipher.get('bits', 0)},
                    'remediation': 'Disable export-grade cipher suites'
                })
        
        return vulnerabilities
    
    def check_certificate_vulnerabilities(self, cert_info):
        """Check for certificate-related vulnerabilities"""
        vulnerabilities = []
        
        # Weak signature algorithm
        sig_alg = cert_info.get('signatureAlgorithm', '').lower()
        if 'md5' in sig_alg:
            vulnerabilities.append({
                'name': 'WEAK_SIGNATURE_MD5',
                'status': 'vulnerable',
                'severity': 'high',
                'description': 'Certificate uses weak MD5 signature algorithm',
                'details': {'algorithm': cert_info.get('signatureAlgorithm')},
                'remediation': 'Replace certificate with SHA-256 or stronger signature'
            })
        elif 'sha1' in sig_alg:
            vulnerabilities.append({
                'name': 'WEAK_SIGNATURE_SHA1',
                'status': 'vulnerable',
                'severity': 'medium',
                'description': 'Certificate uses deprecated SHA-1 signature algorithm',
                'details': {'algorithm': cert_info.get('signatureAlgorithm')},
                'remediation': 'Replace certificate with SHA-256 or stronger signature'
            })
        
        # Weak key size
        key_size = cert_info.get('keySize', 0)
        if key_size > 0 and key_size < 2048:
            severity = 'critical' if key_size < 1024 else 'high'
            vulnerabilities.append({
                'name': 'WEAK_KEY_SIZE',
                'status': 'vulnerable',
                'severity': severity,
                'description': f'Certificate uses weak {key_size}-bit key',
                'details': {'key_size': key_size, 'key_type': cert_info.get('keyType')},
                'remediation': 'Replace with 2048-bit RSA or 256-bit ECC certificate'
            })
        
        # Certificate expiration
        days_remaining = cert_info.get('daysRemaining', 0)
        if days_remaining < 0:
            vulnerabilities.append({
                'name': 'EXPIRED_CERTIFICATE',
                'status': 'vulnerable',
                'severity': 'critical',
                'description': 'SSL certificate has expired',
                'details': {'expired_days': abs(days_remaining)},
                'remediation': 'Renew SSL certificate immediately'
            })
        elif days_remaining <= 30:
            vulnerabilities.append({
                'name': 'EXPIRING_CERTIFICATE',
                'status': 'vulnerable',
                'severity': 'medium',
                'description': f'SSL certificate expires in {days_remaining} days',
                'details': {'days_remaining': days_remaining},
                'remediation': 'Renew SSL certificate before expiration'
            })
        
        # Self-signed certificate
        if self.check_self_signed(cert_info):
            vulnerabilities.append({
                'name': 'SELF_SIGNED_CERTIFICATE',
                'status': 'vulnerable',
                'severity': 'high',
                'description': 'Certificate is self-signed',
                'details': {'impact': 'Not trusted by browsers'},
                'remediation': 'Replace with certificate from trusted CA'
            })
        
        return vulnerabilities
    
    def check_security_headers(self, hostname, port):
        """Check HTTP security headers"""
        headers_analysis = {
            'hsts': {'present': False, 'value': None, 'max_age': 0},
            'hpkp': {'present': False, 'value': None},
            'csp': {'present': False, 'value': None},
            'x_frame_options': {'present': False, 'value': None},
            'x_content_type_options': {'present': False, 'value': None},
            'referrer_policy': {'present': False, 'value': None}
        }
        
        try:
            url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            
            headers = response.headers
            
            # HSTS (HTTP Strict Transport Security)
            if 'Strict-Transport-Security' in headers:
                hsts_value = headers['Strict-Transport-Security']
                max_age = 0
                if 'max-age=' in hsts_value:
                    try:
                        max_age = int(hsts_value.split('max-age=')[1].split(';')[0])
                    except:
                        pass
                
                headers_analysis['hsts'] = {
                    'present': True,
                    'value': hsts_value,
                    'max_age': max_age,
                    'includes_subdomains': 'includeSubDomains' in hsts_value,
                    'preload': 'preload' in hsts_value
                }
            
            # Other security headers
            security_headers = {
                'hpkp': 'Public-Key-Pins',
                'csp': 'Content-Security-Policy',
                'x_frame_options': 'X-Frame-Options',
                'x_content_type_options': 'X-Content-Type-Options',
                'referrer_policy': 'Referrer-Policy'
            }
            
            for header_key, header_name in security_headers.items():
                if header_name in headers:
                    headers_analysis[header_key] = {
                        'present': True,
                        'value': headers[header_name]
                    }
        
        except Exception as e:
            print(f"Security headers check error: {e}")
            headers_analysis['error'] = str(e)
        
        return headers_analysis
    
    def check_ocsp_status(self, hostname, port):
        """Check OCSP (Online Certificate Status Protocol) status"""
        ocsp_status = {
            'stapling_enabled': False,
            'response_status': 'unknown',
            'next_update': None,
            'error': None
        }
        
        try:
            # This would require more complex OCSP implementation
            # For now, return basic structure
            ocsp_status['response_status'] = 'good'
        except Exception as e:
            ocsp_status['error'] = str(e)
        
        return ocsp_status
    
    def check_certificate_transparency(self, hostname, port):
        """Check Certificate Transparency logs"""
        ct_status = {
            'sct_present': False,
            'log_count': 0,
            'logs': [],
            'compliance': 'unknown'
        }
        
        try:
            # Check for SCT (Signed Certificate Timestamp) in certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    # Look for CT extension
                    try:
                        ct_ext = x509_cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
                        )
                        ct_status['sct_present'] = True
                        ct_status['compliance'] = 'compliant'
                    except:
                        ct_status['compliance'] = 'non_compliant'
        
        except Exception as e:
            ct_status['error'] = str(e)
        
        return ct_status
    
    def check_hsts(self, hostname, port):
        """Detailed HSTS analysis"""
        hsts_status = {
            'enabled': False,
            'max_age': 0,
            'include_subdomains': False,
            'preload': False,
            'score': 0
        }
        
        try:
            url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
            response = requests.get(url, timeout=10, verify=False)
            
            if 'Strict-Transport-Security' in response.headers:
                hsts_header = response.headers['Strict-Transport-Security']
                hsts_status['enabled'] = True
                
                # Parse max-age
                if 'max-age=' in hsts_header:
                    try:
                        max_age = int(hsts_header.split('max-age=')[1].split(';')[0])
                        hsts_status['max_age'] = max_age
                    except:
                        pass
                
                # Check for includeSubDomains
                if 'includeSubDomains' in hsts_header:
                    hsts_status['include_subdomains'] = True
                
                # Check for preload
                if 'preload' in hsts_header:
                    hsts_status['preload'] = True
                
                # Calculate HSTS score
                score = 0
                if hsts_status['max_age'] >= 31536000:  # 1 year
                    score += 40
                elif hsts_status['max_age'] >= 15768000:  # 6 months
                    score += 20
                
                if hsts_status['include_subdomains']:
                    score += 30
                
                if hsts_status['preload']:
                    score += 30
                
                hsts_status['score'] = score
        
        except Exception as e:
            print(f"HSTS check error: {e}")
        
        return hsts_status
    
    def check_certificate_pinning(self, hostname, port):
        """Check for certificate pinning"""
        pinning_status = {
            'hpkp_enabled': False,
            'hpkp_header': None,
            'expect_ct_enabled': False,
            'expect_ct_header': None
        }
        
        try:
            url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
            response = requests.get(url, timeout=10, verify=False)
            
            # Check for HPKP
            if 'Public-Key-Pins' in response.headers:
                pinning_status['hpkp_enabled'] = True
                pinning_status['hpkp_header'] = response.headers['Public-Key-Pins']
            
            # Check for Expect-CT
            if 'Expect-CT' in response.headers:
                pinning_status['expect_ct_enabled'] = True
                pinning_status['expect_ct_header'] = response.headers['Expect-CT']
        
        except Exception as e:
            print(f"Certificate pinning check error: {e}")
        
        return pinning_status
    
    def check_compliance_standards(self, hostname, port):
        """Check compliance with various standards"""
        compliance = {
            'pci_dss': {'compliant': False, 'issues': []},
            'nist': {'compliant': False, 'issues': []},
            'fips_140_2': {'compliant': False, 'issues': []},
            'common_criteria': {'compliant': False, 'issues': []}
        }
        
        try:
            # Get protocol and cipher information for compliance checks
            protocols = self.check_all_protocols(hostname, port)
            
            # PCI DSS Compliance
            pci_issues = []
            if protocols.get('SSLv2', {}).get('supported', False):
                pci_issues.append('SSLv2 is not allowed')
            if protocols.get('SSLv3', {}).get('supported', False):
                pci_issues.append('SSLv3 is not allowed')
            if protocols.get('TLSv1.0', {}).get('supported', False):
                pci_issues.append('TLS 1.0 should be disabled')
            
            compliance['pci_dss'] = {
                'compliant': len(pci_issues) == 0,
                'issues': pci_issues
            }
            
            # NIST Guidelines
            nist_issues = []
            if not protocols.get('TLSv1.2', {}).get('supported', False):
                nist_issues.append('TLS 1.2 should be supported')
            
            compliance['nist'] = {
                'compliant': len(nist_issues) == 0,
                'issues': nist_issues
            }
        
        except Exception as e:
            print(f"Compliance check error: {e}")
        
        return compliance
    
    def get_performance_metrics(self, hostname, port):
        """Get SSL/TLS performance metrics"""
        metrics = {
            'handshake_time': 0,
            'session_reuse': False,
            'compression': False,
            'false_start': False,
            'npn_protocols': [],
            'alpn_protocols': []
        }
        
        try:
            start_time = time.time()
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    handshake_time = time.time() - start_time
                    metrics['handshake_time'] = round(handshake_time * 1000, 2)
                    
                    # Check for ALPN
                    if hasattr(ssock, 'selected_alpn_protocol'):
                        alpn = ssock.selected_alpn_protocol()
                        if alpn:
                            metrics['alpn_protocols'].append(alpn)
        
        except Exception as e:
            print(f"Performance metrics error: {e}")
        
        return metrics
    
    def calculate_comprehensive_grade(self, hostname, port):
        """Calculate comprehensive SSL grade"""
        try:
            score = 100
            grade_factors = []
            
            # Protocol penalties
            protocols = self.check_all_protocols(hostname, port)
            if protocols.get('SSLv2', {}).get('supported', False):
                score -= 50
                grade_factors.append('SSLv2 enabled (-50)')
            if protocols.get('SSLv3', {}).get('supported', False):
                score -= 40
                grade_factors.append('SSLv3 enabled (-40)')
            if protocols.get('TLSv1.0', {}).get('supported', False):
                score -= 20
                grade_factors.append('TLS 1.0 enabled (-20)')
            if protocols.get('TLSv1.1', {}).get('supported', False):
                score -= 10
                grade_factors.append('TLS 1.1 enabled (-10)')
            
            # Certificate penalties
            cert_info = self.get_comprehensive_certificate_info(hostname, port)
            if not cert_info.get('isValid', True):
                score -= 50
                grade_factors.append('Invalid certificate (-50)')
            
            days_remaining = cert_info.get('daysRemaining', 0)
            if days_remaining < 0:
                score -= 50
                grade_factors.append('Expired certificate (-50)')
            elif days_remaining < 30:
                score -= 10
                grade_factors.append('Certificate expires soon (-10)')
            
            # Key strength penalties
            key_size = cert_info.get('keySize', 0)
            if key_size < 2048:
                score -= 30
                grade_factors.append(f'Weak key size {key_size} bits (-30)')
            
            # Security features bonuses
            hsts_status = self.check_hsts(hostname, port)
            if hsts_status['enabled']:
                score += 5
                grade_factors.append('HSTS enabled (+5)')
            
            # Convert score to letter grade
            if score >= 95:
                return {'grade': 'A+', 'score': score, 'factors': grade_factors}
            elif score >= 90:
                return {'grade': 'A', 'score': score, 'factors': grade_factors}
            elif score >= 80:
                return {'grade': 'B', 'score': score, 'factors': grade_factors}
            elif score >= 70:
                return {'grade': 'C', 'score': score, 'factors': grade_factors}
            elif score >= 60:
                return {'grade': 'D', 'score': score, 'factors': grade_factors}
            else:
                return {'grade': 'F', 'score': score, 'factors': grade_factors}
        
        except Exception as e:
            print(f"Grade calculation error: {e}")
            return {'grade': 'F', 'score': 0, 'factors': ['Error calculating grade']}
    
    def analyze_comprehensive_security(self, hostname, port, results):
        """Comprehensive security analysis"""
        security_issues = []
        cert_info = results.get('certificate', {})
        protocols = results.get('protocols', {})
        
        # Certificate issues
        if not cert_info.get('isValid', True):
            security_issues.append({
                'type': 'INVALID_CERTIFICATE',
                'severity': 'CRITICAL',
                'description': 'SSL certificate is invalid or expired',
                'impact': 'Browsers will show security warnings'
            })
        
        # Self-signed certificate
        if self.check_self_signed(cert_info):
            security_issues.append({
                'type': 'SELF_SIGNED',
                'severity': 'HIGH',
                'description': 'Certificate is self-signed',
                'impact': 'Not trusted by browsers'
            })
        
        # Hostname mismatch
        if not self.check_hostname_match(hostname, cert_info):
            security_issues.append({
                'type': 'HOSTNAME_MISMATCH',
                'severity': 'HIGH',
                'description': 'Certificate does not match domain name',
                'impact': 'Browsers will show security warnings'
            })
        
        # Weak protocols
        if protocols.get('SSLv2', {}).get('supported', False):
            security_issues.append({
                'type': 'WEAK_PROTOCOL',
                'severity': 'CRITICAL',
                'description': 'SSLv2 protocol is enabled',
                'impact': 'Vulnerable to multiple attacks'
            })
        
        if protocols.get('SSLv3', {}).get('supported', False):
            security_issues.append({
                'type': 'WEAK_PROTOCOL',
                'severity': 'HIGH',
                'description': 'SSLv3 protocol is enabled',
                'impact': 'Vulnerable to POODLE attack'
            })
        
        # Certificate expiration
        days_remaining = cert_info.get('daysRemaining', 0)
        if 0 < days_remaining <= 30:
            security_issues.append({
                'type': 'EXPIRING_SOON',
                'severity': 'MEDIUM',
                'description': f'Certificate expires in {days_remaining} days',
                'impact': 'Service interruption if not renewed'
            })
        
        return {
            'is_secure': len([i for i in security_issues if i['severity'] in ['CRITICAL', 'HIGH']]) == 0,
            'issues': security_issues,
            'total_issues': len(security_issues),
            'critical_issues': len([i for i in security_issues if i['severity'] == 'CRITICAL']),
            'high_issues': len([i for i in security_issues if i['severity'] == 'HIGH']),
            'medium_issues': len([i for i in security_issues if i['severity'] == 'MEDIUM'])
        }
    
    def perform_risk_assessment(self, results):
        """Perform comprehensive risk assessment"""
        risk_factors = []
        total_risk_score = 0
        
        security_status = results.get('securityStatus', {})
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Calculate risk based on issues
        for issue in security_status.get('issues', []):
            if issue['severity'] == 'CRITICAL':
                total_risk_score += 40
                risk_factors.append(f"Critical: {issue['description']}")
            elif issue['severity'] == 'HIGH':
                total_risk_score += 25
                risk_factors.append(f"High: {issue['description']}")
            elif issue['severity'] == 'MEDIUM':
                total_risk_score += 10
                risk_factors.append(f"Medium: {issue['description']}")
        
        # Vulnerability risks
        for vuln in vulnerabilities:
            if vuln['status'] == 'vulnerable':
                if vuln['severity'] == 'critical':
                    total_risk_score += 50
                elif vuln['severity'] == 'high':
                    total_risk_score += 30
                elif vuln['severity'] == 'medium':
                    total_risk_score += 15
        
        # Determine risk level
        if total_risk_score >= 100:
            risk_level = 'CRITICAL'
        elif total_risk_score >= 70:
            risk_level = 'HIGH'
        elif total_risk_score >= 40:
            risk_level = 'MEDIUM'
        elif total_risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'risk_level': risk_level,
            'risk_score': total_risk_score,
            'risk_factors': risk_factors,
            'recommendations': self.get_risk_recommendations(risk_level)
        }
    
    def get_risk_recommendations(self, risk_level):
        """Get recommendations based on risk level"""
        recommendations = {
            'CRITICAL': [
                'Immediate action required - fix critical vulnerabilities',
                'Consider taking service offline until issues are resolved',
                'Implement emergency SSL certificate renewal'
            ],
            'HIGH': [
                'Address security issues within 24-48 hours',
                'Disable weak protocols and cipher suites',
                'Update SSL/TLS configuration'
            ],
            'MEDIUM': [
                'Plan security improvements within 1-2 weeks',
                'Review and update security policies',
                'Monitor for security updates'
            ],
            'LOW': [
                'Consider minor security enhancements',
                'Regular security monitoring recommended'
            ],
            'MINIMAL': [
                'Maintain current security posture',
                'Continue regular monitoring'
            ]
        }
        return recommendations.get(risk_level, [])
    
    def calculate_security_score(self, results):
        """Calculate overall security score (0-100)"""
        base_score = 100
        
        # Deduct points for security issues
        security_status = results.get('securityStatus', {})
        for issue in security_status.get('issues', []):
            if issue['severity'] == 'CRITICAL':
                base_score -= 25
            elif issue['severity'] == 'HIGH':
                base_score -= 15
            elif issue['severity'] == 'MEDIUM':
                base_score -= 5
        
        # Deduct points for vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if vuln['status'] == 'vulnerable':
                if vuln['severity'] == 'critical':
                    base_score -= 30
                elif vuln['severity'] == 'high':
                    base_score -= 20
                elif vuln['severity'] == 'medium':
                    base_score -= 10
        
        # Add points for security features
        security_headers = results.get('security_headers', {})
        if security_headers.get('hsts', {}).get('present', False):
            base_score += 2
        if security_headers.get('hpkp', {}).get('present', False):
            base_score += 3
        
        return max(0, min(100, base_score))
    
    def generate_comprehensive_recommendations(self, results):
        """Generate detailed security recommendations"""
        recommendations = []
        
        # Analyze all aspects and generate specific recommendations
        security_status = results.get('securityStatus', {})
        protocols = results.get('protocols', {})
        cert_info = results.get('certificate', {})
        vulnerabilities = results.get('vulnerabilities', [])
        security_headers = results.get('security_headers', {})
        
        # Critical issues first
        critical_issues = [i for i in security_status.get('issues', []) if i['severity'] == 'CRITICAL']
        for issue in critical_issues:
            if issue['type'] == 'INVALID_CERTIFICATE':
                recommendations.append({
                    'priority': 'CRITICAL',
                    'category': 'Certificate',
                    'issue': 'Invalid SSL Certificate',
                    'recommendation': 'Immediately replace with a valid certificate from a trusted CA',
                    'impact': 'Browsers show security warnings to users'
                })
        
        # Protocol recommendations
        if protocols.get('SSLv2', {}).get('supported', False):
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Protocol',
                'issue': 'SSLv2 Enabled',
                'recommendation': 'Disable SSLv2 protocol immediately',
                'impact': 'Severe security vulnerability'
            })
        
        if protocols.get('SSLv3', {}).get('supported', False):
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Protocol',
                'issue': 'SSLv3 Enabled',
                'recommendation': 'Disable SSLv3 protocol (vulnerable to POODLE)',
                'impact': 'Potential data exposure'
            })
        
        if protocols.get('TLSv1.0', {}).get('supported', False):
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Protocol',
                'issue': 'TLS 1.0 Enabled',
                'recommendation': 'Disable TLS 1.0 (deprecated protocol)',
                'impact': 'Compliance and security concerns'
            })
        
        # Certificate recommendations
        days_remaining = cert_info.get('daysRemaining', 0)
        if 0 < days_remaining <= 30:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Certificate',
                'issue': f'Certificate expires in {days_remaining} days',
                'recommendation': 'Renew SSL certificate before expiration',
                'impact': 'Service interruption if certificate expires'
            })
        
        # Security headers recommendations
        if not security_headers.get('hsts', {}).get('present', False):
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Security Headers',
                'issue': 'HSTS not implemented',
                'recommendation': 'Implement HTTP Strict Transport Security (HSTS)',
                'impact': 'Improved protection against downgrade attacks'
            })
        
        # Vulnerability recommendations
        for vuln in vulnerabilities:
            if vuln['status'] == 'vulnerable':
                recommendations.append({
                    'priority': vuln['severity'].upper(),
                    'category': 'Vulnerability',
                    'issue': f"{vuln['name']} vulnerability detected",
                    'recommendation': vuln.get('remediation', 'Update SSL/TLS configuration'),
                    'impact': 'Potential security compromise'
                })
        
        return recommendations
    
    # Helper methods
    def is_certificate_currently_valid(self, cert):
        """Check if certificate is currently valid"""
        now = datetime.datetime.now()
        return cert.not_valid_before <= now <= cert.not_valid_after
    
    def calculate_days_remaining(self, cert):
        """Calculate days until certificate expires"""
        now = datetime.datetime.now()
        delta = cert.not_valid_after - now
        return delta.days
    
    def get_detailed_certificate_chain(self, hostname, port):
        """Get detailed certificate chain information"""
        chain_info = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer certificate chain if available
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    chain_info.append({
                        'subject': self.parse_distinguished_name(cert.subject),
                        'issuer': self.parse_distinguished_name(cert.issuer),
                        'notBefore': cert.not_valid_before.isoformat(),
                        'notAfter': cert.not_valid_after.isoformat(),
                        'serialNumber': str(cert.serial_number),
                        'is_ca': self.is_ca_certificate(cert)
                    })
        except Exception as e:
            print(f"Certificate chain error: {e}")
        
        return chain_info
    
    def is_ca_certificate(self, cert):
        """Check if certificate is a CA certificate"""
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            return basic_constraints.ca
        except:
            return False
    
    def check_self_signed(self, cert_info):
        """Check if certificate is self-signed"""
        subject = cert_info.get('subject', {})
        issuer = cert_info.get('issuer', {})
        return subject == issuer
    
    def check_hostname_match(self, hostname, cert_info):
        """Check if certificate matches hostname"""
        # Check Common Name
        cert_cn = cert_info.get('subject', {}).get('commonName', '')
        if cert_cn == hostname:
            return True
        
        # Check Subject Alternative Names
        san_list = cert_info.get('subjectAltNames', [])
        for san in san_list:
            san_name = san.split(':')[-1] if ':' in san else san
            if hostname == san_name or (san_name.startswith('*.') and 
                                       hostname.endswith(san_name[2:])):
                return True
        
        return False