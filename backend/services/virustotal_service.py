# backend/services/virustotal_service.py
import requests
import json
import os
import time
import hashlib
import re
import base64
from flask import jsonify

# API key dari VirusTotal
API_KEY = "1c10f9758e940d1a6820c53ca7840620e7a6d91a55344312db9cb2b52da78c79"
BASE_URL = "https://www.virustotal.com/api/v3/"

def scan_url(url):
    """Scan URL menggunakan VirusTotal API"""
    print(f"Scanning URL: {url}")
    
    # Format untuk VirusTotal API v3
    endpoint = "urls"
    headers = {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Format data sesuai dengan API VirusTotal v3
    data = {
        "url": url
    }
    
    try:
        print(f"Sending request to {BASE_URL}{endpoint}")
        response = requests.post(f"{BASE_URL}{endpoint}", headers=headers, data=data)
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Debugging
            print(f"JSON response: {result}")
            
            # Extract analysis ID safely
            data_obj = result.get("data", {})
            if not data_obj:
                print("No data object in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            analysis_id = data_obj.get("id")
            if not analysis_id:
                print("No analysis ID found in response")
                return {"success": False, "message": "Tidak mendapatkan analysis ID dari VirusTotal"}
                
            print(f"Analysis ID: {analysis_id}")
            return {"success": True, "message": "URL berhasil dikirim untuk analisis", "analysis_id": analysis_id}
        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "message": f"Gagal mengirim URL: {response.status_code}", "error": response.text}
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Terjadi kesalahan: {str(e)}"}

def scan_file(file_path):
    """Scan file menggunakan VirusTotal API"""
    print(f"Scanning file: {file_path}")
    
    # Hitung hash file untuk cek apakah sudah pernah di-scan
    file_hash = calculate_file_hash(file_path)
    print(f"File hash: {file_hash}")
    
    # Coba get hasil dari hash terlebih dahulu
    hash_result = get_file_report(file_hash)
    if hash_result.get("success") and hash_result.get("status") == "completed":
        print("File already analyzed")
        return {"success": True, "message": "File sudah pernah dianalisis", "analysis_id": hash_result.get("analysis_id")}
    
    # Jika belum pernah di-scan, upload file
    endpoint = "files"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        print(f"Uploading file to {BASE_URL}{endpoint}")
        with open(file_path, 'rb') as file:
            files = {"file": (os.path.basename(file_path), file, "application/octet-stream")}
            response = requests.post(f"{BASE_URL}{endpoint}", headers=headers, files=files)
        
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Debugging
            print(f"JSON response: {result}")
            
            # Extract analysis ID safely
            data_obj = result.get("data", {})
            if not data_obj:
                print("No data object in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            analysis_id = data_obj.get("id")
            if not analysis_id:
                print("No analysis ID found in response")
                return {"success": False, "message": "Tidak mendapatkan analysis ID dari VirusTotal"}
                
            print(f"Analysis ID: {analysis_id}")
            return {"success": True, "message": "File berhasil dikirim untuk analisis", "analysis_id": analysis_id}
        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "message": f"Gagal mengirim file: {response.status_code}", "error": response.text}
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Terjadi kesalahan: {str(e)}"}

def scan_domain(domain):
    """Scan domain menggunakan VirusTotal API"""
    print(f"Scanning domain: {domain}")
    
    # Validate domain format
    domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    if not re.match(domain_pattern, domain):
        return {"success": False, "message": "Format domain tidak valid"}
    
    endpoint = f"domains/{domain}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        print(f"Sending request to {BASE_URL}{endpoint}")
        response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Debugging
            print(f"JSON response (truncated): {str(result)[:500]}...")
            
            # Extract data safely
            data_obj = result.get("data", {})
            if not data_obj:
                print("No data object in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            attributes = data_obj.get("attributes", {})
            if not attributes:
                print("No attributes in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            # Get last analysis stats
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            last_analysis_results = attributes.get("last_analysis_results", {})
            
            if last_analysis_stats:
                # Generate a unique analysis ID for domain scan
                analysis_id = f"domain_{domain}_{int(time.time())}"
                
                # Format hasil untuk frontend
                formatted_results = {
                    "malicious": last_analysis_stats.get("malicious", 0),
                    "suspicious": last_analysis_stats.get("suspicious", 0),
                    "harmless": last_analysis_stats.get("harmless", 0),
                    "undetected": last_analysis_stats.get("undetected", 0),
                    "total_engines": sum(last_analysis_stats.values()) if last_analysis_stats else 0,
                    "scan_date": int(time.time()),
                    "detailed_results": last_analysis_results
                }
                
                print(f"Domain analysis completed. Stats: {last_analysis_stats}")
                return {
                    "success": True, 
                    "analysis_id": analysis_id,
                    "status": "completed",
                    "results": formatted_results
                }
            else:
                # Generate analysis ID for queued scan
                analysis_id = f"domain_{domain}_{int(time.time())}"
                return {
                    "success": True, 
                    "analysis_id": analysis_id,
                    "message": "Domain dikirim untuk analisis"
                }
                
        elif response.status_code == 404:
            print("Domain not found in VirusTotal")
            # Generate analysis ID for new domain
            analysis_id = f"domain_{domain}_{int(time.time())}"
            return {
                "success": True, 
                "analysis_id": analysis_id,
                "message": "Domain tidak ditemukan, dikirim untuk analisis"
            }
        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "message": f"Gagal melakukan scan domain: {response.status_code}", "error": response.text}
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Terjadi kesalahan: {str(e)}"}

def scan_ip(ip):
    """Scan IP address menggunakan VirusTotal API"""
    print(f"Scanning IP: {ip}")
    
    # Validate IP format
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ipv6_pattern = r"^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$"
    
    if not re.match(ipv4_pattern, ip) and not re.match(ipv6_pattern, ip, re.IGNORECASE):
        return {"success": False, "message": "Format IP address tidak valid"}
    
    endpoint = f"ip_addresses/{ip}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        print(f"Sending request to {BASE_URL}{endpoint}")
        response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Debugging
            print(f"JSON response (truncated): {str(result)[:500]}...")
            
            # Extract data safely
            data_obj = result.get("data", {})
            if not data_obj:
                print("No data object in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            attributes = data_obj.get("attributes", {})
            if not attributes:
                print("No attributes in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            # Get last analysis stats
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            last_analysis_results = attributes.get("last_analysis_results", {})
            
            if last_analysis_stats:
                # Generate a unique analysis ID for IP scan
                analysis_id = f"ip_{ip}_{int(time.time())}"
                
                # Format hasil untuk frontend
                formatted_results = {
                    "malicious": last_analysis_stats.get("malicious", 0),
                    "suspicious": last_analysis_stats.get("suspicious", 0),
                    "harmless": last_analysis_stats.get("harmless", 0),
                    "undetected": last_analysis_stats.get("undetected", 0),
                    "total_engines": sum(last_analysis_stats.values()) if last_analysis_stats else 0,
                    "scan_date": int(time.time()),
                    "detailed_results": last_analysis_results
                }
                
                print(f"IP analysis completed. Stats: {last_analysis_stats}")
                return {
                    "success": True, 
                    "analysis_id": analysis_id,
                    "status": "completed",
                    "results": formatted_results
                }
            else:
                # Generate analysis ID for queued scan
                analysis_id = f"ip_{ip}_{int(time.time())}"
                return {
                    "success": True, 
                    "analysis_id": analysis_id,
                    "message": "IP address dikirim untuk analisis"
                }
                
        elif response.status_code == 404:
            print("IP not found in VirusTotal")
            return {"success": False, "message": "IP address tidak ditemukan dalam database VirusTotal"}
        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "message": f"Gagal melakukan scan IP: {response.status_code}", "error": response.text}
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Terjadi kesalahan: {str(e)}"}

def scan_hash(file_hash):
    """Scan file hash menggunakan VirusTotal API"""
    print(f"Scanning hash: {file_hash}")
    
    # Validate hash format
    md5_pattern = r"^[a-f0-9]{32}$"
    sha1_pattern = r"^[a-f0-9]{40}$"
    sha256_pattern = r"^[a-f0-9]{64}$"
    
    if not (re.match(md5_pattern, file_hash, re.IGNORECASE) or 
            re.match(sha1_pattern, file_hash, re.IGNORECASE) or 
            re.match(sha256_pattern, file_hash, re.IGNORECASE)):
        return {"success": False, "message": "Format hash tidak valid. Mendukung: MD5, SHA1, SHA256"}
    
    endpoint = f"files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        print(f"Sending request to {BASE_URL}{endpoint}")
        response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Debugging
            print(f"JSON response (truncated): {str(result)[:500]}...")
            
            # Extract data safely
            data_obj = result.get("data", {})
            if not data_obj:
                print("No data object in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            attributes = data_obj.get("attributes", {})
            if not attributes:
                print("No attributes in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            # Get last analysis stats
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            last_analysis_results = attributes.get("last_analysis_results", {})
            
            if last_analysis_stats:
                # Generate a unique analysis ID for hash scan
                analysis_id = f"hash_{file_hash}_{int(time.time())}"
                
                # Format hasil untuk frontend
                formatted_results = {
                    "malicious": last_analysis_stats.get("malicious", 0),
                    "suspicious": last_analysis_stats.get("suspicious", 0),
                    "harmless": last_analysis_stats.get("harmless", 0),
                    "undetected": last_analysis_stats.get("undetected", 0),
                    "total_engines": sum(last_analysis_stats.values()) if last_analysis_stats else 0,
                    "scan_date": int(time.time()),
                    "detailed_results": last_analysis_results
                }
                
                print(f"Hash analysis completed. Stats: {last_analysis_stats}")
                return {
                    "success": True, 
                    "analysis_id": analysis_id,
                    "status": "completed",
                    "results": formatted_results
                }
            else:
                # Generate analysis ID for queued scan
                analysis_id = f"hash_{file_hash}_{int(time.time())}"
                return {
                    "success": True, 
                    "analysis_id": analysis_id,
                    "message": "Hash dikirim untuk analisis"
                }
                
        elif response.status_code == 404:
            print("Hash not found in VirusTotal")
            return {"success": False, "message": "Hash file tidak ditemukan dalam database VirusTotal"}
        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "message": f"Gagal melakukan scan hash: {response.status_code}", "error": response.text}
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Terjadi kesalahan: {str(e)}"}

def get_file_report(file_hash):
    """Mendapatkan hasil analisis file berdasarkan hash"""
    print(f"Getting file report for hash: {file_hash}")
    
    endpoint = f"files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        print(f"Sending request to {BASE_URL}{endpoint}")
        response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Debugging
            print(f"JSON response: {result}")
            
            # Extract last analysis ID safely
            data_obj = result.get("data", {})
            if not data_obj:
                print("No data object in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            attributes = data_obj.get("attributes", {})
            if not attributes:
                print("No attributes in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            last_analysis_id = attributes.get("last_analysis_id")
            if last_analysis_id:
                print(f"Last analysis ID: {last_analysis_id}")
                return {"success": True, "status": "completed", "analysis_id": last_analysis_id}
            else:
                print("No last analysis ID found")
                return {"success": True, "status": "not_found"}
        elif response.status_code == 404:
            print("File not found in VirusTotal")
            return {"success": True, "status": "not_found"}
        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "message": f"Gagal mendapatkan hasil analisis: {response.status_code}"}
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Terjadi kesalahan: {str(e)}"}

def get_analysis_result(analysis_id):
    """Mendapatkan hasil analisis dari VirusTotal - Enhanced untuk handle berbagai tipe"""
    print(f"Getting analysis result for ID: {analysis_id}")
    
    # Check if this is a special analysis ID (domain, ip, hash)
    if analysis_id.startswith("domain_"):
        parts = analysis_id.split("_")
        if len(parts) >= 3:
            domain = "_".join(parts[1:-1])  # Join back in case domain has underscores
            return scan_domain(domain)
    elif analysis_id.startswith("ip_"):
        parts = analysis_id.split("_")
        if len(parts) >= 3:
            ip = "_".join(parts[1:-1])  # Join back in case IP has format issues
            return scan_ip(ip)
    elif analysis_id.startswith("hash_"):
        parts = analysis_id.split("_")
        if len(parts) >= 3:
            hash_value = "_".join(parts[1:-1])  # Join back in case hash has underscores
            return scan_hash(hash_value)
    
    # Original file/URL analysis logic
    endpoint = f"analyses/{analysis_id}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        print(f"Sending request to {BASE_URL}{endpoint}")
        response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Debugging
            print(f"JSON response (truncated): {str(result)[:500]}...")
            
            # Extract and check status safely
            data_obj = result.get("data", {})
            if not data_obj:
                print("No data object in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            attributes = data_obj.get("attributes", {})
            if not attributes:
                print("No attributes in response")
                return {"success": False, "message": "Invalid response dari VirusTotal API"}
                
            status = attributes.get("status")
            print(f"Analysis status: {status}")
            
            if not status:
                print("No status found in attributes")
                return {"success": False, "message": "Status tidak ditemukan dalam respons"}
            
            if status == "completed":
                stats = attributes.get("stats", {})
                if not stats:
                    print("No stats found in attributes")
                    return {"success": False, "message": "Statistik tidak ditemukan dalam respons"}
                    
                results = attributes.get("results", {})
                if not results:
                    print("No results found in attributes")
                    results = {}  # Set empty default
                
                # Format hasil untuk frontend
                formatted_results = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "scan_date": attributes.get("date", int(time.time())),
                    "detailed_results": results
                }
                
                print(f"Analysis completed. Stats: {stats}")
                return {"success": True, "status": status, "results": formatted_results}
            else:
                # Analisis masih berjalan
                return {"success": True, "status": status, "message": "Analisis sedang berlangsung"}
        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "message": f"Gagal mendapatkan hasil analisis: {response.status_code}", "error": response.text}
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Terjadi kesalahan: {str(e)}"}

def detect_input_type(input_string):
    """Detect the type of input (hash, domain, IP, URL)"""
    input_clean = input_string.strip().lower()
    
    # Hash patterns
    md5_pattern = r"^[a-f0-9]{32}$"
    sha1_pattern = r"^[a-f0-9]{40}$"
    sha256_pattern = r"^[a-f0-9]{64}$"
    
    # IP patterns
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ipv6_pattern = r"^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$"
    
    # URL pattern
    url_pattern = r"^https?://.*"
    
    # Domain pattern
    domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    
    if re.match(md5_pattern, input_clean):
        return {"type": "md5", "value": input_clean}
    elif re.match(sha1_pattern, input_clean):
        return {"type": "sha1", "value": input_clean}
    elif re.match(sha256_pattern, input_clean):
        return {"type": "sha256", "value": input_clean}
    elif re.match(url_pattern, input_string):
        return {"type": "url", "value": input_string}
    elif re.match(ipv4_pattern, input_clean):
        return {"type": "ip", "value": input_clean}
    elif re.match(ipv6_pattern, input_clean):
        return {"type": "ipv6", "value": input_clean}
    elif re.match(domain_pattern, input_clean):
        return {"type": "domain", "value": input_clean}
    else:
        return {"type": "unknown", "value": input_string}

def search_query(query):
    """Universal search function that detects input type and calls appropriate scan function"""
    print(f"Searching for: {query}")
    
    detected = detect_input_type(query)
    print(f"Detected type: {detected['type']}")
    
    if detected["type"] in ["md5", "sha1", "sha256"]:
        return scan_hash(detected["value"])
    elif detected["type"] == "domain":
        return scan_domain(detected["value"])
    elif detected["type"] in ["ip", "ipv6"]:
        return scan_ip(detected["value"])
    elif detected["type"] == "url":
        return scan_url(detected["value"])
    else:
        # Try as URL first, then as domain
        try:
            url_result = scan_url(detected["value"])
            if url_result.get("success"):
                return url_result
        except:
            pass
        
        try:
            domain_result = scan_domain(detected["value"])
            if domain_result.get("success"):
                return domain_result
        except:
            pass
            
        return {"success": False, "message": "Format input tidak dikenali. Silakan masukkan URL, domain, IP address, atau file hash yang valid."}

def calculate_file_hash(file_path):
    """Menghitung hash SHA-256 dari file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Baca file dalam chunk untuk menghemat memori
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()