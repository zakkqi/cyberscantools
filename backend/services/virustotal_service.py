# backend/services/virustotal_service.py
import requests
import json
import os
import time
import hashlib
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
    """Mendapatkan hasil analisis dari VirusTotal"""
    print(f"Getting analysis result for ID: {analysis_id}")
    
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

def calculate_file_hash(file_path):
    """Menghitung hash SHA-256 dari file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Baca file dalam chunk untuk menghemat memori
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()