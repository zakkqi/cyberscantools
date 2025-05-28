# backend/app.py
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from pymongo import MongoClient
from bson.objectid import ObjectId
from config import Config
from services.port_scanner import PortScanner
from services.ssl_scanner import SSLScanner
from services.subdomain_scanner import SubdomainScanner
from services.poisoning_scanner import PoisoningScanner
from services.google_dorking_scanner import GoogleDorkingScanner
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os
import json
import requests
import traceback

# Import service untuk VirusTotal
from services.virustotal_service import scan_url, scan_file, get_analysis_result

# Import untuk web vulnerability scanner dengan ZAP
try:
    from services.web_vulnerability_scanner import WebVulnerabilityScanner
    print("Web vulnerability scanner (ZAP) imported successfully")
except ImportError as e:
    print(f"Error importing web vulnerability scanner: {e}")
    WebVulnerabilityScanner = None

# MongoDB Connection
client = MongoClient('mongodb://localhost:27017/')
db = client.cyberscan
users_collection = db.users
scan_history_collection = db.scan_history

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
jwt = JWTManager(app)

# Set up upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Enable CORS for all routes with proper configuration
CORS(app, 
     resources={r"/api/*": {"origins": "*"}}, 
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"])

# Initialize services
port_scanner = PortScanner()
ssl_scanner = SSLScanner()
subdomain_scanner = SubdomainScanner()
poisoning_scanner = PoisoningScanner()
google_dorking_scanner = GoogleDorkingScanner()

# Initialize ZAP scanner if available
web_vulnerability_scanner = WebVulnerabilityScanner() if WebVulnerabilityScanner else None

# Set VirusTotal API key
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '1c10f9758e940d1a6820c53ca7840620e7a6d91a55344312db9cb2b52da78c79')

# Ensure CORS headers in preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        
        # Add required CORS headers
        headers = resp.headers
        headers['Access-Control-Allow-Origin'] = '*'
        headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        headers['Access-Control-Max-Age'] = '3600'
        
        return resp

# Add CORS headers to all responses
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# Auth routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    
    # Check required fields
    if not all(field in data for field in ["username", "email", "password"]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check if username exists
    if users_collection.find_one({"username": data["username"]}):
        return jsonify({"error": "Username already exists"}), 409
    
    # Check if email exists
    if users_collection.find_one({"email": data["email"]}):
        return jsonify({"error": "Email already exists"}), 409
    
    # Create user document
    user = {
        "username": data["username"],
        "email": data["email"],
        "password": generate_password_hash(data["password"]),
        "first_name": data.get("first_name", ""),
        "last_name": data.get("last_name", ""),
        "role": "user",
        "created_at": datetime.utcnow()
    }
    
    # Insert to DB
    result = users_collection.insert_one(user)
    
    # Get the created user with _id
    created_user = users_collection.find_one({"_id": result.inserted_id})
    
    if created_user:
        # Convert _id to string and remove password
        created_user["_id"] = str(created_user["_id"])
        created_user.pop("password", None)
        
        # Generate token
        access_token = create_access_token(identity=created_user["_id"])
        
        return jsonify({
            "message": "User registered successfully",
            "user": created_user,
            "access_token": access_token
        }), 201
    
    return jsonify({"error": "Failed to create user"}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    
    if not all(field in data for field in ["username", "password"]):
        return jsonify({"error": "Missing username or password"}), 400
    
    # Try finding by username
    user = users_collection.find_one({"username": data["username"]})
    
    # If not found, try email
    if not user:
        user = users_collection.find_one({"email": data["username"]})
    
    # Verify user and password
    if user and check_password_hash(user["password"], data["password"]):
        # Convert _id to string and remove password
        user["_id"] = str(user["_id"])
        user.pop("password", None)
        
        # Generate token
        access_token = create_access_token(identity=user["_id"])
        
        return jsonify({
            "message": "Login successful",
            "user": user,
            "access_token": access_token
        })
    
    return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        
        if user:
            user["_id"] = str(user["_id"])
            user.pop("password", None)
            return jsonify(user)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": "User not found"}), 404

# API Status route
@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({'status': 'running'})

# Debug route
@app.route('/api/debug-test', methods=['GET', 'POST'])
def debug_test():
    """Test endpoint to debug routing issues"""
    method = request.method
    args = dict(request.args)
    form = dict(request.form)
    json_data = request.json if request.is_json else None
    
    return jsonify({
        'success': True,
        'message': 'Debug endpoint working correctly',
        'method': method,
        'args': args,
        'form': form,
        'json': json_data
    })

# Scanners list
@app.route('/api/scanners', methods=['GET'])
def get_scanners():
    scanners = [
        {
            'id': 'port-scanner',
            'name': 'Port Scanner',
            'description': 'Scan for open ports on target hosts',
            'icon': 'server'
        },
        {
            'id': 'ssl-scanner',
            'name': 'SSL/TLS Scanner',
            'description': 'Check for SSL/TLS configuration issues',
            'icon': 'lock'  
        },
        {
            'id': 'web-scanner',
            'name': 'Web Vulnerability Scanner',
            'description': 'Detect web vulnerabilities using OWASP ZAP',
            'icon': 'globe',
            'status': 'active' if web_vulnerability_scanner else 'unavailable',
        },
        {
            'id': 'subdomain-scanner',
            'name': 'Subdomain Finder',
            'description': 'Discover subdomains of a target domain',
            'icon': 'search'
        },
        {
            'id': 'defacement-scanner',
            'name': 'Web Defacement Scanner',
            'description': 'Monitor and detect website defacement activities',
            'icon': 'shield'
        },
        {
            'id': 'poisoning-scanner',
            'name': 'Google Poisoning Scanner',
            'description': 'Detect search engine poisoning and malicious SEO activities',
            'icon': 'virus'
        },
        {
            'id': 'google-dorking-scanner',
            'name': 'Google Dorking Scanner',
            'description': 'Find exposed information using Google search operators',
            'icon': 'google'
        },
        {
            'id': 'virustotal-scanner',
            'name': 'VirusTotal Scanner',
            'description': 'Leverage VirusTotal\'s multi-engine scanning to detect malicious files and URLs',
            'icon': 'virus',
            'status': 'active' if VIRUSTOTAL_API_KEY else 'needs_configuration'
        }
    ]
    return jsonify(scanners)

# Other scanner routes
@app.route('/api/scan/port', methods=['POST'])
def run_port_scan():
    try:
        data = request.json
        target = data.get('target')
        scan_options = data.get('scan_options', {})
        
        # Run port scan
        result = port_scanner.scan(target, scan_options)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/scan/ssl', methods=['POST'])
def run_ssl_scan():
    try:
        data = request.json
        target = data.get('target')
        scan_options = data.get('scan_options', {})
        
        # Run SSL scan
        result = ssl_scanner.scan(target, scan_options)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
@app.route('/api/scan/poisoning', methods=['POST'])
def run_poisoning_scan():
    try:
        data = request.json
        target = data.get('target')
        scan_options = data.get('scan_options', {})
        
        # Run poisoning scan
        result = poisoning_scanner.scan(target, scan_options)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
@app.route('/api/scan/google-dorking', methods=['POST'])
def run_google_dorking_scan():
    try:
        data = request.json
        target = data.get('target')
        scan_options = data.get('scan_options', {})
        
        result = google_dorking_scanner.scan(target, scan_options)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/scan/subdomain', methods=['POST'])
def run_subdomain_scan():
    try:
        data = request.json
        target = data.get('target')
        scan_options = data.get('scan_options', {})
        
        # Run actual subdomain scan
        result = subdomain_scanner.scan(target, scan_options)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Web Vulnerability Scanner Routes (ZAP)
@app.route('/api/scan/web/start', methods=['POST'])
def start_web_scan():
    """Start a web vulnerability scan"""
    try:
        data = request.get_json()
        target = data.get('target')
        mode = data.get('mode', 'basic')
        
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        if not web_vulnerability_scanner:
            return jsonify({'error': 'Web scanner not available'}), 503
        
        # Get user_id from token if available
        user_id = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                user_id = get_jwt_identity()
            except:
                # Continue without user (anonymous scan)
                pass
        
        # Start scan
        result = web_vulnerability_scanner.start_scan_with_user(
            target=target,
            scan_mode=mode,
            user_id=user_id
        )
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in web scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/web/progress/<scan_id>', methods=['GET'])
def get_scan_progress(scan_id):
    """Get progress for a specific scan"""
    try:
        if not web_vulnerability_scanner:
            return jsonify({
                'status': 'error',
                'message': 'ZAP scanner not available'
            }), 503
        
        progress = web_vulnerability_scanner.get_scan_progress(scan_id)
        return jsonify(progress)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Test endpoint for web scanner
@app.route('/api/scan/web/test', methods=['GET'])
def test_web_scan():
    """Test ZAP connectivity"""
    if not web_vulnerability_scanner:
        return jsonify({
            'status': 'error',
            'message': 'ZAP scanner not initialized'
        }), 503
    
    connected, message = web_vulnerability_scanner.test_connection()
    return jsonify({
        'status': 'success' if connected else 'error',
        'message': message,
        'zap_available': connected
    })

@app.route('/api/scan/defacement', methods=['POST'])
def run_defacement_scan():
    return jsonify({
        'status': 'error',
        'message': 'Defacement scanner not implemented yet'
    }), 501

# VirusTotal Scanner Routes - PERBAIKAN
@app.route('/api/virustotal/url', methods=['POST'])
def virustotal_url_scan():
    """Submit a URL for scanning with VirusTotal"""
    try:
        print("Menerima permintaan scan URL dengan VirusTotal")
        
        data = request.get_json()
        if not data or 'target' not in data:
            print("Target URL tidak ditemukan dalam permintaan")
            return jsonify({"success": False, "message": "Target URL tidak ditemukan dalam permintaan"}), 400
        
        target = data.get('target')
        print(f"Memindai URL: {target}")
        
        # Panggil service
        result = scan_url(target)
        print(f"Hasil scan: {result}")
        
        # Simpan hasil scan ke history (opsional)
        if result.get('success') and result.get('analysis_id'):
            try:
                scan_history = {
                    "scan_id": result['analysis_id'],
                    "target": target,
                    "type": "virustotal_url",
                    "timestamp": datetime.utcnow(),
                    "status": "submitted"
                }
                
                # Tambahkan user_id jika ada JWT
                try:
                    user_id = get_jwt_identity()
                    if user_id:
                        scan_history["user_id"] = user_id
                except:
                    pass
                
                # Simpan ke database
                scan_history_collection.insert_one(scan_history)
                print(f"Scan disimpan ke riwayat dengan ID: {result['analysis_id']}")
            except Exception as history_error:
                print(f"Error menyimpan scan ke history: {str(history_error)}")
        
        return jsonify(result)
    except Exception as e:
        print(f"Error dalam VirusTotal URL scan: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/virustotal/file', methods=['POST'])
def virustotal_file_scan():
    """Submit a file for scanning with VirusTotal"""
    try:
        print("Menerima permintaan scan file dengan VirusTotal")
        
        if 'file' not in request.files:
            print("Tidak ada file yang diunggah")
            return jsonify({"success": False, "message": "File tidak ditemukan dalam request"}), 400
        
        uploaded_file = request.files['file']
        
        if uploaded_file.filename == '':
            print("Nama file kosong")
            return jsonify({"success": False, "message": "Tidak ada file yang dipilih"}), 400
        
        print(f"File yang diterima: {uploaded_file.filename}")
        
        # Save file to temporary location
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        uploaded_file.save(file_path)
        print(f"File disimpan ke: {file_path}")
        
        # Panggil service
        result = scan_file(file_path)
        print(f"Hasil scan file: {result}")
        
        # Hapus file temporary setelah scan
        try:
            os.remove(file_path)
            print(f"File temporary dihapus: {file_path}")
        except Exception as cleanup_error:
            print(f"Error menghapus file temporary: {str(cleanup_error)}")
        
        # Simpan hasil scan ke history (opsional)
        if result.get('success') and result.get('analysis_id'):
            try:
                scan_history = {
                    "scan_id": result['analysis_id'],
                    "target": uploaded_file.filename,
                    "type": "virustotal_file",
                    "timestamp": datetime.utcnow(),
                    "status": "submitted"
                }
                
                # Tambahkan user_id jika ada JWT
                try:
                    user_id = get_jwt_identity()
                    if user_id:
                        scan_history["user_id"] = user_id
                except:
                    pass
                
                # Simpan ke database
                scan_history_collection.insert_one(scan_history)
                print(f"Scan file disimpan ke riwayat dengan ID: {result['analysis_id']}")
            except Exception as history_error:
                print(f"Error menyimpan scan file ke history: {str(history_error)}")
        
        return jsonify(result)
    except Exception as e:
        print(f"Error dalam VirusTotal file scan: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/virustotal/status/<analysis_id>', methods=['GET'])
def virustotal_scan_status(analysis_id):
    """Get the status of a VirusTotal scan"""
    try:
        print(f"Memeriksa status scan dengan ID: {analysis_id}")
        
        # Panggil service
        result = get_analysis_result(analysis_id)
        print(f"Status scan: {result.get('status', 'unknown')}")
        
        # Update status di database jika scan selesai
        if result.get('success') and result.get('status') == 'completed':
            try:
                scan_history_collection.update_one(
                    {"scan_id": analysis_id},
                    {"$set": {
                        "status": "completed",
                        "completed_at": datetime.utcnow(),
                        "results": result.get('results')
                    }}
                )
                print(f"Status scan diperbarui ke 'completed' untuk ID: {analysis_id}")
            except Exception as update_error:
                print(f"Error memperbarui status scan: {str(update_error)}")
        
        return jsonify(result)
    except Exception as e:
        print(f"Error memeriksa status scan: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/virustotal/test', methods=['GET'])
def test_virustotal_connection():
    """Test VirusTotal API connection"""
    try:
        print("Menguji koneksi VirusTotal API")
        
        # Validasi API key
        if not VIRUSTOTAL_API_KEY:
            print("VirusTotal API key tidak dikonfigurasi")
            return jsonify({
                "success": False,
                "message": "VirusTotal API key tidak dikonfigurasi"
            }), 500
            
        # Coba akses API VirusTotal dengan API key
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        
        # Lakukan test API call ke endpoint yang tidak memerlukan parameter tambahan
        test_url = "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1"
        try:
            response = requests.get(test_url, headers=headers)
            print(f"VirusTotal API test response status: {response.status_code}")
            
            if response.status_code == 200:
                return jsonify({
                    "success": True,
                    "message": "VirusTotal API connection successful",
                    "api_key_valid": True,
                    "api_key_masked": f"{VIRUSTOTAL_API_KEY[:5]}...{VIRUSTOTAL_API_KEY[-5:]}",
                    "response_status": response.status_code,
                    "timestamp": datetime.now().isoformat()
                })
            else:
                return jsonify({
                    "success": False,
                    "message": f"VirusTotal API returned status {response.status_code}",
                    "api_key_masked": f"{VIRUSTOTAL_API_KEY[:5]}...{VIRUSTOTAL_API_KEY[-5:]}",
                    "response_status": response.status_code,
                    "response_content": response.text[:200]
                }), 400
        except Exception as req_error:
            print(f"Error menghubungi VirusTotal API: {str(req_error)}")
            return jsonify({
                "success": False,
                "message": f"Failed to connect to VirusTotal API: {str(req_error)}",
                "api_key_masked": f"{VIRUSTOTAL_API_KEY[:5]}...{VIRUSTOTAL_API_KEY[-5:]}"
            }), 500
            
    except Exception as e:
        print(f"Error pengujian koneksi VirusTotal: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": f"VirusTotal service connection test failed: {str(e)}"
        }), 500

# User scan history
@app.route('/api/user/history', methods=['GET'])
@jwt_required()
def get_user_scan_history():
    """Get scan history for current user"""
    user_id = get_jwt_identity()
    
    limit = request.args.get('limit', 10, type=int)
    
    try:
        # Get scans from MongoDB
        scans = list(scan_history_collection.find(
            {"user_id": user_id}
        ).sort("created_at", -1).limit(limit))
        
        # Convert _id to string
        for scan in scans:
            scan["_id"] = str(scan["_id"])
            
        return jsonify(scans)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Helper function to save scan to MongoDB
def save_scan_to_history(scan_id, user_id, target, scan_type, scan_mode):
    scan = {
        "scan_id": scan_id,
        "user_id": user_id,
        "target": target,
        "scan_type": scan_type,
        "scan_mode": scan_mode,
        "created_at": datetime.utcnow(),
        "status": "running"
    }
    
    scan_history_collection.insert_one(scan)

# Helper function to update scan status
def update_scan_status(scan_id, status, results=None):
    update_data = {
        "status": status
    }
    
    if status == "completed":
        update_data["completed_at"] = datetime.utcnow()
        if results:
            update_data["results"] = results
    
    scan_history_collection.update_one(
        {"scan_id": scan_id},
        {"$set": update_data}
    )

# Main entry point
if __name__ == '__main__':
    print("Starting CyberScan API server...")
    print(f"VirusTotal API Key configured: {bool(VIRUSTOTAL_API_KEY)}")
    
    # Print all routes for debugging
    print("Available routes:")
    for rule in app.url_map.iter_rules():
        methods = ','.join(list(rule.methods))
        print(f"{methods:20} {str(rule)}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)