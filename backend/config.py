# backend/config.py
import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'your-jwt-secret'
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb://localhost:27017/cyberscan'
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 1 day in seconds
    DEBUG = os.environ.get('DEBUG') == 'True'
    
    # ZAP Configuration
    ZAP_HOST = os.environ.get('ZAP_HOST') or 'localhost'
    ZAP_PORT = int(os.environ.get('ZAP_PORT', 8080))
    ZAP_API_KEY = os.environ.get('ZAP_API_KEY') or ''
    
    # VirusTotal Configuration
    VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY') or '1c10f9758e940d1a6820c53ca7840620e7a6d91a55344312db9cb2b52da78c79'
    
    # Upload Configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32MB (batas VirusTotal)

# Pastikan direktori uploads ada
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)