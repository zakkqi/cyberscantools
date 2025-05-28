# backend/db.py
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

mongo = PyMongo()

class Database:
    @staticmethod
    def init_app(app):
        mongo.init_app(app)
        
    @staticmethod
    def get_db():
        return mongo.db
        
class UserModel:
    @staticmethod
    def create_user(username, email, password, first_name="", last_name=""):
        """Create a new user"""
        # Check if username exists
        if mongo.db.users.find_one({"username": username}):
            return None, "Username already exists"
            
        # Check if email exists
        if mongo.db.users.find_one({"email": email}):
            return None, "Email already exists"
            
        # Create user document
        user = {
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "first_name": first_name,
            "last_name": last_name,
            "role": "user",
            "created_at": datetime.utcnow()
        }
        
        # Insert to DB
        result = mongo.db.users.insert_one(user)
        
        # Get the created user with _id
        created_user = mongo.db.users.find_one({"_id": result.inserted_id})
        
        if created_user:
            # Convert _id to string and remove password
            created_user["_id"] = str(created_user["_id"])
            created_user.pop("password", None)
            return created_user, None
            
        return None, "Failed to create user"
    
    @staticmethod
    def authenticate(username_or_email, password):
        """Authenticate a user"""
        # Try finding by username
        user = mongo.db.users.find_one({"username": username_or_email})
        
        # If not found, try email
        if not user:
            user = mongo.db.users.find_one({"email": username_or_email})
            
        # Verify user and password
        if user and check_password_hash(user["password"], password):
            # Convert _id to string and remove password
            user["_id"] = str(user["_id"])
            user.pop("password", None)
            return user, None
            
        return None, "Invalid username or password"
    
    @staticmethod
    def get_user_by_id(user_id):
        """Get user by ID"""
        try:
            user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
            if user:
                user["_id"] = str(user["_id"])
                user.pop("password", None)
                return user, None
        except Exception as e:
            return None, str(e)
            
        return None, "User not found"
        
class ScanHistoryModel:
    @staticmethod
    def create_scan(user_id, scan_id, target, scan_type, scan_mode=""):
        """Create a new scan history entry"""
        scan = {
            "scan_id": scan_id,
            "user_id": user_id,
            "target": target,
            "scan_type": scan_type,
            "scan_mode": scan_mode,
            "created_at": datetime.utcnow(),
            "status": "running"
        }
        
        result = mongo.db.scan_history.insert_one(scan)
        return str(result.inserted_id)
    
    @staticmethod
    def update_scan_status(scan_id, status, results=None):
        """Update scan status and results"""
        update_data = {
            "status": status
        }
        
        if status == "completed":
            update_data["completed_at"] = datetime.utcnow()
            update_data["results"] = results
            
        mongo.db.scan_history.update_one(
            {"scan_id": scan_id},
            {"$set": update_data}
        )
    
    @staticmethod
    def get_user_scans(user_id, limit=10):
        """Get scans for a user"""
        scans = mongo.db.scan_history.find(
            {"user_id": user_id}
        ).sort("created_at", -1).limit(limit)
        
        result = []
        for scan in scans:
            scan["_id"] = str(scan["_id"])
            result.append(scan)
            
        return result