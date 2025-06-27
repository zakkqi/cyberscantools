# backend/models.py
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from datetime import datetime
import os

# MongoDB connection
client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
db = client.cyberscan_tools

class UserModel:
    collection = db.users
    
    @staticmethod
    def create_user(username, email, password, first_name="", last_name="", role="user"):
        """Create a new user with role system"""
        
        # Check if user already exists
        if UserModel.collection.find_one({"$or": [{"username": username}, {"email": email}]}):
            return None, "User already exists"
        
        # Hash password
        password_hash = generate_password_hash(password)
        
        # Default permissions based on role
        default_permissions = {
            "admin": [
                "system.admin",
                "users.manage", 
                "scans.unlimited",
                "reports.all",
                "settings.modify",
                "logs.view"
            ],
            "moderator": [
                "users.view",
                "scans.moderate",
                "reports.view",
                "logs.view"
            ],
            "user": [
                "scans.basic",
                "reports.own",
                "profile.edit"
            ]
        }
        
        user_data = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "is_admin": role in ["admin", "moderator"],
            "permissions": default_permissions.get(role, default_permissions["user"]),
            "admin_level": 1 if role == "admin" else 2 if role == "moderator" else 0,
            "status": "active",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login": None,
            "created_by": None,
            "two_factor_enabled": False,
            "password_expires_at": None,
            "access_restrictions": {},
            "department": ""
        }
        
        try:
            result = UserModel.collection.insert_one(user_data)
            user_data["_id"] = str(result.inserted_id)
            
            # Remove sensitive data before returning
            safe_user = {k: v for k, v in user_data.items() if k != "password_hash"}
            return safe_user, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def authenticate(username_or_email, password):
        """Authenticate user and update last_login"""
        
        user = UserModel.collection.find_one({
            "$or": [
                {"username": username_or_email},
                {"email": username_or_email}
            ],
            "status": "active"
        })
        
        if not user:
            return None, "Invalid credentials"
        
        if not check_password_hash(user["password_hash"], password):
            return None, "Invalid credentials"
        
        # Update last login
        UserModel.collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        # Remove sensitive data
        safe_user = {k: v for k, v in user.items() if k != "password_hash"}
        safe_user["_id"] = str(safe_user["_id"])
        
        return safe_user, None
    
    @staticmethod
    def get_user_by_id(user_id):
        """Get user by ID"""
        try:
            user = UserModel.collection.find_one({"_id": ObjectId(user_id)})
            if not user:
                return None, "User not found"
            
            # Remove sensitive data
            safe_user = {k: v for k, v in user.items() if k != "password_hash"}
            safe_user["_id"] = str(safe_user["_id"])
            
            return safe_user, None
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def get_all_users(admin_user_id=None):
        """Get all users (admin only)"""
        try:
            users = list(UserModel.collection.find({}, {"password_hash": 0}))
            for user in users:
                user["_id"] = str(user["_id"])
                if user.get("created_by"):
                    user["created_by"] = str(user["created_by"])
            return users, None
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def update_user_role(user_id, new_role, admin_id):
        """Update user role (admin only)"""
        try:
            # Get new permissions based on role
            default_permissions = {
                "admin": [
                    "system.admin",
                    "users.manage", 
                    "scans.unlimited",
                    "reports.all",
                    "settings.modify",
                    "logs.view"
                ],
                "moderator": [
                    "users.view",
                    "scans.moderate", 
                    "reports.view",
                    "logs.view"
                ],
                "user": [
                    "scans.basic",
                    "reports.own",
                    "profile.edit"
                ]
            }
            
            update_data = {
                "role": new_role,
                "is_admin": new_role in ["admin", "moderator"],
                "permissions": default_permissions.get(new_role, default_permissions["user"]),
                "admin_level": 1 if new_role == "admin" else 2 if new_role == "moderator" else 0,
                "updated_at": datetime.utcnow()
            }
            
            result = UserModel.collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": update_data}
            )
            
            if result.modified_count == 0:
                return False, "User not found or no changes made"
            
            # Log admin action
            AdminActionLog.log_action(
                admin_id=admin_id,
                action_type="update_user_role",
                target_user_id=user_id,
                description=f"Changed user role to {new_role}"
            )
            
            return True, None
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def delete_user(user_id, admin_id):
        """Delete user (admin only)"""
        try:
            result = UserModel.collection.delete_one({"_id": ObjectId(user_id)})
            
            if result.deleted_count == 0:
                return False, "User not found"
            
            # Log admin action
            AdminActionLog.log_action(
                admin_id=admin_id,
                action_type="delete_user",
                target_user_id=user_id,
                description=f"Deleted user"
            )
            
            return True, None
        except Exception as e:
            return False, str(e)

class AdminActionLog:
    collection = db.admin_actions_log
    
    @staticmethod
    def log_action(admin_id, action_type, description, target_user_id=None, ip_address=None):
        """Log admin actions"""
        try:
            log_data = {
                "admin_id": ObjectId(admin_id),
                "action_type": action_type,
                "description": description,
                "target_user_id": ObjectId(target_user_id) if target_user_id else None,
                "ip_address": ip_address,
                "created_at": datetime.utcnow()
            }
            
            AdminActionLog.collection.insert_one(log_data)
            return True
        except Exception as e:
            print(f"Failed to log admin action: {e}")
            return False
    
    @staticmethod
    def get_logs(limit=100, admin_id=None):
        """Get admin action logs"""
        try:
            query = {}
            if admin_id:
                query["admin_id"] = ObjectId(admin_id)
            
            logs = list(AdminActionLog.collection.find(query)
                       .sort("created_at", -1)
                       .limit(limit))
            
            for log in logs:
                log["_id"] = str(log["_id"])
                log["admin_id"] = str(log["admin_id"])
                if log.get("target_user_id"):
                    log["target_user_id"] = str(log["target_user_id"])
            
            return logs, None
        except Exception as e:
            return None, str(e)

class SystemSettings:
    collection = db.system_settings
    
    @staticmethod
    def get_setting(key):
        """Get system setting"""
        try:
            setting = SystemSettings.collection.find_one({"setting_key": key})
            return setting["setting_value"] if setting else None, None
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def update_setting(key, value, admin_id):
        """Update system setting (admin only)"""
        try:
            result = SystemSettings.collection.update_one(
                {"setting_key": key},
                {
                    "$set": {
                        "setting_key": key,
                        "setting_value": value,
                        "modified_by": ObjectId(admin_id),
                        "modified_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            # Log admin action
            AdminActionLog.log_action(
                admin_id=admin_id,
                action_type="update_setting",
                description=f"Updated setting {key}"
            )
            
            return True, None
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_all_settings():
        """Get all system settings"""
        try:
            settings = list(SystemSettings.collection.find({}, {"_id": 0}))
            return settings, None
        except Exception as e:
            return None, str(e)

class ScanHistoryModel:
    collection = db.scan_history
    
    @staticmethod
    def create_scan(user_id, target, scan_type, results=None):
        """Create scan record"""
        try:
            scan_data = {
                "user_id": ObjectId(user_id),
                "target": target,
                "scan_type": scan_type,
                "results": results or {},
                "status": "completed",
                "created_at": datetime.utcnow()
            }
            
            result = ScanHistoryModel.collection.insert_one(scan_data)
            scan_data["_id"] = str(result.inserted_id)
            scan_data["user_id"] = str(scan_data["user_id"])
            
            return scan_data, None
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def get_user_scans(user_id, limit=50):
        """Get user's scan history"""
        try:
            scans = list(ScanHistoryModel.collection.find({"user_id": ObjectId(user_id)})
                        .sort("created_at", -1)
                        .limit(limit))
            
            for scan in scans:
                scan["_id"] = str(scan["_id"])
                scan["user_id"] = str(scan["user_id"])
            
            return scans, None
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def get_all_scans(limit=100):
        """Get all scans (admin only)"""
        try:
            scans = list(ScanHistoryModel.collection.find({})
                        .sort("created_at", -1)
                        .limit(limit))
            
            for scan in scans:
                scan["_id"] = str(scan["_id"])
                scan["user_id"] = str(scan["user_id"])
            
            return scans, None
        except Exception as e:
            return None, str(e)