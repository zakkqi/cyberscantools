# backend/auth.py
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from db import UserModel, ScanHistoryModel
from datetime import timedelta

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    
    # Check required fields
    if not all(field in data for field in ["username", "email", "password"]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Create user
    user, error = UserModel.create_user(
        username=data["username"],
        email=data["email"],
        password=data["password"],
        first_name=data.get("first_name", ""),
        last_name=data.get("last_name", "")
    )
    
    if error:
        return jsonify({"error": error}), 409
    
    # Generate token
    access_token = create_access_token(
        identity=user["_id"],
        expires_delta=timedelta(days=1)
    )
    
    return jsonify({
        "message": "User registered successfully",
        "user": user,
        "access_token": access_token
    }), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    
    if not all(field in data for field in ["username", "password"]):
        return jsonify({"error": "Missing username or password"}), 400
    
    # Authenticate
    user, error = UserModel.authenticate(
        username_or_email=data["username"],
        password=data["password"]
    )
    
    if error:
        return jsonify({"error": error}), 401
    
    # Generate token
    access_token = create_access_token(
        identity=user["_id"],
        expires_delta=timedelta(days=1)
    )
    
    return jsonify({
        "message": "Login successful",
        "user": user,
        "access_token": access_token
    })

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user, error = UserModel.get_user_by_id(user_id)
    
    if error:
        return jsonify({"error": error}), 404
        
    return jsonify(user)