"""
Settings Routes - Flask Blueprint for Settings API endpoints.

Provides RESTful API for:
- User profile management
- Avatar upload/removal
- Password changes
- API key management
- Notification preferences
- Allowed domains CRUD
"""

import os
import uuid
from flask import Blueprint, request, jsonify, render_template, current_app
from werkzeug.utils import secure_filename

from settings_manager import get_settings_manager

# Create Blueprint
settings_bp = Blueprint('settings', __name__)

# Allowed file extensions for avatar
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================================
# PAGE ROUTE
# =========================================

@settings_bp.route('/settings', methods=['GET'])
def settings_page():
    """Render the settings page."""
    return render_template('settings.html')


# =========================================
# SETTINGS API ENDPOINTS
# =========================================

@settings_bp.route('/api/settings', methods=['GET'])
def get_settings():
    """Get all current settings."""
    manager = get_settings_manager()
    return jsonify({
        "success": True,
        "settings": manager.get_all_settings()
    })


@settings_bp.route('/api/settings', methods=['POST'])
def save_settings():
    """Save all settings at once."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        manager = get_settings_manager()
        success = manager.save_all_settings(data)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Settings saved successfully"
            })
        else:
            return jsonify({"success": False, "error": "Failed to save settings"}), 500
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@settings_bp.route('/api/settings/discard', methods=['POST'])
def discard_settings():
    """Discard unsaved changes and reload from disk."""
    manager = get_settings_manager()
    manager.discard_changes()
    return jsonify({
        "success": True,
        "settings": manager.get_all_settings()
    })


# =========================================
# PROFILE ENDPOINTS
# =========================================

@settings_bp.route('/api/settings/profile', methods=['POST'])
def update_profile():
    """Update user profile (name, email)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        manager = get_settings_manager()
        success = manager.update_profile(
            full_name=data.get('fullName'),
            email=data.get('email')
        )
        
        if success:
            return jsonify({
                "success": True,
                "profile": manager.get_profile()
            })
        else:
            return jsonify({"success": False, "error": "Failed to update profile"}), 500
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@settings_bp.route('/api/settings/avatar', methods=['POST'])
def upload_avatar():
    """Upload a new avatar image."""
    try:
        if 'avatar' not in request.files:
            return jsonify({"success": False, "error": "No file provided"}), 400
        
        file = request.files['avatar']
        
        if file.filename == '':
            return jsonify({"success": False, "error": "No file selected"}), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                "success": False, 
                "error": f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
            }), 400
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(0)  # Seek back to start
        
        if size > MAX_AVATAR_SIZE:
            return jsonify({
                "success": False,
                "error": f"File too large. Maximum size: {MAX_AVATAR_SIZE // (1024*1024)}MB"
            }), 400
        
        # Generate unique filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"avatar_{uuid.uuid4().hex[:8]}.{ext}"
        
        # Ensure uploads directory exists
        uploads_dir = os.path.join(current_app.root_path, 'static', 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Remove old avatar first
        manager = get_settings_manager()
        manager.remove_avatar()
        
        # Save new avatar
        filepath = os.path.join(uploads_dir, filename)
        file.save(filepath)
        
        # Update settings
        manager.set_avatar(filename)
        
        return jsonify({
            "success": True,
            "avatar": f"uploads/{filename}"
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@settings_bp.route('/api/settings/avatar', methods=['DELETE'])
def remove_avatar():
    """Remove current avatar."""
    try:
        manager = get_settings_manager()
        success = manager.remove_avatar()
        
        return jsonify({"success": success})
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================
# PASSWORD ENDPOINTS
# =========================================

@settings_bp.route('/api/settings/password', methods=['POST'])
def change_password():
    """Change user password."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        new_password = data.get('newPassword')
        current_password = data.get('currentPassword')
        
        if not new_password:
            return jsonify({"success": False, "error": "New password required"}), 400
        
        if len(new_password) < 8:
            return jsonify({
                "success": False, 
                "error": "Password must be at least 8 characters"
            }), 400
        
        manager = get_settings_manager()
        
        # Verify current password if one exists
        if not manager.verify_password(current_password or ''):
            return jsonify({
                "success": False,
                "error": "Current password is incorrect"
            }), 401
        
        # Change password
        success = manager.change_password(new_password)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Password updated successfully",
                "passwordLastChanged": manager.get_password_last_changed()
            })
        else:
            return jsonify({"success": False, "error": "Failed to update password"}), 500
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================
# API KEY ENDPOINTS
# =========================================

@settings_bp.route('/api/settings/api-key', methods=['GET'])
def get_api_key():
    """Get the full API key (for copy)."""
    manager = get_settings_manager()
    return jsonify({
        "success": True,
        "apiKey": manager.get_api_key()
    })


@settings_bp.route('/api/settings/api-key', methods=['POST'])
def regenerate_api_key():
    """Regenerate API key."""
    try:
        manager = get_settings_manager()
        new_key = manager.regenerate_api_key()
        
        return jsonify({
            "success": True,
            "apiKey": new_key,
            "apiKeyMasked": manager.get_masked_api_key(),
            "message": "API key regenerated. Make sure to update your integrations."
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================
# NOTIFICATION ENDPOINTS
# =========================================

@settings_bp.route('/api/settings/notifications', methods=['POST'])
def update_notifications():
    """Update notification preferences."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        manager = get_settings_manager()
        success = manager.update_notifications(
            critical_threats=data.get('criticalThreats'),
            suspicious_activity=data.get('suspiciousActivity'),
            weekly_digest=data.get('weeklyDigest')
        )
        
        if success:
            return jsonify({
                "success": True,
                "notifications": manager.get_notifications()
            })
        else:
            return jsonify({"success": False, "error": "Failed to update notifications"}), 500
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================
# ALLOWED DOMAINS ENDPOINTS
# =========================================

@settings_bp.route('/api/settings/allowed-domains', methods=['GET'])
def get_allowed_domains():
    """Get list of allowed domains."""
    manager = get_settings_manager()
    return jsonify({
        "success": True,
        "domains": manager.get_allowed_domains()
    })


@settings_bp.route('/api/settings/allowed-domains', methods=['POST'])
def add_allowed_domain():
    """Add a new allowed domain."""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"success": False, "error": "Domain is required"}), 400
        
        manager = get_settings_manager()
        result = manager.add_allowed_domain(data['domain'])
        
        if result["success"]:
            return jsonify(result)
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@settings_bp.route('/api/settings/allowed-domains/<domain>', methods=['DELETE'])
def remove_allowed_domain(domain):
    """Remove an allowed domain."""
    try:
        manager = get_settings_manager()
        success = manager.remove_allowed_domain(domain)
        
        if success:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Domain not found"}), 404
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
