"""
Settings Manager - Handles all user settings persistence and operations.

This module provides:
- JSON-based settings storage
- Password hashing with werkzeug
- API key generation
- Avatar file management
- Integration with trusted_domains_manifest.json for allowed domains
"""

import json
import os
import secrets
import string
from datetime import datetime
from typing import Dict, Any, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "user_settings.json")
TRUSTED_DOMAINS_FILE = os.path.join(BASE_DIR, "trusted_domains_manifest.json")
UPLOADS_DIR = os.path.join(BASE_DIR, "static", "uploads")

# Default settings template
DEFAULT_SETTINGS = {
    "profile": {
        "fullName": "John Doe",
        "email": "john.doe@phishguard.io",
        "avatar": None,
        "passwordHash": None,
        "passwordLastChanged": None
    },
    "apiKey": None,
    "apiKeyCreatedAt": None,
    "notifications": {
        "criticalThreats": True,
        "suspiciousActivity": True,
        "weeklyDigest": False
    },
    "allowedDomains": [
        {"domain": "google.com", "dateAdded": "2023-10-26"},
        {"domain": "company-intranet.net", "dateAdded": "2023-09-12"},
        {"domain": "secure-payments.io", "dateAdded": "2023-08-05"}
    ]
}


def _ensure_dirs():
    """Ensure required directories exist."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)


def _generate_api_key(length: int = 32) -> str:
    """Generate a secure random API key."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _load_settings() -> Dict[str, Any]:
    """Load settings from JSON file, creating defaults if needed."""
    _ensure_dirs()
    
    if not os.path.exists(SETTINGS_FILE):
        # Create default settings with generated API key
        settings = DEFAULT_SETTINGS.copy()
        settings["apiKey"] = _generate_api_key()
        settings["apiKeyCreatedAt"] = datetime.now().isoformat()
        _save_settings(settings)
        return settings
    
    try:
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        # Return defaults on error
        return DEFAULT_SETTINGS.copy()


def _save_settings(settings: Dict[str, Any]) -> bool:
    """Save settings to JSON file."""
    _ensure_dirs()
    
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
        return True
    except IOError:
        return False


class SettingsManager:
    """Manages user settings with persistence."""
    
    def __init__(self):
        self.settings = _load_settings()
    
    def reload(self):
        """Reload settings from disk."""
        self.settings = _load_settings()
    
    def save(self) -> bool:
        """Save current settings to disk."""
        return _save_settings(self.settings)
    
    # =========================================
    # PROFILE OPERATIONS
    # =========================================
    
    def get_profile(self) -> Dict[str, Any]:
        """Get user profile (excluding password hash)."""
        profile = self.settings.get("profile", {}).copy()
        # Never expose password hash to frontend
        profile.pop("passwordHash", None)
        return profile
    
    def update_profile(self, full_name: Optional[str] = None, 
                      email: Optional[str] = None) -> bool:
        """Update profile information."""
        if full_name is not None:
            self.settings["profile"]["fullName"] = full_name.strip()
        if email is not None:
            self.settings["profile"]["email"] = email.strip().lower()
        return self.save()
    
    def get_avatar_path(self) -> Optional[str]:
        """Get avatar file path relative to static folder."""
        return self.settings.get("profile", {}).get("avatar")
    
    def set_avatar(self, filename: str) -> bool:
        """Set avatar filename."""
        self.settings["profile"]["avatar"] = f"uploads/{filename}"
        return self.save()
    
    def remove_avatar(self) -> bool:
        """Remove avatar and delete file if exists."""
        avatar = self.settings.get("profile", {}).get("avatar")
        if avatar:
            # Delete the file
            full_path = os.path.join(BASE_DIR, "static", avatar)
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                except OSError:
                    pass
        
        self.settings["profile"]["avatar"] = None
        return self.save()
    
    def change_password(self, new_password: str) -> bool:
        """Change user password (hashed)."""
        if not new_password or len(new_password) < 8:
            return False
        
        self.settings["profile"]["passwordHash"] = generate_password_hash(new_password)
        self.settings["profile"]["passwordLastChanged"] = datetime.now().isoformat()
        return self.save()
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        stored_hash = self.settings.get("profile", {}).get("passwordHash")
        if not stored_hash:
            return True  # No password set yet
        return check_password_hash(stored_hash, password)
    
    def get_password_last_changed(self) -> Optional[str]:
        """Get human-readable password last changed date."""
        last_changed = self.settings.get("profile", {}).get("passwordLastChanged")
        if not last_changed:
            return "Never"
        
        try:
            dt = datetime.fromisoformat(last_changed)
            now = datetime.now()
            diff = now - dt
            
            if diff.days > 365:
                years = diff.days // 365
                return f"{years} year{'s' if years > 1 else ''} ago"
            elif diff.days > 30:
                months = diff.days // 30
                return f"{months} month{'s' if months > 1 else ''} ago"
            elif diff.days > 0:
                return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
            else:
                return "Today"
        except (ValueError, TypeError):
            return "Unknown"
    
    # =========================================
    # API KEY OPERATIONS
    # =========================================
    
    def get_api_key(self) -> str:
        """Get current API key."""
        key = self.settings.get("apiKey")
        if not key:
            key = _generate_api_key()
            self.settings["apiKey"] = key
            self.settings["apiKeyCreatedAt"] = datetime.now().isoformat()
            self.save()
        return key
    
    def get_masked_api_key(self) -> str:
        """Get masked API key for display (show last 4 chars only)."""
        key = self.get_api_key()
        return "•" * (len(key) - 4) + key[-4:]
    
    def regenerate_api_key(self) -> str:
        """Generate a new API key."""
        new_key = _generate_api_key()
        self.settings["apiKey"] = new_key
        self.settings["apiKeyCreatedAt"] = datetime.now().isoformat()
        self.save()
        return new_key
    
    # =========================================
    # NOTIFICATION PREFERENCES
    # =========================================
    
    def get_notifications(self) -> Dict[str, bool]:
        """Get notification preferences."""
        return self.settings.get("notifications", {
            "criticalThreats": True,
            "suspiciousActivity": True,
            "weeklyDigest": False
        })
    
    def update_notifications(self, critical_threats: Optional[bool] = None,
                            suspicious_activity: Optional[bool] = None,
                            weekly_digest: Optional[bool] = None) -> bool:
        """Update notification preferences."""
        if "notifications" not in self.settings:
            self.settings["notifications"] = {}
        
        if critical_threats is not None:
            self.settings["notifications"]["criticalThreats"] = critical_threats
        if suspicious_activity is not None:
            self.settings["notifications"]["suspiciousActivity"] = suspicious_activity
        if weekly_digest is not None:
            self.settings["notifications"]["weeklyDigest"] = weekly_digest
        
        return self.save()
    
    # =========================================
    # ALLOWED DOMAINS OPERATIONS
    # =========================================
    
    def get_allowed_domains(self) -> List[Dict[str, str]]:
        """Get list of allowed domains."""
        return self.settings.get("allowedDomains", [])
    
    def add_allowed_domain(self, domain: str) -> Dict[str, Any]:
        """Add a new allowed domain."""
        domain = domain.strip().lower()
        
        # Validate domain format
        if not domain or len(domain) < 3:
            return {"success": False, "error": "Invalid domain"}
        
        # Check for duplicates
        existing = [d["domain"] for d in self.settings.get("allowedDomains", [])]
        if domain in existing:
            return {"success": False, "error": "Domain already exists"}
        
        # Add domain
        new_entry = {
            "domain": domain,
            "dateAdded": datetime.now().strftime("%b %d, %Y")
        }
        
        if "allowedDomains" not in self.settings:
            self.settings["allowedDomains"] = []
        
        self.settings["allowedDomains"].append(new_entry)
        self.save()
        
        # Also add to trusted_domains_manifest.json for ML bypass
        self._sync_to_trusted_domains(domain, add=True)
        
        return {"success": True, "domain": new_entry}
    
    def remove_allowed_domain(self, domain: str) -> bool:
        """Remove an allowed domain."""
        domain = domain.strip().lower()
        
        original_count = len(self.settings.get("allowedDomains", []))
        self.settings["allowedDomains"] = [
            d for d in self.settings.get("allowedDomains", [])
            if d["domain"].lower() != domain
        ]
        
        if len(self.settings["allowedDomains"]) < original_count:
            self.save()
            # Also remove from trusted_domains_manifest.json
            self._sync_to_trusted_domains(domain, add=False)
            return True
        return False
    
    def _sync_to_trusted_domains(self, domain: str, add: bool = True):
        """Sync allowed domain to trusted_domains_manifest.json."""
        try:
            if os.path.exists(TRUSTED_DOMAINS_FILE):
                with open(TRUSTED_DOMAINS_FILE, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
            else:
                manifest = {"trusted_domains": [], "user_added": []}
            
            # Use user_added section for settings-added domains
            if "user_added" not in manifest:
                manifest["user_added"] = []
            
            if add and domain not in manifest["user_added"]:
                manifest["user_added"].append(domain)
            elif not add and domain in manifest["user_added"]:
                manifest["user_added"].remove(domain)
            
            with open(TRUSTED_DOMAINS_FILE, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)
        except (IOError, json.JSONDecodeError):
            pass  # Silent fail - main settings still work
    
    # =========================================
    # BULK OPERATIONS
    # =========================================
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all settings for frontend (sanitized)."""
        return {
            "profile": self.get_profile(),
            "passwordLastChanged": self.get_password_last_changed(),
            "apiKeyMasked": self.get_masked_api_key(),
            "notifications": self.get_notifications(),
            "allowedDomains": self.get_allowed_domains()
        }
    
    def save_all_settings(self, data: Dict[str, Any]) -> bool:
        """Save multiple settings at once."""
        # Update profile
        if "profile" in data:
            profile = data["profile"]
            self.update_profile(
                full_name=profile.get("fullName"),
                email=profile.get("email")
            )
        
        # Update notifications
        if "notifications" in data:
            notif = data["notifications"]
            self.update_notifications(
                critical_threats=notif.get("criticalThreats"),
                suspicious_activity=notif.get("suspiciousActivity"),
                weekly_digest=notif.get("weeklyDigest")
            )
        
        return self.save()
    
    def discard_changes(self):
        """Reload settings from disk, discarding any unsaved changes."""
        self.reload()


# Global instance
_settings_manager = None


def get_settings_manager() -> SettingsManager:
    """Get or create the global settings manager instance."""
    global _settings_manager
    if _settings_manager is None:
        _settings_manager = SettingsManager()
    return _settings_manager
