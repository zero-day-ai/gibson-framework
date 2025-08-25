"""Authentication security hardening."""
import hashlib
import secrets
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta


class SecurityHardener:
    """Implements security hardening for authentication."""

    def __init__(self):
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        self.rate_limits: Dict[str, List[datetime]] = {}

        # Security policies
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.rate_limit_window = timedelta(minutes=1)
        self.rate_limit_max = 60

    def check_rate_limit(self, identifier: str) -> bool:
        """Check if rate limit is exceeded."""
        now = datetime.utcnow()

        # Clean old entries
        if identifier in self.rate_limits:
            self.rate_limits[identifier] = [
                t for t in self.rate_limits[identifier] if now - t < self.rate_limit_window
            ]
        else:
            self.rate_limits[identifier] = []

        # Check limit
        if len(self.rate_limits[identifier]) >= self.rate_limit_max:
            return False

        # Record attempt
        self.rate_limits[identifier].append(now)
        return True

    def record_failed_attempt(self, identifier: str) -> bool:
        """Record failed authentication attempt."""
        now = datetime.utcnow()

        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []

        self.failed_attempts[identifier].append(now)

        # Check if should be blocked
        recent_failures = [
            t for t in self.failed_attempts[identifier] if now - t < timedelta(minutes=10)
        ]

        if len(recent_failures) >= self.max_failed_attempts:
            self.blocked_ips[identifier] = now
            return False

        return True

    def is_blocked(self, identifier: str) -> bool:
        """Check if identifier is blocked."""
        if identifier not in self.blocked_ips:
            return False

        # Check if lockout expired
        if datetime.utcnow() - self.blocked_ips[identifier] > self.lockout_duration:
            del self.blocked_ips[identifier]
            return False

        return True

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token."""
        return secrets.token_urlsafe(length)

    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data for storage."""
        salt = secrets.token_bytes(16)
        return hashlib.pbkdf2_hmac("sha256", data.encode(), salt, 100000).hex()

    def validate_api_key_strength(self, api_key: str) -> Dict[str, Any]:
        """Validate API key strength."""
        issues = []

        if len(api_key) < 20:
            issues.append("Key length too short (minimum 20 characters)")

        if api_key.lower() == api_key or api_key.upper() == api_key:
            issues.append("Key should contain mixed case")

        if not any(c.isdigit() for c in api_key):
            issues.append("Key should contain numbers")

        return {
            "strong": len(issues) == 0,
            "issues": issues,
            "score": max(0, 100 - (len(issues) * 25)),
        }
