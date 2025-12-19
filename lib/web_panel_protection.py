#!/usr/bin/env python3
"""
Web Panel Protection Module for ASTRACAT_GUARD
Specialized protection for web-based control panels
"""

import os
import sys
import time
import re
import hashlib
import hmac
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
import threading


class WebPanelProtector:
    """
    Specialized protection system for web panels
    """
    def __init__(self, config):
        self.config = config['protection']['web_panel_protection']
        self.sensitive_paths = set(config['protection']['web_panel_protection']['sensitive_urls'])
        
        # Track login attempts
        self.login_attempts = defaultdict(deque)  # Store timestamps of login attempts
        self.failed_logins = defaultdict(int)     # Count failed logins
        self.successful_logins = defaultdict(int) # Count successful logins
        self.session_tokens = {}                  # Active sessions
        
        # Track form submissions
        self.form_submissions = defaultdict(deque)  # Form submission timestamps
        self.locked_accounts = defaultdict(datetime)  # Account lock times
        
        # CSRF protection
        self.csrf_tokens = {}  # Valid CSRF tokens
        self.token_expiration = 3600  # 1 hour
        
        # Session management
        self.active_sessions = {}  # session_id -> session_data
        self.session_timeout = 3600  # 1 hour
        
    def is_sensitive_path(self, path):
        """Check if the requested path is a sensitive admin/web panel path"""
        for sensitive in self.sensitive_paths:
            if sensitive in path.lower():
                return True
        return False

    def generate_csrf_token(self, session_id):
        """Generate a CSRF token for the session"""
        timestamp = str(int(time.time()))
        token_data = f"{session_id}:{timestamp}"
        token_hash = hashlib.sha256(token_data.encode()).hexdigest()
        self.csrf_tokens[token_hash] = {
            'session_id': session_id,
            'created_at': time.time()
        }
        return token_hash

    def validate_csrf_token(self, token, session_id):
        """Validate the CSRF token"""
        if token not in self.csrf_tokens:
            return False
            
        token_data = self.csrf_tokens[token]
        if token_data['session_id'] != session_id:
            return False
            
        # Check if token is expired
        if time.time() - token_data['created_at'] > self.token_expiration:
            del self.csrf_tokens[token]
            return False
            
        # Token is valid, remove it to prevent reuse
        del self.csrf_tokens[token]
        return True

    def detect_brute_force(self, ip, username=None, success=False):
        """
        Detect brute force login attempts
        """
        now = time.time()
        
        # Add to login attempts history
        self.login_attempts[ip].append(now)
        
        # Remove attempts older than 15 minutes
        while self.login_attempts[ip] and now - self.login_attempts[ip][0] > 900:
            self.login_attempts[ip].popleft()
        
        # If successful login, reset counters
        if success:
            self.failed_logins[ip] = 0
            if username:
                self.failed_logins[f"{ip}:{username}"] = 0
            return False
        
        # Count recent attempts
        recent_attempts = len(self.login_attempts[ip])
        
        # Global threshold check
        if recent_attempts > 10:  # More than 10 attempts in 15 minutes
            return True
            
        # Per-username threshold check (if username provided)
        if username:
            user_attempts_key = f"{ip}:{username}"
            self.failed_logins[user_attempts_key] += 1
            if self.failed_logins[user_attempts_key] > 5:
                return True
        
        # Overall failed attempts check
        self.failed_logins[ip] += 1
        if self.failed_logins[ip] > 20:
            return True
            
        return False

    def should_lock_account(self, ip, username=None):
        """Check if account should be temporarily locked"""
        if username:
            user_attempts_key = f"{ip}:{username}"
            return self.failed_logins[user_attempts_key] > 5
        return self.failed_logins[ip] > 20

    def is_account_locked(self, ip, username=None):
        """Check if account is currently locked"""
        lock_key = f"{ip}:{username}" if username else ip
        if lock_key in self.locked_accounts:
            # Check if lock period has expired
            lock_until = self.locked_accounts[lock_key]
            if datetime.now() < lock_until:
                return True
            else:
                # Lock period expired, remove from locked accounts
                del self.locked_accounts[lock_key]
        return False

    def handle_failed_login(self, ip, username=None):
        """Handle failed login attempt"""
        if self.detect_brute_force(ip, username, success=False):
            lock_key = f"{ip}:{username}" if username else ip
            lock_duration = 3600  # Lock for 1 hour
            self.locked_accounts[lock_key] = datetime.now() + timedelta(seconds=lock_duration)
            logging.warning(f"Account locked due to brute force: {lock_key}")
            return True
        return False

    def handle_successful_login(self, ip, username=None):
        """Handle successful login"""
        self.failed_logins[ip] = 0
        if username:
            self.failed_logins[f"{ip}:{username}"] = 0
            # Clear account lock if exists
            lock_key = f"{ip}:{username}"
            if lock_key in self.locked_accounts:
                del self.locked_accounts[lock_key]
                
        # Record successful login
        self.successful_logins[ip] += 1

    def detect_form_spam(self, ip, form_type="login"):
        """Detect form spamming attempts"""
        now = time.time()
        form_key = f"{ip}:{form_type}"
        
        # Add to form submission history
        self.form_submissions[form_key].append(now)
        
        # Remove submissions older than 1 minute
        while self.form_submissions[form_key] and now - self.form_submissions[form_key][0] > 60:
            self.form_submissions[form_key].popleft()
        
        # Check if too many submissions in the last minute
        if len(self.form_submissions[form_key]) > 10:  # More than 10 submissions per minute
            return True
            
        return False

    def create_session(self, user_id, ip):
        """Create a new session for the user"""
        session_id = hashlib.sha256(f"{user_id}:{ip}:{time.time()}".encode()).hexdigest()
        
        self.active_sessions[session_id] = {
            'user_id': user_id,
            'ip': ip,
            'created_at': time.time(),
            'last_activity': time.time(),
            'csrf_token': self.generate_csrf_token(session_id)
        }
        
        return session_id

    def validate_session(self, session_id):
        """Validate if a session is still active and not expired"""
        if session_id not in self.active_sessions:
            return False
            
        session = self.active_sessions[session_id]
        
        # Check if session is expired
        if time.time() - session['last_activity'] > self.session_timeout:
            del self.active_sessions[session_id]
            return False
            
        # Update last activity
        session['last_activity'] = time.time()
        return True

    def logout_session(self, session_id):
        """Logout a session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]

    def get_user_sessions(self, user_id):
        """Get all active sessions for a user"""
        sessions = []
        for session_id, data in self.active_sessions.items():
            if data['user_id'] == user_id:
                sessions.append(session_id)
        return sessions

    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        expired_sessions = []
        now = time.time()
        
        for session_id, session in self.active_sessions.items():
            if now - session['last_activity'] > self.session_timeout:
                expired_sessions.append(session_id)
                
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
            
        return len(expired_sessions)


class WAFModule:
    """
    Web Application Firewall for additional protection
    """
    def __init__(self, config):
        self.config = config
        self.sql_injection_patterns = [
            r"(?i)(union\s+select|select.*from|drop\s+table|insert\s+into|update.*set|delete\s+from)",
            r"(?i)(exec\s*\(|sp_|xp_|0x[0-9a-f]+)",  # SQL exec patterns
            r"--\s*[^\s]", r"#\s*[^\s]", r"/\*.*?\*/"  # SQL comments
        ]
        
        self.xss_patterns = [
            r"(?i)<script[^>]*>", r"(?i)</script>", r"(?i)javascript:", 
            r"(?i)vbscript:", r"(?i)onload\s*=", r"(?i)onerror\s*="
        ]
        
        self.path_traversal_patterns = [
            r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c", r"\.\.\%2f"
        ]
        
        self.blocked_extensions = {
            '.php', '.asp', '.aspx', '.jsp', '.jspx', '.html', '.htm', 
            '.pl', '.cgi', '.sh', '.py', '.rb', '.java'
        }
        
        # Track alerts
        self.alerts = deque(maxlen=1000)

    def detect_sql_injection(self, data):
        """Detect potential SQL injection attempts"""
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, data):
                self._log_alert("SQL Injection", data)
                return True
        return False

    def detect_xss(self, data):
        """Detect potential XSS attempts"""
        for pattern in self.xss_patterns:
            if re.search(pattern, data):
                self._log_alert("XSS Attempt", data)
                return True
        return False

    def detect_path_traversal(self, path):
        """Detect directory traversal attempts"""
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                self._log_alert("Directory Traversal", path)
                return True
        return False

    def detect_malicious_extension(self, filename):
        """Detect potentially malicious file extensions"""
        extension = os.path.splitext(filename)[1].lower()
        if extension in self.blocked_extensions:
            self._log_alert("Malicious File Upload", filename)
            return True
        return False

    def _log_alert(self, alert_type, data):
        """Log security alert"""
        alert = {
            'timestamp': datetime.now(),
            'type': alert_type,
            'data': data[:100]  # Limit data length
        }
        self.alerts.append(alert)
        logging.warning(f"WAF Alert: {alert_type} - {data[:50]}...")

    def scan_request(self, method, path, headers, body=""):
        """Scan an HTTP request for malicious content"""
        # Check for path traversal
        if self.detect_path_traversal(path):
            return True, "Path traversal attempt"
        
        # Check headers for XSS
        for header_value in headers.values():
            if self.detect_xss(str(header_value)):
                return True, "XSS in headers"
        
        # Check body for SQL injection and XSS
        combined_data = f"{method} {path}\n{body}"
        if self.detect_sql_injection(combined_data):
            return True, "SQL injection attempt"
        
        if self.detect_xss(combined_data):
            return True, "XSS attempt"
        
        # Check for malicious file uploads
        content_disposition = headers.get('Content-Disposition', '')
        if content_disposition:
            filename_match = re.search(r'filename="([^"]+)"', content_disposition, re.IGNORECASE)
            if filename_match:
                filename = filename_match.group(1)
                if self.detect_malicious_extension(filename):
                    return True, "Malicious file upload attempt"
        
        return False, "Request OK"


class WebPanelDefenseSystem:
    """
    Main class that coordinates web panel protection
    """
    def __init__(self, config):
        self.config = config
        self.web_protector = WebPanelProtector(config)
        self.waf = WAFModule(config)
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def _cleanup_loop(self):
        """Background thread to perform periodic cleanup"""
        while True:
            try:
                # Clean up expired sessions every 5 minutes
                expired_count = self.web_protector.cleanup_expired_sessions()
                if expired_count > 0:
                    logging.info(f"Cleaned up {expired_count} expired sessions")
                    
                time.sleep(300)  # 5 minutes
            except Exception as e:
                logging.error(f"Error in cleanup loop: {e}")
                time.sleep(60)

    def protect_request(self, ip, method, path, headers, body=""):
        """
        Main protection method to check if a request should be blocked
        Returns: (should_block, reason)
        """
        # Check if this is a sensitive path that needs extra protection
        if self.web_protector.is_sensitive_path(path):
            # Check for brute force attempts
            if self.web_protector.detect_form_spam(ip, "login"):
                return True, "Form spam detection"
                
            # Check if account is locked
            if self.web_protector.is_account_locked(ip):
                return True, "Account locked due to previous failed attempts"
        
        # Run WAF checks
        blocked, reason = self.waf.scan_request(method, path, headers, body)
        if blocked:
            return blocked, reason
            
        # Additional checks for sensitive paths
        if self.web_protector.is_sensitive_path(path):
            # Check for potential automation tools
            user_agent = headers.get('User-Agent', '').lower()
            if any(bot in user_agent for bot in ['bot', 'crawler', 'scanner', 'masscan', 'nmap']):
                return True, "Automated tool detected"
        
        return False, "OK"

    def handle_login_attempt(self, ip, username, success=False):
        """Handle a login attempt, returns True if should block"""
        if success:
            self.web_protector.handle_successful_login(ip, username)
            return False
        else:
            return self.web_protector.handle_failed_login(ip, username)

    def create_user_session(self, user_id, ip):
        """Create a new authenticated session"""
        return self.web_protector.create_session(user_id, ip)

    def validate_session(self, session_id):
        """Validate a session"""
        return self.web_protector.validate_session(session_id)

    def logout_session(self, session_id):
        """Logout a session"""
        self.web_protector.logout_session(session_id)

    def get_security_stats(self):
        """Get security statistics"""
        return {
            'active_sessions': len(self.web_protector.active_sessions),
            'waf_alerts_count': len(self.waf.alerts),
            'recent_waf_alerts': list(self.waf.alerts)[-10:] if self.waf.alerts else []
        }


if __name__ == "__main__":
    print("Web Panel Protection Module for ASTRACAT_GUARD")
    print("Provides specialized protection for web-based control panels")