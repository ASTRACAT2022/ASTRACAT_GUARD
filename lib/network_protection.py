#!/usr/bin/env python3
"""
Advanced Network Protection Module for ASTRACAT_GUARD
Implements real-time network traffic analysis and blocking
"""

import os
import sys
import time
import socket
import struct
import threading
import subprocess
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
import psutil


class NetworkMonitor:
    """
    Real-time network traffic monitoring class
    """
    def __init__(self, protected_ports=[80, 443, 8080]):
        self.protected_ports = protected_ports
        self.stats = {
            'total_packets': 0,
            'filtered_packets': 0,
            'blocked_ips': set(),
            'connections': defaultdict(int),
            'packet_history': defaultdict(deque)
        }
        self.monitoring = False
        self.filter_chain = []
        
    def start_monitoring(self):
        """Start network monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logging.info(f"Network monitoring started for ports: {self.protected_ports}")

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=2)
        logging.info("Network monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        # This is a simplified version - in production, we'd use raw sockets or netfilter
        while self.monitoring:
            try:
                # Get current network connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.laddr.port in self.protected_ports:
                        if conn.raddr:  # Has remote address
                            remote_ip = conn.raddr.ip
                            self.stats['connections'][remote_ip] += 1
                            
                            # Apply filters
                            for filter_func in self.filter_chain:
                                if filter_func(remote_ip, conn):
                                    self.block_ip(remote_ip)
                                    break
                
                # Sleep to reduce CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logging.error(f"Error in network monitoring: {e}")
                time.sleep(1)

    def block_ip(self, ip):
        """Block an IP using iptables"""
        if ip not in self.stats['blocked_ips']:
            try:
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd.split(), check=True, capture_output=True)
                self.stats['blocked_ips'].add(ip)
                logging.warning(f"Blocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block IP {ip}: {e}")

    def add_filter(self, filter_func):
        """Add a filter function to the chain"""
        self.filter_chain.append(filter_func)

    def get_stats(self):
        """Get current statistics"""
        return dict(self.stats)


class AttackDetector:
    """
    Detection mechanisms for various types of attacks
    """
    def __init__(self, config):
        self.config = config
        self.request_rates = defaultdict(lambda: deque(maxlen=100))  # Store last 100 timestamps
        self.connection_attempts = defaultdict(int)
        self.bad_requests = defaultdict(int)

    def detect_rate_abuse(self, ip):
        """Detect rate limit abuse"""
        if not self.config['rate_limit']['enabled']:
            return False
            
        window_size = self.config['rate_limit']['window_size']
        threshold = self.config['rate_limit']['threshold']
        
        now = time.time()
        recent_requests = [req_time for req_time in self.request_rates[ip] 
                          if now - req_time <= window_size]
        
        if len(recent_requests) > threshold:
            return True
            
        # Add current request
        self.request_rates[ip].append(now)
        return False

    def detect_connection_flooding(self, ip):
        """Detect connection flooding"""
        if not self.config['connection_limit']['enabled']:
            return False
            
        max_conn = self.config['connection_limit']['max_connections_per_ip']
        
        self.connection_attempts[ip] += 1
        current_attempts = self.connection_attempts[ip]
        
        # Reset counter periodically
        if current_attempts % 50 == 0:  # Every 50 attempts, reset slowly
            self.connection_attempts[ip] = max(0, current_attempts - 10)
        
        return current_attempts > max_conn

    def detect_bad_requests(self, ip, request_type="GET"):
        """Detect abusive request patterns"""
        if not self.config['http_flood']['enabled']:
            return False
            
        max_req = self.config['http_flood']['max_requests_per_second']
        
        self.bad_requests[ip] += 1
        current_requests = self.bad_requests[ip]
        
        # Check if requests per second exceed threshold
        if current_requests > max_req:
            return True
        
        # Reset counter after checking
        if current_requests % 20 == 0:  # Periodic reset
            self.bad_requests[ip] = max(0, current_requests - 5)
        
        return False

    def detect_slowloris(self, ip, headers_count, time_connected):
        """Detect slowloris attacks"""
        if not self.config['slowloris_protection']['enabled']:
            return False
            
        max_headers = self.config['slowloris_protection']['max_headers']
        timeout = self.config['slowloris_protection']['timeout']
        
        return headers_count > max_headers or time_connected > timeout


class WebPanelProtector:
    """
    Specialized protection for web panels
    """
    def __init__(self, config):
        self.config = config
        self.sensitive_paths = config['web_panel_protection']['sensitive_urls']
        self.brute_force_attempts = defaultdict(int)
        self.failed_logins = defaultdict(deque)

    def is_sensitive_path(self, path):
        """Check if path is sensitive"""
        for sensitive in self.sensitive_paths:
            if sensitive in path:
                return True
        return False

    def detect_brute_force(self, ip, path, success=False):
        """Detect brute force attempts to sensitive paths"""
        if not self.config['web_panel_protection']['enabled']:
            return False
            
        if not self.is_sensitive_path(path):
            return False
            
        now = time.time()
        
        if not success:
            # Failed attempt
            self.brute_force_attempts[ip] += 1
            self.failed_logins[ip].append(now)
        else:
            # Successful login - reset counter
            self.brute_force_attempts[ip] = 0
            self.failed_logins[ip].clear()
        
        # Check failed login attempts in last 5 minutes
        recent_failures = [t for t in self.failed_logins[ip] 
                          if now - t <= 300]  # 5 minutes
        
        # Brute force threshold
        if len(recent_failures) > 10:
            return True
            
        # High attempt rate
        if self.brute_force_attempts[ip] > 20:
            return True
            
        return False


class BotDetector:
    """
    Bot detection mechanism
    """
    def __init__(self, config):
        self.config = config
        self.known_bots = {
            'masscan', 'nmap', 'nikto', 'sqlmap', 'nessus', 
            'zgrab', 'gobuster', 'dirbuster', 'scanning'
        }

    def detect_bot(self, user_agent):
        """Detect if request is from a bot/scanner"""
        if not self.config['user_agent_filter']['enabled']:
            return False
            
        ua_lower = user_agent.lower()
        for bot_signature in self.config['user_agent_filter']['blocked_agents']:
            if bot_signature.lower() in ua_lower:
                return True
                
        return False


class ASTRACATGUARDCore:
    """
    Main protection core that ties everything together
    """
    def __init__(self, config_path="conf/config.yaml"):
        # Import here to avoid circular dependencies
        import yaml
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.network_monitor = NetworkMonitor(
            self.config['network']['protected_ports']
        )
        self.attack_detector = AttackDetector(self.config['protection'])
        self.web_protector = WebPanelProtector(self.config['protection'])
        self.bot_detector = BotDetector(self.config['protection'])
        
        # Setup logging
        log_level = getattr(logging, self.config['logging']['level'].upper())
        log_file = self.config['logging']['file']
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Load IP lists
        self.whitelisted_ips = set(self.config['whitelist']['ips'])
        self.blacklisted_ips = set()

    def is_whitelisted(self, ip):
        """Check if IP is whitelisted"""
        return ip in self.whitelisted_ips

    def is_blacklisted(self, ip):
        """Check if IP is blacklisted"""
        return ip in self.blacklisted_ips

    def add_to_blacklist(self, ip):
        """Add IP to blacklist"""
        self.blacklisted_ips.add(ip)
        self.network_monitor.block_ip(ip)

    def should_block_request(self, ip, path="/", user_agent="", headers_count=0, time_connected=0):
        """Main decision function to determine if request should be blocked"""
        # Never block whitelisted IPs
        if self.is_whitelisted(ip):
            return False
            
        # Always block blacklisted IPs
        if self.is_blacklisted(ip):
            return True
            
        # Detect various attack patterns
        if self.attack_detector.detect_rate_abuse(ip):
            logging.warning(f"Rate abuse detected from {ip}")
            self.add_to_blacklist(ip)
            return True
            
        if self.attack_detector.detect_connection_flooding(ip):
            logging.warning(f"Connection flooding detected from {ip}")
            self.add_to_blacklist(ip)
            return True
            
        if self.attack_detector.detect_bad_requests(ip):
            logging.warning(f"Bad request pattern detected from {ip}")
            self.add_to_blacklist(ip)
            return True
            
        if self.attack_detector.detect_slowloris(ip, headers_count, time_connected):
            logging.warning(f"Slowloris attack detected from {ip}")
            self.add_to_blacklist(ip)
            return True
            
        if self.bot_detector.detect_bot(user_agent):
            logging.warning(f"Malicious bot detected from {ip}: {user_agent}")
            self.add_to_blacklist(ip)
            return True
            
        if self.web_protector.detect_brute_force(ip, path):
            logging.warning(f"Brute force attack detected from {ip} on {path}")
            self.add_to_blacklist(ip)
            return True
            
        return False

    def start_protection(self):
        """Start all protection mechanisms"""
        logging.info("Starting ASTRACAT_GUARD protection engines...")
        
        # Add custom filters to network monitor
        self.network_monitor.add_filter(
            lambda ip, conn: self.should_block_request(ip)
        )
        
        # Start network monitoring
        self.network_monitor.start_monitoring()
        
        logging.info("All protection engines started successfully")

    def stop_protection(self):
        """Stop all protection mechanisms"""
        logging.info("Stopping ASTRACAT_GUARD protection engines...")
        self.network_monitor.stop_monitoring()
        logging.info("All protection engines stopped")

    def get_statistics(self):
        """Get protection statistics"""
        stats = self.network_monitor.get_stats().copy()
        stats['whitelisted_ips_count'] = len(self.whitelisted_ips)
        stats['blacklisted_ips_count'] = len(self.blacklisted_ips)
        return stats


# Example usage
if __name__ == "__main__":
    # This would normally be started by the main daemon
    print("ASTRACAT_GUARD Network Protection Module")
    print("This module provides the core protection logic.")
    print("Run the main daemon to start protection.")