#!/usr/bin/env python3
"""
ASTRACAT_GUARD - Server Protection System
Main protection daemon
"""

import os
import sys
import time
import json
import yaml
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import select


class AstracatGuard:
    def __init__(self, config_path="conf/config.yaml"):
        self.config = self.load_config(config_path)
        self.setup_logging()
        
        # Initialize statistics
        self.stats = {
            'requests': 0,
            'blocked_requests': 0,
            'blocked_ips': set(),
            'request_history': defaultdict(deque),
            'connection_counts': defaultdict(int),
        }
        
        # Initialize protection modules
        self.rate_limiter = RateLimiter(self.config['protection']['rate_limit'])
        self.connection_limiter = ConnectionLimiter(self.config['protection']['connection_limit'])
        self.http_flood_detector = HTTPFloodDetector(self.config['protection']['http_flood'])
        self.slowloris_detector = SlowLorisDetector(self.config['protection']['slowloris_protection'])
        
        # Load whitelists and blacklists
        self.load_ip_lists()
        
        logging.info("ASTRACAT_GUARD initialized successfully")

    def load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            # Return default config
            return self.default_config()

    def default_config(self):
        """Return default configuration"""
        return {
            'protection': {
                'ddos_protection': True,
                'rate_limit': {'enabled': True, 'threshold': 100, 'window_size': 60},
                'connection_limit': {'enabled': True, 'max_connections': 100, 'max_connections_per_ip': 10},
                'http_flood': {'enabled': True, 'max_requests_per_second': 10},
                'slowloris_protection': {'enabled': True, 'timeout': 15, 'max_headers': 100, 'header_timeout': 5},
                'web_panel_protection': {'enabled': True, 'sensitive_urls': ['/admin', '/login', '/panel']},
                'user_agent_filter': {'enabled': True, 'blocked_agents': ['masscan', 'nmap']}
            },
            'logging': {'level': 'INFO', 'file': '/var/log/astracat_guard.log'},
            'whitelist': {'enabled': True, 'ips': ['127.0.0.1', '::1']},
            'blacklist': {'enabled': True, 'auto_block_time': 3600, 'auto_block_threshold': 10}
        }

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config['logging']['level'].upper())
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['logging']['file']),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def load_ip_lists(self):
        """Load whitelist and blacklist IPs"""
        self.whitelisted_ips = set()
        self.blacklisted_ips = set()
        
        # Load whitelisted IPs
        if self.config['whitelist']['enabled']:
            for ip in self.config['whitelist']['ips']:
                self.whitelisted_ips.add(ipaddress.ip_network(ip, strict=False))
        
        # Load blacklisted IPs (we'll populate this dynamically based on attacks)
        if self.config['blacklist']['enabled']:
            # Initially empty, will be populated during runtime
            pass

    def is_whitelisted(self, ip):
        """Check if IP is whitelisted"""
        try:
            ip_obj = ipaddress.IPv4Address(ip) if '.' in ip else ipaddress.IPv6Address(ip)
            for network in self.whitelisted_ips:
                if ip_obj in network:
                    return True
        except:
            pass
        return False

    def is_blacklisted(self, ip):
        """Check if IP is blacklisted"""
        return ip in self.blacklisted_ips

    def add_to_blacklist(self, ip):
        """Add IP to blacklist"""
        self.blacklisted_ips.add(ip)
        logging.warning(f"IP {ip} added to blacklist")

    def check_request(self, client_ip, request_data):
        """Check if request should be blocked"""
        # Skip if whitelisted
        if self.is_whitelisted(client_ip):
            return False
            
        # Check if blacklisted
        if self.is_blacklisted(client_ip):
            self.stats['blocked_requests'] += 1
            return True
        
        # Apply various protection checks
        if self.config['protection']['rate_limit']['enabled']:
            if self.rate_limiter.check(client_ip):
                self.add_to_blacklist(client_ip)
                self.stats['blocked_requests'] += 1
                return True
                
        if self.config['protection']['http_flood']['enabled']:
            if self.http_flood_detector.detect(client_ip):
                self.add_to_blacklist(client_ip)
                self.stats['blocked_requests'] += 1
                return True
                
        if self.config['protection']['user_agent_filter']['enabled']:
            user_agent = request_data.get('user_agent', '')
            for blocked_agent in self.config['protection']['user_agent_filter']['blocked_agents']:
                if blocked_agent.lower() in user_agent.lower():
                    self.add_to_blacklist(client_ip)
                    self.stats['blocked_requests'] += 1
                    return True
                    
        # Check for sensitive URLs in web panel protection
        if self.config['protection']['web_panel_protection']['enabled']:
            url = request_data.get('url', '')
            for sensitive_url in self.config['protection']['web_panel_protection']['sensitive_urls']:
                if sensitive_url in url:
                    # Apply stricter checks for sensitive URLs
                    if self.rate_limiter.check(client_ip, factor=0.5):  # More restrictive
                        self.add_to_blacklist(client_ip)
                        self.stats['blocked_requests'] += 1
                        return True
        
        # Update stats
        self.stats['requests'] += 1
        return False

    def run(self):
        """Main protection loop"""
        logging.info("ASTRACAT_GUARD protection engine started")
        
        while True:
            try:
                # Perform periodic maintenance
                self.maintenance()
                
                # Monitor network traffic (simplified simulation)
                # In a real implementation, this would hook into network traffic
                time.sleep(1)
                
            except KeyboardInterrupt:
                logging.info("ASTRACAT_GUARD shutting down...")
                break
            except Exception as e:
                logging.error(f"Error in main loop: {e}")
                time.sleep(1)

    def maintenance(self):
        """Perform periodic maintenance tasks"""
        # Clean up old request records periodically
        current_time = time.time()
        cleanup_threshold = current_time - self.config['protection']['rate_limit']['window_size']
        
        for ip, requests in list(self.stats['request_history'].items()):
            # Remove old requests
            while requests and requests[0] < cleanup_threshold:
                requests.popleft()


class RateLimiter:
    def __init__(self, config):
        self.enabled = config['enabled']
        self.threshold = config['threshold']
        self.window_size = config['window_size']
        self.requests = defaultdict(deque)

    def check(self, ip, factor=1.0):
        """Check if IP exceeds rate limit"""
        if not self.enabled:
            return False
            
        current_time = time.time()
        threshold = int(self.threshold * factor)
        
        # Remove old requests outside the window
        while self.requests[ip] and self.requests[ip][0] < current_time - self.window_size:
            self.requests[ip].popleft()
            
        # Check if limit exceeded
        if len(self.requests[ip]) >= threshold:
            return True
            
        # Record this request
        self.requests[ip].append(current_time)
        return False


class ConnectionLimiter:
    def __init__(self, config):
        self.enabled = config['enabled']
        self.max_connections = config['max_connections']
        self.max_connections_per_ip = config['max_connections_per_ip']
        self.connections = {}
        self.connections_per_ip = defaultdict(int)

    def check(self, ip):
        """Check connection limits"""
        if not self.enabled:
            return False
            
        # Check global connection limit
        if len(self.connections) >= self.max_connections:
            return True
            
        # Check per-IP connection limit
        if self.connections_per_ip[ip] >= self.max_connections_per_ip:
            return True
            
        return False

    def add_connection(self, ip, conn_id):
        """Add a connection"""
        if not self.enabled:
            return
            
        self.connections[conn_id] = ip
        self.connections_per_ip[ip] += 1

    def remove_connection(self, conn_id):
        """Remove a connection"""
        if not self.enabled or conn_id not in self.connections:
            return
            
        ip = self.connections.pop(conn_id)
        self.connections_per_ip[ip] -= 1
        if self.connections_per_ip[ip] <= 0:
            del self.connections_per_ip[ip]


class HTTPFloodDetector:
    def __init__(self, config):
        self.enabled = config['enabled']
        self.max_req_per_sec = config['max_requests_per_second']
        self.requests = defaultdict(list)

    def detect(self, ip):
        """Detect HTTP flood"""
        if not self.enabled:
            return False
            
        current_time = time.time()
        
        # Keep only recent requests
        self.requests[ip] = [req_time for req_time in self.requests[ip] 
                           if current_time - req_time <= 1]  # Last second
        
        if len(self.requests[ip]) >= self.max_req_per_sec:
            return True
            
        self.requests[ip].append(current_time)
        return False


class SlowLorisDetector:
    def __init__(self, config):
        self.enabled = config['enabled']
        self.timeout = config['timeout']
        self.header_timeout = config['header_timeout']
        self.max_headers = config['max_headers']
        self.connections = {}

    def check_connection(self, conn_id):
        """Check if connection is exhibiting slowloris behavior"""
        if not self.enabled or conn_id not in self.connections:
            return False
            
        conn_info = self.connections[conn_id]
        current_time = time.time()
        
        # Check if headers are being sent too slowly
        if 'last_header_time' in conn_info:
            if current_time - conn_info['last_header_time'] > self.header_timeout:
                return True
                
        # Check if there are too many headers
        if conn_info.get('headers_count', 0) > self.max_headers:
            return True
            
        # Check total connection time
        if current_time - conn_info['start_time'] > self.timeout:
            return True
            
        return False

    def record_header(self, conn_id):
        """Record that a header was received"""
        if not self.enabled:
            return
            
        if conn_id not in self.connections:
            self.connections[conn_id] = {
                'start_time': time.time(),
                'headers_count': 0
            }
            
        self.connections[conn_id]['last_header_time'] = time.time()
        self.connections[conn_id]['headers_count'] += 1

    def close_connection(self, conn_id):
        """Close connection and clean up"""
        if conn_id in self.connections:
            del self.connections[conn_id]


if __name__ == "__main__":
    guard = AstracatGuard()
    guard.run()