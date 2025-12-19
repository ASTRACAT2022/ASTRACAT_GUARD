#!/usr/bin/env python3
"""
ASTRACAT_GUARD - Optimized Server Protection System
Main daemon with focus on low resource usage
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
import signal
import setproctitle  # Need to install this: pip install setproctitle


class OptimizedAstracatGuard:
    """
    Optimized version of ASTRACAT_GUARD focused on minimal resource usage
    """
    def __init__(self, config_path="conf/config.yaml"):
        self.config = self.load_config(config_path)
        self.setup_logging()
        
        # Set process title for easier identification
        setproctitle.setproctitle("astracat-guard")
        
        # Initialize lightweight statistics
        self.stats = {
            'requests': 0,
            'blocked_requests': 0,
            'blocked_ips': {},
            'request_history': defaultdict(deque),
        }
        
        # Initialize protection modules with optimized settings
        self.rate_limiter = OptimizedRateLimiter(self.config['protection']['rate_limit'])
        self.http_flood_detector = OptimizedHTTPFloodDetector(self.config['protection']['http_flood'])
        
        # Load whitelists and blacklists
        self.load_ip_lists()
        
        # Resource monitoring
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        
        logging.info("ASTRACAT_GUARD initialized with optimized settings")

    def load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            return self.default_config()

    def default_config(self):
        """Return default configuration optimized for low resource usage"""
        return {
            'protection': {
                'ddos_protection': True,
                'rate_limit': {'enabled': True, 'threshold': 100, 'window_size': 60},
                'http_flood': {'enabled': True, 'max_requests_per_second': 10},
                'web_panel_protection': {'enabled': True, 'sensitive_urls': ['/admin', '/login', '/panel']},
                'user_agent_filter': {'enabled': True, 'blocked_agents': ['masscan', 'nmap']}
            },
            'logging': {'level': 'INFO', 'file': '/var/log/astracat_guard.log'},
            'whitelist': {'enabled': True, 'ips': ['127.0.0.1', '::1']},
            'blacklist': {'enabled': True, 'auto_block_time': 3600, 'auto_block_threshold': 10}
        }

    def setup_logging(self):
        """Setup logging configuration with rotation"""
        from logging.handlers import RotatingFileHandler
        
        log_level = getattr(logging, self.config['logging']['level'].upper())
        
        # Create rotating file handler to prevent log files from growing too large
        handler = RotatingFileHandler(
            self.config['logging']['file'],
            maxBytes=10*1024*1024,  # 10MB
            backupCount=3
        )
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(handler)
        
        # Also add console handler for important messages
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    def load_ip_lists(self):
        """Load whitelist and blacklist IPs"""
        self.whitelisted_ips = set()
        self.blacklisted_ips = {}
        
        # Load whitelisted IPs
        if self.config['whitelist']['enabled']:
            for ip in self.config['whitelist']['ips']:
                try:
                    self.whitelisted_ips.add(ipaddress.ip_network(ip, strict=False))
                except ValueError:
                    logging.warning(f"Invalid IP in whitelist: {ip}")

    def is_whitelisted(self, ip):
        """Check if IP is whitelisted - optimized version"""
        try:
            ip_obj = ipaddress.IPv4Address(ip) if '.' in ip else ipaddress.IPv6Address(ip)
            for network in self.whitelisted_ips:
                if ip_obj in network:
                    return True
        except:
            pass
        return False

    def is_blacklisted(self, ip):
        """Check if IP is blacklisted with expiration"""
        if ip in self.blacklisted_ips:
            # Check if block has expired
            if time.time() > self.blacklisted_ips[ip]:
                del self.blacklisted_ips[ip]
                return False
            return True
        return False

    def add_to_blacklist(self, ip):
        """Add IP to temporary blacklist"""
        block_duration = self.config['blacklist']['auto_block_time']
        self.blacklisted_ips[ip] = time.time() + block_duration
        logging.warning(f"IP {ip} temporarily blocked for {block_duration}s due to violation")

    def check_request(self, client_ip, request_data):
        """Optimized request checking function"""
        # Skip if whitelisted
        if self.is_whitelisted(client_ip):
            return False
            
        # Check if blacklisted
        if self.is_blacklisted(client_ip):
            self.stats['blocked_requests'] += 1
            return True
        
        # Apply protection checks only if enabled
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
                
        # User agent filtering (lightweight)
        if self.config['protection']['user_agent_filter']['enabled']:
            user_agent = request_data.get('user_agent', '').lower()
            for blocked_agent in self.config['protection']['user_agent_filter']['blocked_agents']:
                if blocked_agent.lower() in user_agent:
                    self.add_to_blacklist(client_ip)
                    self.stats['blocked_requests'] += 1
                    return True
        
        # Update stats
        self.stats['requests'] += 1
        return False

    def cleanup_old_records(self):
        """Clean up old request records to free memory"""
        current_time = time.time()
        cleanup_threshold = current_time - self.config['protection']['rate_limit']['window_size']
        
        # Clean up old request records
        for ip in list(self.stats['request_history'].keys()):
            # Remove old requests
            while self.stats['request_history'][ip] and self.stats['request_history'][ip][0] < cleanup_threshold:
                self.stats['request_history'][ip].popleft()
            
            # Remove IPs with no recent requests
            if not self.stats['request_history'][ip]:
                del self.stats['request_history'][ip]
        
        # Clean up expired blacklist entries (done in is_blacklisted)
        pass

    def run(self):
        """Main protection loop optimized for low resource usage"""
        logging.info("ASTRACAT_GUARD protection engine started (optimized mode)")
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        try:
            while True:
                # Perform periodic cleanup
                current_time = time.time()
                if current_time - self.last_cleanup > self.cleanup_interval:
                    self.cleanup_old_records()
                    self.last_cleanup = current_time
                
                # Sleep longer intervals to reduce CPU usage
                # Only wake up to do maintenance tasks
                time.sleep(10)  # Longer sleep interval
                
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
        finally:
            logging.info("ASTRACAT_GUARD shutting down gracefully...")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logging.info(f"Received signal {signum}, shutting down...")
        sys.exit(0)


class OptimizedRateLimiter:
    """
    Memory-efficient rate limiter using circular buffers
    """
    def __init__(self, config):
        self.enabled = config['enabled']
        self.threshold = config['threshold']
        self.window_size = config['window_size']
        # Using deque with maxlen for automatic memory management
        self.requests = defaultdict(lambda: deque(maxlen=config['threshold']))

    def check(self, ip, factor=1.0):
        """Check rate limit violations"""
        if not self.enabled:
            return False
            
        current_time = time.time()
        threshold = int(self.threshold * factor)
        
        # The deque automatically maintains only the last N requests
        if len(self.requests[ip]) >= threshold:
            # Check if they're all within the window
            if len(self.requests[ip]) > 0 and current_time - self.requests[ip][0] <= self.window_size:
                return True
        
        # Add current request
        self.requests[ip].append(current_time)
        return False


class OptimizedHTTPFloodDetector:
    """
    Efficient HTTP flood detector
    """
    def __init__(self, config):
        self.enabled = config['enabled']
        self.max_req_per_sec = config['max_requests_per_second']
        # Using a simple counter with timestamp for efficiency
        self.request_counts = defaultdict(lambda: {'count': 0, 'timestamp': time.time()})

    def detect(self, ip):
        """Detect HTTP flood attacks efficiently"""
        if not self.enabled:
            return False
            
        current_time = time.time()
        data = self.request_counts[ip]
        
        # Reset counter if enough time has passed
        if current_time - data['timestamp'] > 1:
            data['count'] = 1
            data['timestamp'] = current_time
        else:
            data['count'] += 1
            # Check if threshold exceeded
            if data['count'] > self.max_req_per_sec:
                return True
        
        return False


def resource_usage_monitor():
    """
    Standalone resource usage monitor
    """
    import psutil
    import time
    
    process = psutil.Process(os.getpid())
    
    while True:
        try:
            cpu_percent = process.cpu_percent()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024  # Convert to MB
            
            if cpu_percent > 20:  # Log if using more than 20% CPU
                logging.warning(f"High CPU usage: {cpu_percent}%")
            if memory_mb > 100:   # Log if using more than 100MB
                logging.warning(f"High memory usage: {memory_mb:.2f}MB")
            
            time.sleep(60)  # Check every minute
        except:
            break


if __name__ == "__main__":
    # Start resource monitoring in background thread
    monitor_thread = threading.Thread(target=resource_usage_monitor, daemon=True)
    monitor_thread.start()
    
    # Start the main guard
    guard = OptimizedAstracatGuard()
    guard.run()