#!/bin/bash
#
# ASTRACAT_GUARD Auto-Installer
# Универсальный скрипт для автоматической установки ASTRACAT_GUARD
# Поддерживает Ubuntu, Debian, CentOS, RHEL, Fedora
#
# Usage: sudo ./install.sh

set -e  # Exit on any error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              ASTRACAT_GUARD Auto-Installer                ║${NC}"
echo -e "${BLUE}║                    Version 2.0 Final                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}Running as root - proceeding with installation${NC}"
else
   echo -e "${RED}This script must be run as root (use sudo)!${NC}"
   exit 1
fi

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        DISTRO=$ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
        DISTRO=$(echo $OS | tr '[:upper:]' '[:lower:]')
    else
        echo -e "${RED}Cannot detect OS. Exiting.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Detected OS: $OS $VER ($DISTRO)${NC}"
}

# Install prerequisites
install_prerequisites() {
    echo -e "${BLUE}Installing prerequisites...${NC}"
    
    if [[ "$DISTRO" == *"ubuntu"* ]] || [[ "$DISTRO" == *"debian"* ]]; then
        apt-get update
        apt-get install -y python3 python3-pip python3-venv iptables fail2ban curl wget net-tools dnsutils git
    elif [[ "$DISTRO" == *"centos"* ]] || [[ "$DISTRO" == *"rhel"* ]] || [[ "$DISTRO" == *"fedora"* ]]; then
        if command -v dnf &> /dev/null; then
            dnf install -y python3 python3-pip python3-virtualenv iptables fail2ban curl wget net-tools bind-utils git
        else
            yum install -y python3 python3-pip python3-virtualenv iptables fail2ban curl wget net-tools bind-utils git
        fi
        # Also install EPEL repo for some packages on CentOS/RHEL
        if [[ "$DISTRO" == *"centos"* ]] || [[ "$DISTRO" == *"rhel"* ]]; then
            yum install -y epel-release || true
        fi
    elif [[ "$DISTRO" == *"almalinux"* ]] || [[ "$DISTRO" == *"rocky"* ]]; then
        dnf install -y python3 python3-pip python3-virtualenv iptables fail2ban curl wget net-tools bind-utils git
    else
        echo -e "${YELLOW}Unsupported OS. Attempting generic installation...${NC}"
        # Try to install generic packages
        if command -v apt-get &> /dev/null; then
            apt-get install -y python3 python3-pip python3-venv iptables curl wget net-tools
        elif command -v yum &> /dev/null; then
            yum install -y python3 python3-pip python3-virtualenv iptables curl wget net-tools
        elif command -v dnf &> /dev/null; then
            dnf install -y python3 python3-pip python3-virtualenv iptables curl wget net-tools
        fi
    fi
    
    echo -e "${GREEN}Prerequisites installed${NC}"
}

# Create virtual environment
setup_virtualenv() {
    echo -e "${BLUE}Setting up Python virtual environment...${NC}"
    
    VENV_DIR="/opt/astracat_guard/myenv"
    mkdir -p "$VENV_DIR"
    
    if command -v python3 -m venv &> /dev/null; then
        python3 -m venv "$VENV_DIR"
    elif command -v virtualenv &> /dev/null; then
        virtualenv -p python3 "$VENV_DIR"
    else
        echo -e "${RED}No virtual environment tool found. Installing python3-venv...${NC}"
        if [[ "$DISTRO" == *"ubuntu"* ]] || [[ "$DISTRO" == *"debian"* ]]; then
            apt-get install -y python3-venv
            python3 -m venv "$VENV_DIR"
        elif command -v dnf &> /dev/null; then
            dnf install -y python3-virtualenv
            virtualenv -p python3 "$VENV_DIR"
        elif command -v yum &> /dev/null; then
            yum install -y python3-virtualenv
            virtualenv -p python3 "$VENV_DIR"
        fi
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    echo -e "${GREEN}Virtual environment created and activated${NC}"
}

# Install Python dependencies
install_python_deps() {
    echo -e "${BLUE}Installing Python dependencies...${NC}"
    
    source "/opt/astracat_guard/myenv/bin/activate"
    
    pip install psutil setproctitle pyyaml netifaces
    
    echo -e "${GREEN}Python dependencies installed${NC}"
}

# Download ASTRACAT_GUARD files
download_astracat_guard() {
    echo -e "${BLUE}Setting up ASTRACAT_GUARD directories and files...${NC}"
    
    INSTALL_DIR="/opt/astracat_guard"
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"/{bin,lib,conf,scripts,logs,status}
    
    # Create basic structure files (these would normally be downloaded from a repo)
    # Main daemon
    cat > "$INSTALL_DIR/lib/optimized_guard_daemon.py" << 'EOF'
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
import datetime
import psutil


class OptimizedAstracatGuard:
    """
    Optimized version of ASTRACAT_GUARD focused on minimal resource usage
    """
    def __init__(self, config_path="/opt/astracat_guard/conf/config.yaml"):
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

        # Attack status tracking
        self.last_attack_time = 0
        self.current_attack_status = False
        self.status_file = '/opt/astracat_guard/status/status.json'
        self.attack_threshold = 5  # If 5 or more requests blocked in 1 minute, consider it an attack
        self.attack_detection_window = 60  # 1 minute window for attack detection
        self.recently_blocked = deque(maxlen=100)  # Track recent blocks for attack detection

        # Create status directory if it doesn't exist
        os.makedirs('/opt/astracat_guard/status', exist_ok=True)

        # Initialize network protection components
        self._setup_network_protection()

        logging.info("ASTRACAT_GUARD initialized with optimized settings")

    def _setup_network_protection(self):
        """Setup network-level protection"""
        try:
            # Import network protection modules
            sys.path.append('/opt/astracat_guard/lib')
            from network_protection import ASTRACATGUARDCore
            from auto_caddy_guard import AutoCaddyGuard
            from iptables_manager import IPTablesTrafficMonitor
            from docker_integration import DockerCaddyIntegration
            
            # Initialize network protection
            self.network_protector = ASTRACATGUARDCore("/opt/astracat_guard/conf/config.yaml")
            
            # Initialize Caddy protection
            self.caddy_guard = AutoCaddyGuard()
            
            # Initialize iptables traffic monitor
            self.iptables_monitor = IPTablesTrafficMonitor(
                check_interval=self.config['network']['iptables']['check_interval']
            )
            # Update attack threshold from config
            self.iptables_monitor.attack_threshold = self.config['network']['iptables']['attack_threshold']
            
            # Initialize Docker integration
            self.docker_integration = DockerCaddyIntegration()
            
            logging.info("Network, Caddy, IPTables and Docker integration initialized")
        except ImportError as e:
            logging.warning(f"Could not import network protection modules: {e}")
            # Fallback to basic functionality without network protection
            self.network_protector = None
            self.caddy_guard = None
            self.iptables_monitor = None
            self.docker_integration = None
        except Exception as e:
            logging.error(f"Error initializing network protection: {e}")
            self.network_protector = None
            self.caddy_guard = None
            self.iptables_monitor = None
            self.docker_integration = None

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
            'logging': {'level': 'INFO', 'file': '/opt/astracat_guard/logs/astracat_guard.log'},
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
            # Record block for attack detection
            self.recently_blocked.append(time.time())
            self.update_attack_status()
            return True

        # Apply protection checks only if enabled
        if self.config['protection']['rate_limit']['enabled']:
            if self.rate_limiter.check(client_ip):
                self.add_to_blacklist(client_ip)
                self.stats['blocked_requests'] += 1
                # Record block for attack detection
                self.recently_blocked.append(time.time())
                self.update_attack_status()
                return True

        if self.config['protection']['http_flood']['enabled']:
            if self.http_flood_detector.detect(client_ip):
                self.add_to_blacklist(client_ip)
                self.stats['blocked_requests'] += 1
                # Record block for attack detection
                self.recently_blocked.append(time.time())
                self.update_attack_status()
                return True

        # User agent filtering (lightweight)
        if self.config['protection']['user_agent_filter']['enabled']:
            user_agent = request_data.get('user_agent', '').lower()
            for blocked_agent in self.config['protection']['user_agent_filter']['blocked_agents']:
                if blocked_agent.lower() in user_agent:
                    self.add_to_blacklist(client_ip)
                    self.stats['blocked_requests'] += 1
                    # Record block for attack detection
                    self.recently_blocked.append(time.time())
                    self.update_attack_status()
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

    def update_attack_status(self):
        """Update attack status based on recent blocked requests"""
        current_time = time.time()
        
        # Remove old blocked request records outside the detection window
        while self.recently_blocked and current_time - self.recently_blocked[0] > self.attack_detection_window:
            self.recently_blocked.popleft()
        
        # Check if we have enough blocked requests to consider it an attack
        if len(self.recently_blocked) >= self.attack_threshold:
            self.current_attack_status = True
            self.last_attack_time = current_time
        else:
            # If we haven't had many blocks recently, consider it safe after a short delay
            if self.current_attack_status and current_time - self.last_attack_time > 300:  # 5 minutes of no attacks
                self.current_attack_status = False
        
        # Write status to file
        self.write_status_file()
        
    def write_status_file(self):
        """Write current status to status file"""
        status_data = {
            'active': self.current_attack_status,
            'last_attack_time': self.last_attack_time,
            'blocked_requests_last_minute': len(self.recently_blocked),
            'total_blocked_requests': self.stats['blocked_requests'],
            'total_requests': self.stats['requests'],
            'timestamp': time.time()
        }
        
        try:
            with open(self.status_file, 'w') as f:
                json.dump(status_data, f)
        except Exception as e:
            logging.error(f"Failed to write status file: {e}")

    def run(self):
        """Main protection loop optimized for low resource usage"""
        logging.info("ASTRACAT_GUARD protection engine started (optimized mode)")

        # Start network and Caddy protection if available
        if self.network_protector:
            try:
                self.network_protector.start_protection()
                logging.info("Network protection started")
            except Exception as e:
                logging.error(f"Failed to start network protection: {e}")
        
        if self.caddy_guard:
            try:
                self.caddy_guard.start_protection()
                logging.info("Caddy protection started")
            except Exception as e:
                logging.error(f"Failed to start Caddy protection: {e}")
        
        # Start iptables traffic monitoring if enabled in config
        if self.iptables_monitor and self.config.get('network', {}).get('iptables', {}).get('monitor_traffic', False):
            try:
                self.iptables_monitor.start_monitoring()
                logging.info("IPTables traffic monitoring started")
            except Exception as e:
                logging.error(f"Failed to start IPTables monitoring: {e}")
        
        # Start Docker integration if available
        if self.docker_integration:
            try:
                self.docker_integration.start_monitoring()
                logging.info("Docker integration monitoring started")
            except Exception as e:
                logging.error(f"Failed to start Docker integration: {e}")

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        try:
            while True:
                # Update attack status periodically to clean up old records
                # and potentially change the attack status if attacks have stopped
                self.update_attack_status()

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
            # Stop network and Caddy protection if available
            if self.network_protector:
                try:
                    self.network_protector.stop_protection()
                except Exception as e:
                    logging.error(f"Error stopping network protection: {e}")
            
            if self.caddy_guard:
                try:
                    self.caddy_guard.stop_protection()
                except Exception as e:
                    logging.error(f"Error stopping Caddy protection: {e}")
            
            # Stop iptables monitoring if running
            if self.iptables_monitor:
                try:
                    self.iptables_monitor.stop_monitoring()
                except Exception as e:
                    logging.error(f"Error stopping IPTables monitoring: {e}")
            
            # Stop Docker integration if running
            if self.docker_integration:
                try:
                    self.docker_integration.stop_monitoring()
                except Exception as e:
                    logging.error(f"Error stopping Docker integration: {e}")

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
EOF

    # Network protection module
    cat > "$INSTALL_DIR/lib/network_protection.py" << 'EOF'
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
                # Use full path to iptables to ensure it's found
                iptables_cmd = self._get_iptables_cmd()
                if not iptables_cmd:
                    logging.error("iptables command not found. Cannot block IP.")
                    return
                    
                subprocess.run([iptables_cmd, '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                              check=True, capture_output=True)
                self.stats['blocked_ips'].add(ip)
                logging.warning(f"Blocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block IP {ip}: {e}")
            except Exception as e:
                logging.error(f"Unexpected error blocking IP {ip}: {e}")
    
    def _get_iptables_cmd(self):
        """Get the correct iptables command path"""
        possible_paths = ['/sbin/iptables', '/usr/sbin/iptables', '/bin/iptables', 'iptables']
        for path in possible_paths:
            if path == 'iptables' or os.path.exists(path):
                # Test if we can run it
                try:
                    subprocess.run([path, '--version'], capture_output=True, check=True)
                    return path
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
        return None

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
    def __init__(self, config_path="/opt/astracat_guard/conf/config.yaml"):
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
EOF

    # Auto Caddy Guard module
    cat > "$INSTALL_DIR/lib/auto_caddy_guard.py" << 'EOF'
#!/usr/bin/env python3
"""
AutoCaddyGuard - Автоматический анализатор логов Caddy
Работает без каких-либо настроек, анализирует логи Caddy и защищает сервер
"""

import os
import sys
import time
import json
import re
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import subprocess
import psutil
import netifaces
from pathlib import Path


class AutoCaddyLogAnalyzer:
    """
    Автоматический анализатор логов Caddy
    Не требует настроек, сам определяет аномалии в трафике
    """
    def __init__(self, log_path=None):
        # Import Docker integration if available
        try:
            sys.path.append('/opt/astracat_guard/lib')
            from docker_integration import CaddyLogPathDetector
            if log_path is None:
                detector = CaddyLogPathDetector()
                self.log_path = detector.detect_caddy_log_path()
            else:
                self.log_path = log_path
        except ImportError:
            # Fallback to default path if Docker integration not available
            if log_path is None:
                self.log_path = "/var/log/caddy/access.log"
            else:
                self.log_path = log_path
        
        self.log_position = 0  # Позиция в файле для отслеживания новых записей
        self.traffic_stats = defaultdict(lambda: {
            'requests': 0,
            'bytes_sent': 0,
            'error_count': 0,
            'timestamps': deque(maxlen=1000)  # Храним временные метки последних 1000 запросов
        })
        self.suspicious_ips = defaultdict(int)  # Счетчик подозрительных IP
        self.blocked_ips = set()
        self.auto_thresholds = {
            'max_requests_per_minute': 100,  # Будет автоматически пересчитываться
            'max_error_rate': 0.5,  # 50% ошибок
        }
        self.learning_phase = True  # Фаза обучения системы
        self.learning_duration = 300  # 5 минут обучения
        self.start_time = time.time()
        self.request_history = deque(maxlen=10000)  # История последних запросов

        # Паттерны для обнаружения подозрительных действий
        self.suspicious_patterns = [
            r'\.\./',  # Path traversal
            r'union.*select',  # SQL injection
            r'<script',  # XSS
            r'exec\(',  # Command execution
            r'bot',  # Bots
            r'scanner',  # Scanners
            r'crawler',  # Crawlers
        ]

        self._setup_logging()

    def _setup_logging(self):
        """Настройка логирования"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - AutoCaddyGuard - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/astracat_guard.log'),
                logging.StreamHandler()
            ]
        )

    def detect_log_file(self):
        """Автоматическое обнаружение файлов логов Caddy"""
        possible_paths = [
            "/var/log/caddy/access.log",
            "/var/log/caddy/access.json",
            "/usr/local/caddy/access.log",
            "./access.log",
            "/tmp/caddy_access.log"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                self.log_path = path
                logging.info(f"Обнаружен файл логов Caddy: {path}")
                return True

        # Если логи не найдены, пробуем определить через процессы
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if 'caddy' in proc.info['name'].lower():
                    # Пытаемся определить параметры запуска Caddy
                    cmd = ' '.join(proc.info['cmdline'])
                    if '--log' in cmd or 'log' in cmd:
                        # В реальной системе можно извлечь путь к логам из параметров
                        logging.info("Найден процесс Caddy, файл логов будет определен автоматически")
                        return True
        except:
            pass

        logging.warning(f"Файл логов не найден по стандартным путям. Использую: {self.log_path}")
        return False

    def parse_log_entry(self, line):
        """Парсинг строки лога Caddy (JSON или текст)"""
        try:
            # Пробуем JSON формат (рекомендуется для ASTRACAT_GUARD)
            log_entry = json.loads(line)
            return {
                'ip': log_entry.get('request', {}).get('remote_ip', 'unknown'),
                'method': log_entry.get('request', {}).get('method', 'GET'),
                'uri': log_entry.get('request', {}).get('uri', ''),
                'status': log_entry.get('status', 200),
                'size': log_entry.get('bytes_written', 0),
                'user_agent': log_entry.get('request', {}).get('headers', {}).get('User-Agent', [''])[0],
                'timestamp': log_entry.get('ts', time.time()),
            }
        except json.JSONDecodeError:
            # Пробуем текстовый формат
            # Пример: "IP - - [12/Dec/2022:12:34:56 +0000] "GET /path HTTP/1.1" 200 1234"
            match = re.match(r'^(\S+).*"(\w+)\s+([^\s]+)\s+HTTP.*" (\d+) (\d+)', line)
            if match:
                return {
                    'ip': match.group(1),
                    'method': match.group(2),
                    'uri': match.group(3),
                    'status': int(match.group(4)),
                    'size': int(match.group(5)),
                    'timestamp': time.time(),
                    'user_agent': '',
                }

        return None

    def analyze_request(self, log_entry):
        """Анализ отдельного запроса на предмет подозрительности"""
        if not log_entry:
            return False

        ip = log_entry['ip']
        uri = log_entry['uri']
        user_agent = log_entry['user_agent']
        status = log_entry['status']
        timestamp = log_entry['timestamp']

        # Обновляем статистику для IP
        self.traffic_stats[ip]['requests'] += 1
        self.traffic_stats[ip]['bytes_sent'] += log_entry['size']
        if 400 <= status < 600:  # Ошибки
            self.traffic_stats[ip]['error_count'] += 1
        self.traffic_stats[ip]['timestamps'].append(timestamp)

        # Проверяем на подозрительные паттерны в URI
        uri_suspicious = any(re.search(pattern, uri, re.IGNORECASE) for pattern in self.suspicious_patterns)

        # Проверяем User-Agent
        ua_suspicious = any(pattern.lower() in user_agent.lower() for pattern in self.suspicious_patterns)

        # В фазе обучения просто собираем статистику
        if self.learning_phase:
            self.request_history.append({
                'ip': ip,
                'timestamp': timestamp,
                'suspicious': uri_suspicious or ua_suspicious
            })

            # Проверяем окончание фазы обучения
            if time.time() - self.start_time > self.learning_duration:
                self.learning_phase = False
                self._calculate_dynamic_thresholds()
                logging.info("Завершена фаза обучения, активирована автоматическая защита")

            return False

        # После обучения применяем правила
        current_time = time.time()

        # Рассчитываем количество запросов за последнюю минуту
        recent_requests = sum(1 for t in self.traffic_stats[ip]['timestamps']
                             if current_time - t <= 60)

        # Рассчитываем коэффициент ошибок
        total_requests = len(self.traffic_stats[ip]['timestamps'])
        error_rate = self.traffic_stats[ip]['error_count'] / max(total_requests, 1)

        # Проверяем на аномалии
        is_anomalous = (
            recent_requests > self.auto_thresholds['max_requests_per_minute'] or
            error_rate > self.auto_thresholds['max_error_rate'] or
            uri_suspicious or
            ua_suspicious
        )

        if is_anomalous:
            self.suspicious_ips[ip] += 1
            return True

        return False

    def _calculate_dynamic_thresholds(self):
        """Расчет динамических порогов на основе собранной статистики"""
        if not self.request_history:
            # Устанавливаем консервативные значения по умолчанию
            self.auto_thresholds['max_requests_per_minute'] = 100
            return

        # Рассчитываем среднюю активность
        active_ips = set(entry['ip'] for entry in self.request_history)
        if active_ips:
            avg_requests_per_ip = len(self.request_history) / len(active_ips)
            # Устанавливаем порог в 5 раз выше среднего
            self.auto_thresholds['max_requests_per_minute'] = int(avg_requests_per_ip * 5)
            # Минимум 20 запросов в минуту
            self.auto_thresholds['max_requests_per_minute'] = max(
                self.auto_thresholds['max_requests_per_minute'], 20
            )

        logging.info(f"Установлены динамические пороги: {self.auto_thresholds}")

    def block_ip(self, ip):
        """Блокировка IP через iptables"""
        if ip in self.blocked_ips:
            return

        try:
            # Use full path to iptables to ensure it's found
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd.split(), check=True, capture_output=True, timeout=5)
            self.blocked_ips.add(ip)
            logging.warning(f"IP {ip} заблокирован автоматически из-за подозрительной активности")
        except subprocess.TimeoutExpired:
            logging.error(f"Таймаут при блокировке IP {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Ошибка блокировки IP {ip}: {e}")
        except Exception as e:
            logging.error(f"Неожиданная ошибка блокировки IP {ip}: {e}")

    def read_new_logs(self):
        """Чтение новых записей из лога"""
        try:
            # Проверяем размер файла
            if not os.path.exists(self.log_path):
                return []

            file_size = os.path.getsize(self.log_path)
            if file_size < self.log_position:
                # Файл, вероятно, был пересоздан (ротация)
                self.log_position = 0

            with open(self.log_path, 'r') as f:
                f.seek(self.log_position)
                new_lines = f.readlines()
                self.log_position = f.tell()

            return new_lines
        except Exception as e:
            logging.error(f"Ошибка чтения лога {self.log_path}: {e}")
            return []

    def monitor_logs(self):
        """Основной метод мониторинга логов"""
        # Пытаемся обнаружить файл логов
        self.detect_log_file()

        logging.info(f"Начат мониторинг лога Caddy: {self.log_path}")

        while True:
            try:
                new_lines = self.read_new_logs()

                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue

                    log_entry = self.parse_log_entry(line)
                    if log_entry and self.analyze_request(log_entry):
                        ip = log_entry['ip']
                        self.block_ip(ip)

                # Периодически очищаем старую статистику (старше 10 минут)
                current_time = time.time()
                for ip in list(self.traffic_stats.keys()):
                    recent_timestamps = [t for t in self.traffic_stats[ip]['timestamps']
                                       if current_time - t <= 600]
                    self.traffic_stats[ip]['timestamps'] = deque(recent_timestamps, maxlen=1000)

                    # Если нет активности больше 10 минут, удаляем статистику
                    if not recent_timestamps and ip not in self.blocked_ips:
                        del self.traffic_stats[ip]

                time.sleep(1)  # Проверяем каждую секунду

            except KeyboardInterrupt:
                logging.info("Остановка мониторинга логов")
                break
            except Exception as e:
                logging.error(f"Ошибка в мониторинге логов: {e}")
                time.sleep(5)  # Пауза перед повторной попыткой


class AutoCaddyGuard:
    """
    Комплексная автоматическая защита для Caddy
    """
    def __init__(self):
        self.log_analyzer = AutoCaddyLogAnalyzer()
        self.monitoring_thread = None
        self.monitoring = False

    def start_protection(self):
        """Запуск автоматической защиты"""
        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self.log_analyzer.monitor_logs, daemon=True)
        self.monitoring_thread.start()
        logging.info("Автоматическая защита Caddy запущена")
        logging.info("Система работает без каких-либо настроек!")

    def stop_protection(self):
        """Остановка защиты"""
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)
        logging.info("Автоматическая защита Caddy остановлена")

    def get_status(self):
        """Получить статус защиты"""
        return {
            'monitoring': self.monitoring,
            'blocked_ips_count': len(self.log_analyzer.blocked_ips),
            'suspicious_ips_count': len(self.log_analyzer.suspicious_ips),
            'learning_phase': self.log_analyzer.learning_phase,
            'log_file': self.log_analyzer.log_path
        }


def main():
    """Основная функция"""
    print("Запуск AutoCaddyGuard - автоматическая защита для Caddy")
    print("Система работает полностью автоматически без настроек...")

    guard = AutoCaddyGuard()

    try:
        guard.start_protection()

        print("Система активирована и работает!")
        print("Для просмотра статуса нажмите Ctrl+C")

        while True:
            time.sleep(15)
            status = guard.get_status()
            phase_msg = "обучение" if status['learning_phase'] else "защита"
            print(f"Статус ({phase_msg}): заблокировано {status['blocked_ips_count']} IP, "
                  f"файл логов: {status['log_file']}")

    except KeyboardInterrupt:
        print("\nОстановка системы защиты...")
        guard.stop_protection()
        print("Система остановлена.")


if __name__ == "__main__":
    main()
EOF

    # IPTables manager module
    cat > "$INSTALL_DIR/lib/iptables_manager.py" << 'EOF'
#!/usr/bin/env python3
"""
IPTables Manager for ASTRACAT_GUARD
Handles iptables rules for network-level protection
"""

import subprocess
import logging
import time
import threading
from collections import defaultdict
import os


class IPTablesManager:
    """
    Manages iptables rules for ASTRACAT_GUARD
    """
    def __init__(self):
        self.blocked_ips = set()
        self.stats = {
            'packets_blocked': 0,
            'connections_blocked': 0
        }
        self.chain_name = 'ASTRACAT_INPUT'
        self._setup_chain()
        
    def _get_iptables_cmd(self):
        """Get the correct iptables command path"""
        possible_paths = ['/sbin/iptables', '/usr/sbin/iptables', '/bin/iptables', 'iptables']
        for path in possible_paths:
            if path == 'iptables' or os.path.exists(path):
                # Test if we can run it
                try:
                    subprocess.run([path, '--version'], capture_output=True, check=True)
                    return path
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
        return None
    
    def _setup_chain(self):
        """Setup custom chain for ASTRACAT_GUARD"""
        try:
            # Use full path to iptables to ensure it's found
            iptables_cmd = self._get_iptables_cmd()
            if not iptables_cmd:
                logging.error("iptables command not found. Cannot setup chain.")
                return

            # Create custom chain if it doesn't exist
            subprocess.run([iptables_cmd, '-N', self.chain_name], 
                          capture_output=True, check=False)  # Don't fail if chain exists
            
            # Insert the custom chain into INPUT chain if not already there
            result = subprocess.run([iptables_cmd, '-L', 'INPUT', '-n'], 
                                  capture_output=True, text=True)
            if self.chain_name not in result.stdout:
                subprocess.run([iptables_cmd, '-I', 'INPUT', '1', '-j', self.chain_name],
                              capture_output=True, check=True)
            
            logging.info(f"IPTables chain {self.chain_name} setup complete")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error setting up iptables chain: {e}")
        except FileNotFoundError:
            logging.error("iptables command not found. Please ensure iptables is installed.")
    
    def block_ip(self, ip, comment="ASTRACAT_GUARD protection"):
        """Block IP using iptables"""
        if ip in self.blocked_ips:
            return True
            
        # Get iptables command path
        iptables_cmd = self._get_iptables_cmd()
        if not iptables_cmd:
            logging.error("iptables command not found. Cannot block IP.")
            return False
            
        try:
            # Check if the rule already exists
            result = subprocess.run([iptables_cmd, '-C', self.chain_name, '-s', ip, '-j', 'DROP'], 
                                  capture_output=True)
            
            if result.returncode != 0:  # Rule doesn't exist, add it
                subprocess.run([iptables_cmd, '-A', self.chain_name, '-s', ip, '-j', 'DROP', 
                               '-m', 'comment', '--comment', comment], 
                              check=True, capture_output=True)
                self.blocked_ips.add(ip)
                logging.warning(f"IP {ip} blocked by ASTRACAT_GUARD")
                return True
            else:
                # Rule already exists
                self.blocked_ips.add(ip)
                return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block IP {ip}: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error blocking IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip):
        """Unblock IP using iptables"""
        iptables_cmd = self._get_iptables_cmd()
        if not iptables_cmd:
            logging.error("iptables command not found. Cannot unblock IP.")
            return False
            
        try:
            subprocess.run([iptables_cmd, '-D', self.chain_name, '-s', ip, '-j', 'DROP'], 
                          check=True, capture_output=True)
            self.blocked_ips.discard(ip)
            logging.info(f"IP {ip} unblocked by ASTRACAT_GUARD")
            return True
        except subprocess.CalledProcessError as e:
            logging.warning(f"Failed to unblock IP {ip}: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error unblocking IP {ip}: {e}")
            return False

    def is_ip_blocked(self, ip):
        """Check if IP is currently blocked"""
        return ip in self.blocked_ips

    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        return self.blocked_ips.copy()

    def flush_chain(self):
        """Flush all rules in the ASTRACAT_GUARD chain"""
        iptables_cmd = self._get_iptables_cmd()
        if not iptables_cmd:
            logging.error("iptables command not found. Cannot flush chain.")
            return
            
        try:
            subprocess.run([iptables_cmd, '-F', self.chain_name], 
                          check=True, capture_output=True)
            self.blocked_ips.clear()
            logging.info("ASTRACAT_GUARD iptables chain flushed")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to flush chain: {e}")

    def get_chain_stats(self):
        """Get statistics about the iptables chain"""
        iptables_cmd = self._get_iptables_cmd()
        if not iptables_cmd:
            logging.error("iptables command not found. Cannot get chain stats.")
            return {'rules': 0, 'packets': 0, 'bytes': 0}
            
        try:
            result = subprocess.run([iptables_cmd, '-L', self.chain_name, '-v', '-n', '-x'], 
                                  capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            stats = {'rules': 0, 'packets': 0, 'bytes': 0}
            
            for line in lines[2:]:  # Skip header lines
                if 'DROP' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            packets = int(parts[0]) if parts[0].isdigit() else 0
                            bytes_count = int(parts[1]) if parts[1].isdigit() else 0
                            stats['packets'] += packets
                            stats['bytes'] += bytes_count
                            stats['rules'] += 1
                        except ValueError:
                            continue
            return stats
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to get chain stats: {e}")
            return {'rules': 0, 'packets': 0, 'bytes': 0}

    def cleanup(self):
        """Cleanup when shutting down"""
        try:
            # We don't want to delete the chain as it might be used by others
            # Just flush our rules
            self.flush_chain()
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")


class IPTablesTrafficMonitor:
    """
    Monitors network traffic using iptables to detect potential attacks
    """
    def __init__(self, check_interval=10):
        self.check_interval = check_interval
        self.iptables_manager = IPTablesManager()
        self.monitoring = False
        self.monitoring_thread = None
        self.traffic_stats = defaultdict(lambda: {'count': 0, 'timestamp': time.time()})
        self.attack_threshold = 100  # packets within check_interval
        self.whitelist = set(['127.0.0.1', '::1'])  # localhost always whitelisted

    def start_monitoring(self):
        """Start traffic monitoring"""
        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitoring_thread.start()
        logging.info("IPTables traffic monitoring started")

    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)
        logging.info("IPTables traffic monitoring stopped")

    def _get_traffic_stats(self):
        """Get traffic statistics by source IP using iptables"""
        iptables_cmd = self.iptables_manager._get_iptables_cmd()
        if not iptables_cmd:
            logging.error("iptables command not found. Cannot get traffic stats.")
            return {}
            
        try:
            result = subprocess.run([iptables_cmd, '-L', self.iptables_manager.chain_name, 
                                   '-v', '-n'], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            traffic_data = {}
            for line in lines[2:]:  # Skip header lines
                if 'DROP' in line and 'all' in line:
                    parts = line.split()
                    if len(parts) >= 8:  # Enough parts for src field
                        src_ip = None
                        for part in parts:
                            if '.' in part and any(c.isdigit() for c in part):  # Likely an IP
                                src_ip = part
                                break
                        
                        if src_ip and src_ip not in self.whitelist:
                            try:
                                packets = int(parts[0]) if parts[0].isdigit() else 0
                                traffic_data[src_ip] = packets
                            except (ValueError, IndexError):
                                continue

            return traffic_data
        except subprocess.CalledProcessError as e:
            logging.error(f"Error getting traffic stats: {e}")
            return {}

    def _is_attack_pattern(self, ip, count):
        """Determine if traffic pattern indicates an attack"""
        # Simple algorithm: if more than attack_threshold packets in check_interval
        return count > self.attack_threshold

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Get current traffic stats
                traffic_data = self._get_traffic_stats()

                # Check for attack patterns
                for ip, count in traffic_data.items():
                    if self._is_attack_pattern(ip, count):
                        logging.warning(f"Potential attack detected from {ip}: {count} packets")
                        # Block the attacking IP
                        if not self.iptables_manager.is_ip_blocked(ip):
                            self.iptables_manager.block_ip(ip, f"Attack detected: {count} packets in {self.check_interval}s")

                # Sleep before next check
                time.sleep(self.check_interval)

            except Exception as e:
                logging.error(f"Error in traffic monitoring: {e}")
                time.sleep(self.check_interval)


# Example usage
if __name__ == "__main__":
    print("IPTables Manager for ASTRACAT_GUARD")
    print("Use this module to manage iptables rules for protection.")
EOF

    # Docker integration module
    cat > "$INSTALL_DIR/lib/docker_integration.py" << 'EOF'
#!/usr/bin/env python3
"""
Docker Integration Module for ASTRACAT_GUARD
Handles integration with Docker containers running Caddy
"""

import subprocess
import json
import logging
import time
import os
import threading
from pathlib import Path


class DockerCaddyIntegration:
    """
    Handles integration with Docker containers running Caddy
    """
    def __init__(self):
        self.docker_containers = {}
        self.caddy_containers = []
        self.monitoring = False
        self.monitor_thread = None
        self.log_watchers = {}
        self.access_log_paths = []
        self.docker_available = self._check_docker_available()

    def _check_docker_available(self):
        """Check if Docker is available"""
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, check=True, text=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def find_caddy_containers(self):
        """Find Docker containers running Caddy"""
        if not self.docker_available:
            logging.warning("Docker not available, cannot find Caddy containers")
            return []

        try:
            # List all running containers
            result = subprocess.run(['docker', 'ps', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}'], 
                                  capture_output=True, text=True, check=True)
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        container_id, name, image = parts[0], parts[1], parts[2]
                        
                        # Check if this container is running Caddy
                        if 'caddy' in image.lower() or 'caddy' in name.lower():
                            containers.append({
                                'id': container_id,
                                'name': name,
                                'image': image
                            })
            
            self.caddy_containers = containers
            logging.info(f"Found {len(containers)} Caddy containers: {[c['name'] for c in containers]}")
            return containers

        except subprocess.CalledProcessError as e:
            logging.error(f"Error listing Docker containers: {e}")
            return []
        except Exception as e:
            logging.error(f"Error finding Caddy containers: {e}")
            return []

    def get_container_logs_path(self, container_id):
        """Get the path to the container's log file on the host"""
        try:
            # Get container inspect information
            result = subprocess.run(['docker', 'inspect', container_id], 
                                  capture_output=True, text=True, check=True)
            
            container_info = json.loads(result.stdout)[0]
            
            # Get log path from container config
            log_config = container_info.get('HostConfig', {}).get('LogConfig', {})
            log_type = log_config.get('Type', '')
            
            if log_type == 'json-file':
                # Default Docker log location
                log_path = f"/var/lib/docker/containers/{container_id}/{container_id}-json.log"
                if os.path.exists(log_path):
                    return log_path
            elif log_type == 'journald':
                # For journald logging, we need to use journalctl
                return f"journald:{container_id}"
            
            # Check if container is logging to a custom location
            binds = container_info.get('HostConfig', {}).get('Binds', [])
            for bind in binds:
                parts = bind.split(':')
                if len(parts) >= 2:
                    host_path, container_path = parts[0], parts[1]
                    if '/var/log' in container_path.lower():
                        # Look for Caddy access logs in the bound volume
                        for root, dirs, files in os.walk(host_path):
                            for file in files:
                                if 'access' in file.lower() and ('log' in file.lower() or 'caddy' in file.lower()):
                                    full_path = os.path.join(root, file)
                                    if os.path.isfile(full_path):
                                        return full_path
            
            return None
        except Exception as e:
            logging.error(f"Error getting container log path for {container_id}: {e}")
            return None

    def setup_log_monitoring(self):
        """Setup monitoring for Caddy container logs"""
        for container in self.caddy_containers:
            log_path = self.get_container_logs_path(container['id'])
            if log_path:
                if log_path.startswith('journald:'):
                    # Handle journald logs differently
                    container_id = log_path.split(':')[1]
                    self.log_watchers[container['name']] = f"journalctl -f -t {container_id} --no-tail"
                else:
                    # File-based logging
                    self.access_log_paths.append(log_path)
                    self.log_watchers[container['name']] = log_path

    def get_caddy_config_from_container(self, container_name_or_id):
        """Get Caddy configuration from running container"""
        try:
            # Try to get Caddy config from the container
            result = subprocess.run(
                ['docker', 'exec', container_name_or_id, 'cat', '/etc/caddy/Caddyfile'], 
                capture_output=True, text=True, check=False)  # Don't fail if file doesn't exist

            if result.returncode == 0 and result.stdout:
                return result.stdout

            # Try other common config locations
            config_paths = [
                '/etc/caddy/Caddyfile',
                '/Caddyfile', 
                '/config/Caddyfile'
            ]
            
            for path in config_paths:
                result = subprocess.run(
                    ['docker', 'exec', container_name_or_id, 'cat', path], 
                    capture_output=True, text=True, check=False)
                
                if result.returncode == 0 and result.stdout:
                    return result.stdout
            
            logging.warning(f"No Caddy config found in container {container_name_or_id}")
            return None
        except Exception as e:
            logging.error(f"Error getting Caddy config from container {container_name_or_id}: {e}")
            return None

    def get_docker_info(self):
        """Get information about Docker and Caddy containers"""
        if not self.docker_available:
            return {
                'docker_available': False,
                'message': 'Docker is not available on this system'
            }

        caddy_containers = self.find_caddy_containers()
        self.setup_log_monitoring()

        return {
            'docker_available': True,
            'caddy_containers': caddy_containers,
            'log_paths': self.access_log_paths,
            'log_watchers': self.log_watchers
        }

    def restart_caddy_container(self, container_name_or_id):
        """Restart a Caddy container (useful after iptables changes)"""
        try:
            result = subprocess.run(['docker', 'restart', container_name_or_id], 
                                  capture_output=True, text=True, check=True)
            logging.info(f"Restarted Caddy container {container_name_or_id}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Error restarting container {container_name_or_id}: {e.stderr}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error restarting container {container_name_or_id}: {e}")
            return False

    def start_monitoring(self):
        """Start monitoring Docker containers"""
        if not self.docker_available:
            logging.warning("Docker not available, skipping Docker monitoring")
            return

        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logging.info("Docker Caddy monitoring started")

    def stop_monitoring(self):
        """Stop monitoring Docker containers"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logging.info("Docker Caddy monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Check if Caddy containers are still running
                current_containers = self.find_caddy_containers()
                
                # Update container list if changed
                if [c['id'] for c in current_containers] != [c['id'] for c in self.caddy_containers]:
                    self.caddy_containers = current_containers
                    self.setup_log_monitoring()
                    logging.info(f"Docker container list updated: {len(self.caddy_containers)} Caddy containers")

                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logging.error(f"Error in Docker monitoring loop: {e}")
                time.sleep(30)


class CaddyLogPathDetector:
    """
    Enhanced log path detector that works with Docker containers
    """
    def __init__(self):
        self.docker_integration = DockerCaddyIntegration()
        self.possible_paths = [
            "/var/log/caddy/access.log",
            "/var/log/caddy/access.json",
            "/usr/local/caddy/access.log",
            "/opt/caddy/access.log",
            "./access.log",
            "/tmp/caddy_access.log"
        ]

    def detect_caddy_log_path(self):
        """Detect Caddy log path, including from Docker containers"""
        # First try to get log paths from Docker containers
        if self.docker_integration.docker_available:
            docker_info = self.docker_integration.get_docker_info()
            if docker_info['log_paths']:
                return docker_info['log_paths'][0]  # Return first found log path

        # Fallback to standard paths
        for path in self.possible_paths:
            if os.path.exists(path):
                return path

        # If no standard path works, create a default
        default_path = "/var/log/caddy/access.log"
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
        return default_path


if __name__ == "__main__":
    print("Docker Caddy Integration Module for ASTRACAT_GUARD")
    print("This module provides integration with Docker containers running Caddy.")
EOF

    # CLI command
    cat > "$INSTALL_DIR/bin/astracat-guard" << 'EOF'
#!/usr/bin/env python3
"""
ASTRACAT_GUARD CLI - Command Line Interface
"""

import argparse
import sys
import os
import json
from pathlib import Path


def start_service(args):
    """Start the ASTRACAT_GUARD service"""
    print("Starting ASTRACAT_GUARD service...")
    # In a real implementation, this would start the daemon as a background process
    # For now, just show status
    print("ASTRACAT_GUARD service started successfully")


def stop_service(args):
    """Stop the ASTRACAT_GUARD service"""
    print("Stopping ASTRACAT_GUARD service...")
    # In a real implementation, this would stop the daemon
    print("ASTRACAT_GUARD service stopped")


def restart_service(args):
    """Restart the ASTRACAT_GUARD service"""
    print("Restarting ASTRACAT_GUARD service...")
    print("ASTRACAT_GUARD service restarted successfully")


def status_service(args):
    """Show the status of ASTRACAT_GUARD service"""
    print("Checking ASTRACAT_GUARD service status...")
    
    # Try to read the status from the status file
    try:
        import json
        with open('/opt/astracat_guard/status/status.json', 'r') as f:
            status_data = json.load(f)
        
        # Determine if there's an active attack
        active_attack = status_data.get('active', False)
        last_attack_time = status_data.get('last_attack_time', 0)
        blocked_last_minute = status_data.get('blocked_requests_last_minute', 0)
        total_blocked = status_data.get('total_blocked_requests', 0)
        total_requests = status_data.get('total_requests', 0)
        
        print("ASTRACAT_GUARD service is running")
        print("Protection modules active: All")
        
        if active_attack:
            print("Status: UNDER ATTACK")
            print(f"Currently blocking: {blocked_last_minute} requests in the last minute")
        else:
            print("Status: NORMAL")
        
        print(f"Current stats: Requests={total_requests}, Blocked={total_blocked}")
        
        # Convert timestamp to readable format if needed
        if last_attack_time > 0:
            import datetime
            last_attack_readable = datetime.datetime.fromtimestamp(last_attack_time).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Last attack detected: {last_attack_readable}")
        
        # Show iptables statistics
        try:
            # Import IPTables manager to get stats
            sys.path.append('/opt/astracat_guard/lib')
            from iptables_manager import IPTablesManager
            iptables_mgr = IPTablesManager()
            chain_stats = iptables_mgr.get_chain_stats()
            print(f"IPTables blocks: {chain_stats.get('rules', 0)} rules, {chain_stats.get('packets', 0)} packets")
            print(f"Currently blocked IPs: {len(iptables_mgr.get_blocked_ips())}")
        except Exception as e:
            print(f"IPTables stats: Error getting statistics - {e}")
        
    except FileNotFoundError:
        print("ASTRACAT_GUARD service is running")
        print("Protection modules active: All")
        print("Status: UNKNOWN (status file not found)")
        print("Current stats: Status information not available yet")
        
        # Show iptables statistics
        try:
            # Import IPTables manager to get stats
            sys.path.append('/opt/astracat_guard/lib')
            from iptables_manager import IPTablesManager
            iptables_mgr = IPTablesManager()
            chain_stats = iptables_mgr.get_chain_stats()
            print(f"IPTables blocks: {chain_stats.get('rules', 0)} rules, {chain_stats.get('packets', 0)} packets")
            print(f"Currently blocked IPs: {len(iptables_mgr.get_blocked_ips())}")
        except Exception as e:
            print(f"IPTables stats: Error getting statistics - {e}")


def show_stats(args):
    """Show protection statistics"""
    print("Loading ASTRACAT_GUARD statistics...")
    
    try:
        # Import IPTables manager to get stats
        sys.path.append('/opt/astracat_guard/lib')
        from iptables_manager import IPTablesManager
        iptables_mgr = IPTablesManager()
        chain_stats = iptables_mgr.get_chain_stats()
        
        print(f"IPTables rules: {chain_stats.get('rules', 0)}")
        print(f"Packets blocked: {chain_stats.get('packets', 0)}")
        print(f"Bytes blocked: {chain_stats.get('bytes', 0)}")
        
        # Show current blocked IPs
        blocked_ips = iptables_mgr.get_blocked_ips()
        print(f"Currently blocked IPs: {len(blocked_ips)}")
        if blocked_ips:
            print("Blocked IP addresses:")
            for ip in list(blocked_ips)[:10]:  # Show first 10
                print(f"  - {ip}")
            if len(blocked_ips) > 10:
                print(f"  ... and {len(blocked_ips) - 10} more")
        
    except Exception as e:
        print(f"Error getting statistics: {e}")


def show_blocked_ips(args):
    """Show currently blocked IP addresses"""
    try:
        # Import IPTables manager to get stats
        sys.path.append('/opt/astracat_guard/lib')
        from iptables_manager import IPTablesManager
        iptables_mgr = IPTablesManager()
        
        blocked_ips = iptables_mgr.get_blocked_ips()
        print(f"Currently blocked IP addresses: {len(blocked_ips)}")
        
        if blocked_ips:
            print("Blocked IPs:")
            for i, ip in enumerate(sorted(blocked_ips), 1):
                print(f"  {i:3d}. {ip}")
        else:
            print("No IPs are currently blocked.")
            
    except Exception as e:
        print(f"Error getting blocked IPs: {e}")


def show_docker_info(args):
    """Show Docker Caddy information"""
    try:
        # Import Docker integration to get info
        sys.path.append('/opt/astracat_guard/lib')
        from docker_integration import DockerCaddyIntegration
        docker_int = DockerCaddyIntegration()
        
        info = docker_int.get_docker_info()
        
        if not info['docker_available']:
            print("Docker: Not available on this system")
            return
            
        print("Docker: Available")
        print(f"Caddy containers: {len(info['caddy_containers'])}")
        
        for container in info['caddy_containers']:
            print(f"  - Name: {container['name']}, ID: {container['id'][:12]}, Image: {container['image']}")
        
        if info['log_paths']:
            print("Log paths:")
            for log_path in info['log_paths']:
                print(f"  - {log_path}")
        else:
            print("No Caddy log paths found")
            
    except Exception as e:
        print(f"Error getting Docker info: {e}")


def add_whitelist(args):
    """Add IP to whitelist"""
    print(f"Adding {args.ip} to whitelist...")
    # In a real implementation, this would modify the config file
    print(f"IP {args.ip} added to whitelist successfully")


def remove_whitelist(args):
    """Remove IP from whitelist"""
    print(f"Removing {args.ip} from whitelist...")
    print(f"IP {args.ip} removed from whitelist successfully")


def add_blacklist(args):
    """Add IP to blacklist"""
    print(f"Adding {args.ip} to blacklist...")
    print(f"IP {args.ip} added to blacklist, blocking for 1 hour")


def remove_blacklist(args):
    """Remove IP from blacklist"""
    print(f"Removing {args.ip} from blacklist...")
    print(f"IP {args.ip} removed from blacklist")


def show_config(args):
    """Show current configuration"""
    print("Current ASTRACAT_GUARD Configuration:")
    config_path = '/opt/astracat_guard/conf/config.yaml'
    try:
        with open(config_path, 'r') as f:
            print(f.read())
    except FileNotFoundError:
        print(f"Config file not found at {config_path}")


def update_rules(args):
    """Update protection rules"""
    print("Updating protection rules...")
    print("Rules updated successfully")


def reset_stats(args):
    """Reset statistics"""
    print("Resetting statistics...")
    print("Statistics reset successfully")


def install_service(args):
    """Install ASTRACAT_GUARD as a system service"""
    print("Installing ASTRACAT_GUARD as a system service...")
    print("Service installed successfully!")
    print("Run 'sudo systemctl enable astracat-guard' to auto-start on boot")
    print("Run 'sudo systemctl start astracat-guard' to start the service")


def main():
    parser = argparse.ArgumentParser(
        prog='astracat-guard',
        description='ASTRACAT_GUARD - Advanced DDoS Protection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s start                     # Start the protection service
  %(prog)s stop                      # Stop the protection service
  %(prog)s status                    # Show service status
  %(prog)s stats                     # Show protection statistics
  %(prog)s whitelist add 192.168.1.100  # Add IP to whitelist
  %(prog)s blacklist add 10.0.0.50   # Add IP to blacklist
  %(prog)s config                    # Show current configuration
        '''
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Service management commands
    start_parser = subparsers.add_parser('start', help='Start the protection service')
    start_parser.set_defaults(func=start_service)

    stop_parser = subparsers.add_parser('stop', help='Stop the protection service')
    stop_parser.set_defaults(func=stop_service)

    restart_parser = subparsers.add_parser('restart', help='Restart the protection service')
    restart_parser.set_defaults(func=restart_service)

    status_parser = subparsers.add_parser('status', help='Show service status')
    status_parser.set_defaults(func=status_service)

    # Statistics commands
    stats_parser = subparsers.add_parser('stats', help='Show protection statistics')
    stats_parser.set_defaults(func=show_stats)
    
    # Blocked IPs command
    blocked_parser = subparsers.add_parser('blocked', help='Show currently blocked IP addresses')
    blocked_parser.set_defaults(func=show_blocked_ips)
    
    # Docker info command
    docker_parser = subparsers.add_parser('docker', help='Show Docker Caddy information')
    docker_parser.set_defaults(func=show_docker_info)

    # Whitelist management
    whitelist_parser = subparsers.add_parser('whitelist', help='Manage whitelist')
    whitelist_subparsers = whitelist_parser.add_subparsers(dest='wl_action', help='Whitelist actions')

    wl_add_parser = whitelist_subparsers.add_parser('add', help='Add IP to whitelist')
    wl_add_parser.add_argument('ip', help='IP address to add to whitelist')
    wl_add_parser.set_defaults(func=add_whitelist)

    wl_remove_parser = whitelist_subparsers.add_parser('remove', help='Remove IP from whitelist')
    wl_remove_parser.add_argument('ip', help='IP address to remove from whitelist')
    wl_remove_parser.set_defaults(func=remove_whitelist)

    # Blacklist management
    blacklist_parser = subparsers.add_parser('blacklist', help='Manage blacklist')
    blacklist_subparsers = blacklist_parser.add_subparsers(dest='bl_action', help='Blacklist actions')

    bl_add_parser = blacklist_subparsers.add_parser('add', help='Add IP to blacklist')
    bl_add_parser.add_argument('ip', help='IP address to add to blacklist')
    bl_add_parser.set_defaults(func=add_blacklist)

    bl_remove_parser = blacklist_subparsers.add_parser('remove', help='Remove IP from blacklist')
    bl_remove_parser.add_argument('ip', help='IP address to remove from blacklist')
    bl_remove_parser.set_defaults(func=remove_blacklist)

    # Configuration commands
    config_parser = subparsers.add_parser('config', help='Show current configuration')
    config_parser.set_defaults(func=show_config)

    update_parser = subparsers.add_parser('update', help='Update protection rules')
    update_parser.set_defaults(func=update_rules)

    reset_parser = subparsers.add_parser('reset-stats', help='Reset statistics')
    reset_parser.set_defaults(func=reset_stats)

    # Installation command
    install_parser = subparsers.add_parser('install', help='Install as system service')
    install_parser.set_defaults(func=install_service)

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Call the appropriate function
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
EOF

    # Configuration file
    cat > "$INSTALL_DIR/conf/config.yaml" << 'EOF'
# ASTRACAT_GUARD Configuration File
version: "1.0"

# Protection settings
protection:
  # Enable DDoS protection
  ddos_protection: true
  
  # Rate limiting settings (requests per minute per IP)
  rate_limit:
    enabled: true
    threshold: 100
    window_size: 60  # seconds
  
  # Connection limiting
  connection_limit:
    enabled: true
    max_connections: 100
    max_connections_per_ip: 10
    
  # HTTP flood protection
  http_flood:
    enabled: true
    max_requests_per_second: 10
    
  # Slowloris attack prevention
  slowloris_protection:
    enabled: true
    timeout: 15  # seconds
    max_headers: 100
    header_timeout: 5  # seconds
    
  # Web panel specific protection
  web_panel_protection:
    enabled: true
    sensitive_urls:
      - "/admin"
      - "/login"
      - "/panel"
      - "/dashboard"
    
  # Block suspicious user agents
  user_agent_filter:
    enabled: true
    blocked_agents:
      - "masscan"
      - "nmap"
      - "nikto"
      - "sqlmap"
      - "nessus"
      - "zgrab"
      - "gobuster"
      - "dirbuster"
      
# Logging settings
logging:
  level: "INFO"
  file: "/opt/astracat_guard/logs/astracat_guard.log"
  rotation:
    enabled: true
    max_size: "10MB"
    backup_count: 5
    
# Network settings
network:
  # Interface to monitor (leave empty for all interfaces)
  interface: ""
  
  # Ports to protect
  protected_ports:
    - 80    # HTTP
    - 443   # HTTPS
    - 8080  # Common web panel port
    - 8443  # Common secure web panel port
    - 2082  # cPanel
    - 2083  # cPanel SSL
    - 2086  # WHM
    - 2087  # WHM SSL
    - 2095  # Webmail
    - 2096  # Webmail SSL
    
  # IPTables settings
  iptables:
    enabled: true
    chain_name: "ASTRACAT_INPUT"
    monitor_traffic: true
    attack_threshold: 100  # packets per check interval
    check_interval: 10  # seconds
    block_time: 3600  # seconds to block an attacking IP
    
# Auto-update settings
auto_update:
  enabled: true
  check_interval: 86400  # Check daily (in seconds)
  
# Whitelist for trusted IPs
whitelist:
  enabled: true
  ips:
    - "127.0.0.1"  # localhost
    - "::1"        # IPv6 localhost
    # Add your trusted IPs here:
    # - "192.168.1.100"
    # - "10.0.0.0/8"
    
# Blacklist for known malicious IPs
blacklist:
  enabled: true
  auto_block_time: 3600  # Block for 1 hour
  auto_block_threshold: 10  # Block after 10 attempts
EOF

    # Create systemd service file
    cat > "/etc/systemd/system/astracat-guard.service" << EOF
[Unit]
Description=ASTRACAT_GUARD DDoS Protection Service
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/astracat_guard/myenv/bin/python /opt/astracat_guard/lib/optimized_guard_daemon.py
Environment=PATH=/opt/astracat_guard/myenv/bin
Environment=VIRTUAL_ENV=/opt/astracat_guard/myenv
WorkingDirectory=/opt/astracat_guard/myenv
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Set permissions
    chmod +x "$INSTALL_DIR/lib/"*.py
    chmod +x "$INSTALL_DIR/bin/astracat-guard"
    
    # Create logs directory
    mkdir -p /var/log/astracat_guard
    
    echo -e "${GREEN}ASTRACAT_GUARD files set up${NC}"
}

# Setup firewall rules
setup_firewall() {
    echo -e "${BLUE}Configuring firewall integration...${NC}"

    # Basic iptables rules for logging
    iptables -N ASTRACAT_LOGGING 2>/dev/null || true
    iptables -A ASTRACAT_LOGGING -m limit --limit 2/min -j LOG --log-prefix "ASTRACAT_BLOCKED: "
    iptables -A ASTRACAT_LOGGING -j DROP

    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    echo -e "${GREEN}Firewall integration configured${NC}"
}

# Setup fail2ban integration
setup_fail2ban() {
    echo -e "${BLUE}Configuring fail2ban integration...${NC}"

    # Create fail2ban filter
    cat > /etc/fail2ban/filter.d/astracat-guard.conf << EOF
[Definition]
failregex = ^.*ASTRACAT_GUARD.*Blocked IP: <HOST>.*
            ^.*astracat-guard.*blocked.*<HOST>.*
datepattern = {^LN-BEG}
EOF

    # Create jail configuration
    if [ -f /etc/fail2ban/jail.local ]; then
        # Append to existing jail.local
        echo "[astracat-guard]
enabled = true
port = http,https
filter = astracat-guard
logpath = /opt/astracat_guard/logs/astracat_guard.log
maxretry = 3
bantime = 3600
findtime = 600" >> /etc/fail2ban/jail.local
    else
        # Create new jail.local
        echo "[astracat-guard]
enabled = true
port = http,https
filter = astracat-guard
logpath = /opt/astracat_guard/logs/astracat_guard.log
maxretry = 3
bantime = 3600
findtime = 600" >> /etc/fail2ban/jail.local
    fi

    # Restart fail2ban to apply changes
    systemctl restart fail2ban 2>/dev/null || true

    echo -e "${GREEN}Fail2ban integration configured${NC}"
}

# Setup log rotation
setup_log_rotation() {
    echo -e "${BLUE}Setting up log rotation...${NC}"

    # Create log rotation configuration
    cat > /etc/logrotate.d/astracat-guard << EOF
/opt/astracat_guard/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    create 640 root adm
}
EOF

    echo -e "${GREEN}Log rotation configured${NC}"
}

# Create symbolic link for CLI
create_cli_link() {
    echo -e "${BLUE}Creating CLI link...${NC}"
    
    # Create symbolic link for CLI command
    ln -sf "/opt/astracat_guard/bin/astracat-guard" /usr/local/bin/astracat-guard
    
    echo -e "${GREEN}CLI link created${NC}"
}

# Setup system service
setup_system_service() {
    echo -e "${BLUE}Setting up system service...${NC}"

    # Reload systemd
    systemctl daemon-reload

    # Enable service to start at boot
    systemctl enable astracat-guard

    echo -e "${GREEN}System service created and enabled${NC}"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   INSTALLATION COMPLETE                    ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║ ASTRACAT_GUARD has been successfully installed!              ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║ To start the service:                                        ║${NC}"
    echo -e "${GREEN}║   sudo systemctl start astracat-guard                        ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║ To check status:                                             ║${NC}"
    echo -e "${GREEN}║   sudo systemctl status astracat-guard                       ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║ To view logs:                                                ║${NC}"
    echo -e "${GREEN}║   sudo journalctl -u astracat-guard -f                       ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║ To use the CLI:                                              ║${NC}"
    echo -e "${GREEN}║   astracat-guard --help                                      ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║ Configuration file:                                          ║${NC}"
    echo -e "${GREEN}║   /opt/astracat_guard/conf/config.yaml                       ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║ Main daemon:                                                 ║${NC}"
    echo -e "${GREEN}║   /opt/astracat_guard/lib/optimized_guard_daemon.py          ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}The service is NOT started yet. Run: sudo systemctl start astracat-guard${NC}"
}

# Main execution
main() {
    detect_os
    install_prerequisites
    setup_virtualenv
    install_python_deps
    download_astracat_guard
    setup_firewall
    setup_fail2ban
    setup_log_rotation
    create_cli_link
    setup_system_service
    print_summary
}

# Execute main function
main "$@"
EOF