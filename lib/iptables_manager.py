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
        
    def _setup_chain(self):
        """Setup custom chain for ASTRACAT_GUARD"""
        try:
            # Use full path to iptables to ensure it's found
            iptables_cmd = '/sbin/iptables'
            if not os.path.exists(iptables_cmd):
                iptables_cmd = '/usr/sbin/iptables'
            if not os.path.exists(iptables_cmd):
                iptables_cmd = 'iptables'  # fallback to PATH

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