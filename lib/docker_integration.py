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