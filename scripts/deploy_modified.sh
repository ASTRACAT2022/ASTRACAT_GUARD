#!/bin/bash
#
# ASTRACAT_GUARD Deployment Script
# Easy setup and installation script for ASTRACAT_GUARD protection system

set -e  # Exit on any error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      ASTRACAT_GUARD Deployment       ║${NC}"
echo -e "${BLUE}║         Installation Script          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"

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
    else
        echo -e "${RED}Cannot detect OS. Exiting.${NC}"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing required dependencies...${NC}"

    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        apt-get update
        apt-get install -y python3 python3-pip iptables fail2ban curl wget net-tools dnsutils
        # Check if Python packages are already available
        if ! python3 -c "import psutil, setproctitle" 2>/dev/null; then
            echo -e "${YELLOW}Python packages not found in system Python, ensuring they're in virtual env${NC}"
            # They should already be in the virtual environment, so just continue
        fi
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        yum update -y
        yum install -y python3 python3-pip iptables fail2ban curl wget net-tools bind-utils
        if ! python3 -c "import psutil, setproctitle" 2>/dev/null; then
            pip3 install psutil setproctitle
        fi
    elif [[ "$OS" == *"Amazon Linux"* ]]; then
        yum update -y
        yum install -y python3 python3-pip iptables curl wget net-tools bind-utils
        if ! python3 -c "import psutil, setproctitle" 2>/dev/null; then
            pip3 install psutil setproctitle
        fi
    else
        echo -e "${YELLOW}Unsupported OS. Attempting generic installation...${NC}"
        # Try to install generic packages
        if command -v apt-get &> /dev/null; then
            apt-get install -y python3 python3-pip iptables curl wget net-tools
        elif command -v yum &> /dev/null; then
            yum install -y python3 python3-pip iptables curl wget net-tools
        fi
        if ! python3 -c "import psutil, setproctitle" 2>/dev/null; then
            pip3 install psutil setproctitle
        fi
    fi

    echo -e "${GREEN}Dependencies installed successfully${NC}"
}

# Copy files to system location
install_files() {
    echo -e "${BLUE}Installing ASTRACAT_GUARD files...${NC}"

    # Create installation directory
    INSTALL_DIR="/opt/astracat_guard"
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"/{bin,lib,conf,scripts,logs}

    # Copy files from current directory to installation directory
    cp -r /root/astracat_guard/bin "$INSTALL_DIR/"
    cp -r /root/astracat_guard/lib "$INSTALL_DIR/"
    cp -r /root/astracat_guard/conf "$INSTALL_DIR/"
    cp -r /root/astracat_guard/scripts "$INSTALL_DIR/"
    cp -r /root/astracat_guard/logs "$INSTALL_DIR/"

    # Create symbolic link for CLI command
    ln -sf "$INSTALL_DIR/bin/astracat-guard" /usr/local/bin/astracat-guard

    # Make executable
    chmod +x "$INSTALL_DIR/bin/astracat-guard"
    chmod +x "$INSTALL_DIR/bin/astracat-guard-auto"
    chmod +x "$INSTALL_DIR/lib/"*.py

    # Set proper permissions
    chown -R root:root "$INSTALL_DIR"
    chmod -R 644 "$INSTALL_DIR/conf/"
    chmod 755 "$INSTALL_DIR/bin/"
    chmod 755 "$INSTALL_DIR/lib/"
    chmod 755 "$INSTALL_DIR/scripts/"

    echo -e "${GREEN}Files installed to $INSTALL_DIR${NC}"
}

# Setup system service
setup_system_service() {
    echo -e "${BLUE}Setting up system service...${NC}"

    # Create systemd service file
    cat > /etc/systemd/system/astracat-guard.service << EOF
[Unit]
Description=ASTRACAT_GUARD DDoS Protection Service
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/root/astracat_guard/myenv/bin/python /opt/astracat_guard/lib/optimized_guard_daemon.py
Environment=PATH=/root/astracat_guard/myenv/bin
Environment=VIRTUAL_ENV=/root/astracat_guard/myenv
WorkingDirectory=/root/astracat_guard/myenv
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    # Enable service to start at boot
    systemctl enable astracat-guard

    echo -e "${GREEN}System service created and enabled${NC}"
}

# Configure firewall rules
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

# Configure fail2ban
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
    echo "[astracat-guard]
enabled = true
port = http,https
filter = astracat-guard
logpath = /var/log/astracat_guard.log
maxretry = 3
bantime = 3600
findtime = 600" >> /etc/fail2ban/jail.local

    # Restart fail2ban to apply changes
    systemctl restart fail2ban 2>/dev/null || true
    
    echo -e "${GREEN}Fail2ban integration configured${NC}"
}

# Run initial configuration
initial_configuration() {
    echo -e "${BLUE}Performing initial configuration...${NC}"
    
    # Set up log rotation
    cat > /etc/logrotate.d/astracat-guard << EOF
/var/log/astracat_guard.log {
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

    # Update config file with proper paths
    sed -i "s|/var/log/astracat_guard.log|$INSTALL_DIR/logs/astracat_guard.log|" "$INSTALL_DIR/conf/config.yaml"
    
    echo -e "${GREEN}Initial configuration completed${NC}"
}

# Final status check
final_status_check() {
    echo -e "${BLUE}Performing final status checks...${NC}"
    
    # Check if service is enabled
    if systemctl is-enabled --quiet astracat-guard; then
        echo -e "${GREEN}✓ Service is enabled${NC}"
    else
        echo -e "${YELLOW}⚠ Service may not be enabled${NC}"
    fi
    
    # Check if required binaries exist
    if command -v astracat-guard &> /dev/null; then
        echo -e "${GREEN}✓ CLI command available${NC}"
    else
        echo -e "${RED}✗ CLI command not available${NC}"
    fi
    
    # Check if iptables is available
    if command -v iptables &> /dev/null; then
        echo -e "${GREEN}✓ iptables available${NC}"
    else
        echo -e "${YELLOW}⚠ iptables not available${NC}"
    fi
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
    echo -e "${GREEN}║   $INSTALL_DIR/conf/config.yaml                           ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Main execution
main() {
    detect_os
    install_dependencies
    install_files
    setup_system_service
    setup_firewall
    setup_fail2ban
    initial_configuration
    final_status_check
    print_summary
}

# Execute main function
main "$@"