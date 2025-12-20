#!/bin/bash
# Astracat Guard - SSH Protection Script
# This script ensures SSH connections are never blocked by iptables rules

# Allow all SSH connections on port 22 (both INPUT and OUTPUT)
iptables -I INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "ASTRACAT_GUARD_SSH_ALLOW"
iptables -I OUTPUT -p tcp --sport 22 -j ACCEPT -m comment --comment "ASTRACAT_GUARD_SSH_ALLOW"

# If using a custom SSH port, uncomment and modify the line below:
# iptables -I INPUT -p tcp --dport CUSTOM_SSH_PORT -j ACCEPT -m comment --comment "ASTRACAT_GUARD_SSH_ALLOW"

echo "SSH protection rules applied successfully."