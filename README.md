# ASTRACAT_GUARD
## Advanced DDoS Protection System

ASTRACAT_GUARD is a comprehensive server protection system designed to defend against DDoS attacks, brute force attempts, and other malicious activities while maintaining low resource usage and without breaking legitimate functionality.

## Features

- **DDoS Protection**: Mitigates various DDoS attack vectors
- **Rate Limiting**: Prevents request flooding
- **Web Panel Protection**: Specialized defense for admin panels
- **Bot Detection**: Identifies and blocks malicious bots/scanners
- **Low Resource Usage**: Optimized for minimal CPU and memory consumption
- **Easy Management**: Simple CLI interface for all operations
- **Flexible Configuration**: YAML-based configuration system

## Installation

### Prerequisites
- Linux-based system (Ubuntu, CentOS, Debian, RHEL, Fedora)
- Python 3.6+
- Root access

### Quick Install

```bash
cd astracat_guard
sudo ./scripts/deploy.sh
```

## Configuration

The main configuration file is located at `/opt/astracat_guard/conf/config.yaml`. You can customize protection parameters, whitelist IPs, and configure various protection modules.

Key configuration sections:
- `protection`: Main protection settings
- `logging`: Log configuration
- `whitelist/blacklist`: IP-based filtering
- `network`: Protected ports and interfaces

## Usage

### Starting the Service
```bash
sudo systemctl start astracat-guard
```

### Checking Status
```bash
sudo systemctl status astracat-guard
```

### View Logs
```bash
sudo journalctl -u astracat-guard -f
```

### CLI Commands

#### Service Management
```bash
astracat-guard start          # Start protection service
astracat-guard stop           # Stop protection service
astracat-guard restart        # Restart protection service
astracat-guard status         # Show service status
```

#### Statistics
```bash
astracat-guard stats          # Show protection statistics
astracat-guard reset-stats    # Reset statistics
```

#### IP Management
```bash
astracat-guard whitelist add 192.168.1.100    # Add IP to whitelist
astracat-guard whitelist remove 192.168.1.100 # Remove from whitelist
astracat-guard blacklist add 10.0.0.50         # Add IP to blacklist (temporary)
astracat-guard blacklist remove 10.0.0.50      # Remove from blacklist
```

#### Other Commands
```bash
astracat-guard config         # Show current configuration
astracat-guard update         # Update protection rules
astracat-guard install        # Install as system service
```

## Protection Modules

### Rate Limiting
Prevents request flooding by limiting requests per minute per IP.

### Connection Limiting
Controls the number of concurrent connections to prevent exhaustion attacks.

### HTTP Flood Detection
Identifies and blocks HTTP flooding attempts.

### Slowloris Protection
Defends against slow HTTP denial of service attacks.

### Web Panel Protection
Specialized protection for admin panels and sensitive web areas.

### Bot Detection
Blocks known malicious bots and scanners.

## Performance Tuning

For low-resource environments, adjust these parameters in the config:
- Reduce `rate_limit.threshold` values
- Adjust `max_requests_per_second` for HTTP flood protection
- Modify `auto_block_time` for temporary IP blocking

## Integration

### Fail2Ban
ASTRACAT_GUARD integrates with fail2ban for enhanced security. The integration is set up automatically during installation.

### Firewall
The system works with iptables and can be combined with other firewall solutions.

## Troubleshooting

### Service Won't Start
- Check logs with `journalctl -u astracat-guard`
- Verify configuration with `astracat-guard config`
- Ensure required dependencies are installed

### False Positives
- Add trusted IPs to the whitelist
- Adjust rate limiting thresholds in the configuration
- Fine-tune protection parameters based on your traffic patterns

### High Resource Usage
- Lower the sensitivity of protection modules
- Increase timing thresholds
- Check for any misconfiguration causing loops

## Uninstallation

To uninstall ASTRACAT_GUARD:
```bash
sudo systemctl stop astracat-guard
sudo systemctl disable astracat-guard
sudo rm -rf /opt/astracat_guard
sudo rm /etc/systemd/system/astracat-guard.service
sudo rm /usr/local/bin/astracat-guard
sudo systemctl daemon-reload
```

## Support

For issues and support:
- Check the logs first
- Verify configuration
- Review the protection thresholds
- Contact system administrator if problems persist

---
© 2025 ASTRACAT_GUARD - Advanced Server Protection System