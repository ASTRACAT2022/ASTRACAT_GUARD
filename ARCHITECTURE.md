# ASTRACAT_GUARD System Architecture & Requirements

## Architecture Overview

ASTRACAT_GUARD follows a modular architecture design with the following components:

### Core Components
1. **Main Daemon** (`optimized_guard_daemon.py`)
   - Monitors network traffic and connection patterns
   - Processes protection logic and makes blocking decisions
   - Maintains statistics and logs

2. **Network Monitor** (`network_protection.py`)
   - Real-time traffic analysis
   - IP-based blocking using iptables
   - Connection tracking and filtering

3. **Web Panel Protector** (`web_panel_protection.py`)
   - Specialized protection for web interfaces
   - Brute force prevention for login pages
   - Session management and CSRF protection

4. **CLI Interface** (`bin/astracat-guard`)
   - Command-line management tool
   - Service control and configuration
   - Statistics viewing and IP management

### Protection Modules
- Rate Limiter
- HTTP Flood Detector  
- Bot Detection
- Web Application Firewall (WAF)
- Session Management
- Brute Force Prevention

## System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+, RHEL 7+, Fedora 28+)
- **CPU**: 1 core (2.0 GHz recommended)
- **RAM**: 128 MB available
- **Disk**: 50 MB free space
- **Python**: 3.6 or higher

### Recommended Requirements
- **CPU**: 2+ cores for high-traffic environments
- **RAM**: 256 MB+ for extensive logging
- **Python**: 3.8+ for better performance

### Dependencies
- Python packages: `pyyaml`, `psutil`, `setproctitle`
- System tools: `iptables`, `fail2ban` (optional but recommended)
- Network utilities: `net-tools`, `dnsutils`

## Resource Usage

### CPU Usage
- **Idle**: <1% CPU
- **Normal Operation**: 1-3% CPU
- **Under Attack**: 5-15% CPU (with protection active)

### Memory Usage
- **Base**: ~50 MB RAM
- **With Full Protection**: ~75 MB RAM
- **Peak (Under Attack)**: ~125 MB RAM

### Disk Usage
- **Installation**: ~20 MB
- **Daily Logs**: ~1-5 MB (with rotation)
- **Log Storage**: Configurable with log rotation

## Security Model

### Defense Layers
1. **Perimeter Defense**: IP-based blocking and rate limiting
2. **Protocol Defense**: Protection against HTTP flood, Slowloris
3. **Application Defense**: WAF and bot detection
4. **Panel Defense**: Specialized admin panel protection

### Detection Methods
- **Rate-based**: Request frequency analysis
- **Behavioral**: Pattern recognition in traffic
- **Signature-based**: Known attack vector matching
- **Heuristic**: Anomalous behavior detection

### Blocking Mechanisms
- **Temporary IP Blocks**: Automatic IP blocking for 1 hour (configurable)
- **Rate Limiting**: Per-IP request limits
- **Connection Limits**: Concurrent connection caps
- **Request Filtering**: Content-based blocking

## Integration Points

### With iptables
ASTRACAT_GUARD can integrate with iptables for efficient packet filtering:
- Creates custom chains for blocked traffic
- Logs blocked attempts
- Provides connection tracking

### With fail2ban
Integration allows for:
- Persistent blocking across service restarts
- Integration with other fail2ban filters
- Coordinated response to attacks

### With System Logging
- Standard syslog integration
- Custom log format for easy parsing
- Log rotation to prevent disk space issues

## Performance Considerations

### Optimization Strategies
1. **Caching**: Request history uses efficient data structures
2. **Threading**: Non-blocking operations where possible
3. **Memory Management**: Automatic cleanup of old records
4. **Efficient Algorithms**: O(1) or O(log n) operations where possible

### Tuning Parameters
- Adjust rate limits based on legitimate traffic
- Configure timeout values appropriately
- Set connection limits to match server capacity

## Configuration Management

### Main Configuration File
Location: `/opt/astracat_guard/conf/config.yaml`

Key sections:
- `protection`: Core protection settings
- `logging`: Log configuration
- `whitelist/blacklist`: IP-based filtering rules
- `network`: Protected ports and interfaces

### Environment Considerations
- Production: Higher thresholds, more aggressive blocking
- Development: Lower thresholds for testing
- High-traffic: Adjust timing windows to reduce CPU usage

## Monitoring and Maintenance

### Log Files
- Primary log: `/var/log/astracat_guard.log`
- Systemd journal: Accessible via journalctl
- Rotation: Automatic daily rotation with 5 backups

### Health Checks
- Service status monitoring
- Resource usage tracking
- Protection effectiveness metrics

### Maintenance Tasks
- Log rotation management
- Statistics cleanup
- Configuration validation
- Dependency updates

## Deployment Architecture

### Single Server
```
[Client Traffic] -> [ASTRACAT_GUARD] -> [Web Server/Application]
```

### Load Balanced Environment
```
[Client Traffic] -> [Load Balancer] -> [Multiple Servers with ASTRACAT_GUARD]
```

### Reverse Proxy Setup
```
[Client Traffic] -> [ASTRACAT_GUARD] -> [Reverse Proxy] -> [Backend Servers]
```

## Upgrade Path

### Version Compatibility
- Configuration files are backward compatible
- Database schema (if any) is automatically migrated
- Binary compatibility maintained across minor versions

### Rollback Procedures
- Keep backup of previous configuration
- Test upgrade in staging environment first
- Have restore procedures ready

## Troubleshooting Common Issues

### High Resource Usage
- Check for misconfigured thresholds
- Verify no infinite loops in configuration
- Review traffic patterns for anomalies

### False Positives
- Adjust rate limiting thresholds
- Add legitimate IPs to whitelist
- Fine-tune protection parameters

### Service Failures
- Verify dependencies are installed
- Check configuration file syntax
- Review log files for error messages

This architecture ensures that ASTRACAT_GUARD provides robust protection while maintaining minimal resource usage and easy management.