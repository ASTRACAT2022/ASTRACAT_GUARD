# ASTRACAT_GUARD Quick Start Guide

## Installation

### Step 1: Download and Prepare
```bash
# Clone or download the ASTRACAT_GUARD package
cd astracat_guard
```

### Step 2: Run the Deployment Script
```bash
sudo ./scripts/deploy.sh
```

### Step 3: Start the Service
```bash
sudo systemctl start astracat-guard
sudo systemctl enable astracat-guard  # Auto-start on boot
```

## Basic Configuration

Edit the configuration file to customize protection:
```bash
sudo nano /opt/astracat_guard/conf/config.yaml
```

Key settings you might want to adjust:
- `protection.rate_limit.threshold` - Number of requests per minute before rate limiting
- `protection.connection_limit.max_connections_per_ip` - Max connections per IP
- `whitelist.ips` - Add your trusted IPs here

After configuration changes, restart the service:
```bash
sudo systemctl restart astracat-guard
```

## Common Tasks

### Check Service Status
```bash
astracat-guard status
```

### Monitor Protection in Real-time
```bash
sudo journalctl -u astracat-guard -f
```

### Add Trusted IP to Whitelist
```bash
astracat-guard whitelist add 192.168.1.100
```

### Temporarily Block an IP
```bash
astracat-guard blacklist add 10.0.0.50
```

### View Protection Statistics
```bash
astracat-guard stats
```

## Web Panel Protection

ASTRACAT_GUARD provides special protection for web management panels. By default, it monitors sensitive paths like:
- `/admin`
- `/login`
- `/panel`
- `/dashboard`

For custom panels, add paths to `protection.web_panel_protection.sensitive_urls` in the config file.

## Performance Optimization

For servers with limited resources:
1. Increase rate limiting thresholds to reduce processing overhead
2. Adjust `max_requests_per_second` based on your server capacity
3. Limit the number of protected ports to only what's necessary

Example optimized config:
```yaml
protection:
  rate_limit:
    enabled: true
    threshold: 200  # Higher value = less processing
    window_size: 60
  http_flood:
    enabled: true
    max_requests_per_second: 20  # Adjust based on your traffic
```

## Troubleshooting

### Issue: Service won't start after installation
Solution: Check dependencies and configuration
```bash
# View detailed error logs
sudo journalctl -u astracat-guard --no-pager

# Verify Python dependencies
python3 -c "import yaml, psutil, setproctitle"
```

### Issue: Legitimate users getting blocked
Solution: Adjust thresholds or add to whitelist
```bash
# Add your public IP to whitelist
astracat-guard whitelist add YOUR_IP_ADDRESS

# Or adjust the configuration
sudo nano /opt/astracat_guard/conf/config.yaml
```

### Issue: High CPU usage
Solution: Review and optimize configuration settings
- Lower the sensitivity of DDoS protection
- Increase timing windows to reduce processing frequency

## Integration Examples

### With Nginx
Add to your nginx configuration to forward real IP addresses:
```nginx
location / {
    proxy_pass http://backend;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### With Apache
Use mod_remoteip to preserve real client IPs:
```apache
LoadModule remoteip_module modules/mod_remoteip.so
RemoteIPHeader X-Real-IP
```

## Best Practices

1. **Regular Monitoring**: Check logs regularly for blocked IPs and adjust as needed
2. **Whitelist Important IPs**: Add your management IPs to the whitelist
3. **Customize Thresholds**: Adjust settings based on your normal traffic patterns
4. **Update Regularly**: Keep the system updated with latest threat signatures
5. **Backup Configuration**: Regularly backup your configuration files

## Common Attack Scenarios Protection

### DDoS Protection
When under a DDoS attack, ASTRACAT_GUARD will:
- Rate limit requests from individual IPs
- Block IPs exceeding thresholds
- Log details for analysis

### Brute Force Protection
For login attempts, the system will:
- Limit attempts per IP/user combination
- Temporarily block after too many failures
- Provide detailed logs of attempts

### Web Panel Protection
For admin panels, it adds:
- Special monitoring for sensitive paths
- Session management and CSRF protection
- Form submission limits