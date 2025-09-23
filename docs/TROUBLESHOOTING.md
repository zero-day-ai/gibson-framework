# Gibson Framework Troubleshooting Guide

**Production-Ready Support Guide**

This comprehensive guide helps you diagnose and resolve common issues with the Gibson Framework. All procedures have been validated in production environments.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Installation Issues](#installation-issues)
- [Service Issues](#service-issues)
- [Database Issues](#database-issues)
- [Plugin Issues](#plugin-issues)
- [Git Repository Issues](#git-repository-issues)
- [Network and Connectivity Issues](#network-and-connectivity-issues)
- [Performance Issues](#performance-issues)
- [Configuration Issues](#configuration-issues)
- [Permission Issues](#permission-issues)
- [Logging and Debugging](#logging-and-debugging)
- [Recovery Procedures](#recovery-procedures)
- [Getting Help](#getting-help)

## Quick Diagnostics

### System Status Check

```bash
# Check comprehensive system status with health monitoring
gibson status --verbose --component all

# Check gibson version and build information
gibson version --detailed

# Run complete health check including disk space and memory
gibson status --watch --refresh 1

# Validate configuration and security settings
gibson init --validate-only

# Test database connectivity and integrity
gibson status --component database
```

### Common First Steps

1. **Check Logs**
   ```bash
   # Check structured application logs with real-time monitoring
   gibson logs --follow --level debug --component all

   # View security audit logs
   gibson logs --component security --since 24h

   # Check plugin execution logs
   gibson logs --component plugins --level error

   # Export logs for analysis
   gibson logs --export --format json --output debug-export.json
   ```

2. **Verify Configuration**
   ```bash
   # Validate complete configuration including security settings
   gibson init --validate-config --verbose

   # Show sanitized configuration (secrets redacted)
   gibson config show --sanitized

   # Test database connectivity and migrations
   gibson status --component database --validate
   ```

3. **Check File Permissions**
   ```bash
   # Verify ownership
   ls -la /var/lib/gibson/
   ls -la /etc/gibson/
   ls -la /var/log/gibson/

   # Fix permissions if needed
   sudo chown -R gibson:gibson /var/lib/gibson
   sudo chown -R root:gibson /etc/gibson
   sudo chown -R gibson:gibson /var/log/gibson
   ```

## Installation Issues

### Installation Script Fails

**Problem**: Installation script exits with errors

**Diagnosis**:
```bash
# Check if running as root
whoami

# Verify curl/wget availability
which curl
which wget

# Check internet connectivity
ping github.com

# Verify platform support
uname -a
```

**Solutions**:

1. **Run as non-root user with sudo**:
   ```bash
   # Don't run as root
   curl -fsSL https://example.com/install.sh | bash
   ```

2. **Manual installation**:
   ```bash
   # Download manually
   wget https://github.com/gibson-sec/gibson-framework-2/releases/latest/download/gibson-linux-amd64.tar.gz
   tar -xzf gibson-linux-amd64.tar.gz
   sudo mv gibson-linux-amd64 /usr/local/bin/gibson
   sudo chmod +x /usr/local/bin/gibson
   ```

3. **Fix dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install -y curl wget tar

   # CentOS/RHEL
   sudo yum install -y curl wget tar

   # macOS
   brew install curl wget
   ```

### Package Installation Issues

**Problem**: DEB/RPM package installation fails

**Diagnosis**:
```bash
# Check package manager
dpkg --version  # Debian/Ubuntu
rpm --version   # CentOS/RHEL

# Verify package integrity
dpkg -I gibson_*.deb
rpm -qip gibson_*.rpm

# Check dependencies
dpkg -I gibson_*.deb | grep Depends
rpm -qRp gibson_*.rpm
```

**Solutions**:

1. **Fix missing dependencies**:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install -f

   # CentOS/RHEL
   sudo yum install -y missing-dependency
   ```

2. **Force installation** (if safe):
   ```bash
   # Debian/Ubuntu
   sudo dpkg -i --force-depends gibson_*.deb

   # CentOS/RHEL
   sudo rpm -ivh --nodeps gibson_*.rpm
   ```

### Binary Not Found After Installation

**Problem**: `gibson: command not found`

**Diagnosis**:
```bash
# Check PATH
echo $PATH

# Find gibson binary
which gibson
find /usr -name gibson 2>/dev/null

# Check installation location
ls -la /usr/local/bin/gibson
ls -la /usr/bin/gibson
```

**Solutions**:

1. **Add to PATH**:
   ```bash
   # Temporary
   export PATH=$PATH:/usr/local/bin

   # Permanent
   echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

2. **Create symlink**:
   ```bash
   sudo ln -s /usr/local/bin/gibson /usr/bin/gibson
   ```

## Service Issues

### Service Won't Start

**Problem**: `systemctl start gibson` fails

**Diagnosis**:
```bash
# Check service status
sudo systemctl status gibson

# Check service file
sudo systemctl cat gibson

# Check systemd logs
sudo journalctl -u gibson --no-pager

# Validate service file
sudo systemd-analyze verify gibson.service
```

**Solutions**:

1. **Fix service file**:
   ```bash
   # Check if service file exists
   ls -la /etc/systemd/system/gibson.service

   # Reload systemd if modified
   sudo systemctl daemon-reload
   ```

2. **Fix binary path**:
   ```bash
   # Update service file with correct path
   sudo sed -i 's|/usr/local/bin/gibson|/usr/bin/gibson|' /etc/systemd/system/gibson.service
   sudo systemctl daemon-reload
   ```

3. **Fix user/group**:
   ```bash
   # Check if gibson user exists
   id gibson

   # Create if missing
   sudo useradd --system --shell /bin/false gibson
   ```

### Service Starts But Crashes

**Problem**: Service starts then immediately stops

**Diagnosis**:
```bash
# Check exit code
sudo systemctl status gibson

# Check application logs
sudo journalctl -u gibson -f

# Run manually for debugging
sudo -u gibson gibson serve --config /etc/gibson/config.yaml
```

**Solutions**:

1. **Configuration issues**:
   ```bash
   # Validate configuration
   gibson validate --config /etc/gibson/config.yaml

   # Check file permissions
   sudo chmod 644 /etc/gibson/config.yaml
   ```

2. **Database issues**:
   ```bash
   # Check database file
   ls -la /var/lib/gibson/gibson.db

   # Test database
   sqlite3 /var/lib/gibson/gibson.db "SELECT 1;"
   ```

3. **Port conflicts**:
   ```bash
   # Check if port is in use
   sudo netstat -tlpn | grep :8080

   # Use different port
   gibson serve --port 8081
   ```

### Service Runs But Unresponsive

**Problem**: Service is running but doesn't respond to requests

**Diagnosis**:
```bash
# Check process
ps aux | grep gibson

# Check listening ports
sudo netstat -tlpn | grep gibson

# Test connectivity
curl http://localhost:8080/health
gibson health
```

**Solutions**:

1. **Check bind address**:
   ```bash
   # Ensure binding to correct interface
   # In config.yaml:
   server:
     host: "0.0.0.0"  # Not "127.0.0.1" for external access
     port: 8080
   ```

2. **Firewall issues**:
   ```bash
   # Check firewall rules
   sudo ufw status
   sudo iptables -L

   # Allow port
   sudo ufw allow 8080/tcp
   ```

3. **Resource exhaustion**:
   ```bash
   # Check system resources
   top
   free -h
   df -h

   # Restart service
   sudo systemctl restart gibson
   ```

## Database Issues

### Database Corruption

**Problem**: SQLite database is corrupted

**Diagnosis**:
```bash
# Check database integrity
sqlite3 /var/lib/gibson/gibson.db "PRAGMA integrity_check;"

# Check database file
file /var/lib/gibson/gibson.db

# Check file permissions
ls -la /var/lib/gibson/gibson.db
```

**Solutions**:

1. **Repair database**:
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Backup corrupted database
   sudo cp /var/lib/gibson/gibson.db /tmp/gibson.db.corrupt

   # Try to repair
   sqlite3 /var/lib/gibson/gibson.db "PRAGMA integrity_check;"
   sqlite3 /var/lib/gibson/gibson.db ".recover" | sqlite3 /var/lib/gibson/gibson_recovered.db

   # Replace if successful
   sudo mv /var/lib/gibson/gibson_recovered.db /var/lib/gibson/gibson.db
   sudo chown gibson:gibson /var/lib/gibson/gibson.db
   ```

2. **Restore from backup**:
   ```bash
   # List available backups
   ls -la /var/backups/gibson/

   # Restore from backup
   sudo /opt/gibson/scripts/restore.sh /var/backups/gibson/latest_backup.tar.gz
   ```

3. **Recreate database**:
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Backup old database
   sudo mv /var/lib/gibson/gibson.db /tmp/gibson.db.old

   # Start service (will create new database)
   sudo systemctl start gibson

   # Run migrations
   gibson migrate
   ```

### Database Permission Issues

**Problem**: Cannot access database file

**Diagnosis**:
```bash
# Check file ownership and permissions
ls -la /var/lib/gibson/gibson.db

# Check directory permissions
ls -ld /var/lib/gibson/

# Check if file is locked
lsof /var/lib/gibson/gibson.db
```

**Solutions**:

1. **Fix permissions**:
   ```bash
   sudo chown gibson:gibson /var/lib/gibson/gibson.db
   sudo chmod 644 /var/lib/gibson/gibson.db
   sudo chmod 755 /var/lib/gibson/
   ```

2. **Check for locks**:
   ```bash
   # Kill processes holding locks
   sudo fuser -k /var/lib/gibson/gibson.db

   # Remove WAL files if necessary
   sudo rm -f /var/lib/gibson/gibson.db-wal /var/lib/gibson/gibson.db-shm
   ```

### Database Migration Issues

**Problem**: Migration fails or database version mismatch

**Diagnosis**:
```bash
# Check migration status
gibson migrate status

# Check database version
gibson version --database

# Check migration logs
grep -i migration /var/log/gibson/gibson.log
```

**Solutions**:

1. **Force migration**:
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Run migration manually
   sudo -u gibson gibson migrate auto

   # Start service
   sudo systemctl start gibson
   ```

2. **Manual schema fix**:
   ```bash
   # Check schema
   sqlite3 /var/lib/gibson/gibson.db ".schema"

   # Run specific migration
   gibson migrate force 1.0.0 2.0.0
   ```

## Plugin Issues

### Plugins Not Loading

**Problem**: Plugins directory empty or plugins not discovered

**Diagnosis**:
```bash
# Check plugins directory
ls -la /var/lib/gibson/plugins/

# Check plugin discovery
gibson plugin list

# Check plugin configuration
gibson config show | grep -A 10 plugins
```

**Solutions**:

1. **Create plugins directory**:
   ```bash
   sudo mkdir -p /var/lib/gibson/plugins
   sudo chown gibson:gibson /var/lib/gibson/plugins
   ```

2. **Install example plugins**:
   ```bash
   # Copy example plugins
   sudo cp -r /opt/gibson/plugins/examples/* /var/lib/gibson/plugins/
   sudo chown -R gibson:gibson /var/lib/gibson/plugins
   ```

3. **Check plugin manifests**:
   ```bash
   # Validate plugin.yaml files
   find /var/lib/gibson/plugins -name "plugin.yaml" -exec yaml-validate {} \;
   ```

### Plugin Execution Failures

**Problem**: Plugins fail to execute or timeout

**Diagnosis**:
```bash
# Check plugin status
gibson plugin status

# Check plugin logs
grep -i plugin /var/log/gibson/gibson.log

# Test plugin manually
gibson plugin test plugin-name
```

**Solutions**:

1. **Increase timeout**:
   ```yaml
   # In config.yaml
   plugins:
     timeout: 600  # Increase from 300
   ```

2. **Check plugin dependencies**:
   ```bash
   # Check if plugin binary exists
   ls -la /var/lib/gibson/plugins/plugin-name/

   # Check execution permissions
   chmod +x /var/lib/gibson/plugins/plugin-name/plugin
   ```

3. **Plugin debugging**:
   ```bash
   # Enable plugin debug logging
   gibson serve --log-level debug

   # Run plugin in isolation
   gibson plugin run plugin-name --debug
   ```

### Plugin Version Conflicts

**Problem**: Plugin version mismatches or incompatibility

**Diagnosis**:
```bash
# Check plugin versions
gibson plugin list --verbose

# Check compatibility
gibson plugin validate

# Check gibson version
gibson --version
```

**Solutions**:

1. **Update plugins**:
   ```bash
   # Update all plugins
   gibson plugin update --all

   # Update specific plugin
   gibson plugin update plugin-name
   ```

2. **Downgrade incompatible plugins**:
   ```bash
   # Install specific version
   gibson plugin install plugin-name@1.0.0
   ```

## Git Repository Issues

### Repository Clone Failures

**Problem**: Git repositories fail to clone with authentication or network errors

**Diagnosis**:
```bash
# Test repository access directly
git ls-remote https://github.com/user/repo.git

# Check SSH connectivity
ssh -T git@github.com

# Test with verbose Git output
GIT_CURL_VERBOSE=1 git clone https://github.com/user/repo.git

# Check Gibson repository status
gibson payload repository list --show-status
```

**Common Solutions**:

1. **SSH Authentication Issues**:
   ```bash
   # Generate new SSH key
   ssh-keygen -t ed25519 -C "your-email@company.com"

   # Add SSH key to ssh-agent
   ssh-add ~/.ssh/id_ed25519

   # Add public key to Git provider (GitHub/GitLab)
   cat ~/.ssh/id_ed25519.pub

   # Test SSH connection
   ssh -T git@github.com
   ```

2. **HTTPS Token Authentication**:
   ```bash
   # Add GitHub personal access token
   gibson credential add --name github-token --type token --provider github

   # Validate credential
   gibson credential validate --name github-token

   # Check credential expiration
   gibson credential show --name github-token
   ```

3. **Corporate Firewall/Proxy**:
   ```bash
   # Configure Git proxy
   git config --global http.proxy http://proxy.company.com:8080
   git config --global https.proxy https://proxy.company.com:8080

   # Test connectivity
   ping github.com

   # Check DNS resolution
   nslookup github.com
   ```

### Repository Sync Failures

**Problem**: Repository synchronization fails or is incomplete

**Diagnosis**:
```bash
# Check sync status with detailed information
gibson payload repository list --show-status --output json

# View sync logs
gibson logs --component git --level error --since 1h

# Test repository connectivity
gibson payload repository sync repo-name --verbose

# Check local repository state
ls -la ~/.gibson/repos/
```

**Solutions**:

1. **Local Repository Corruption**:
   ```bash
   # Remove corrupted local repository
   rm -rf ~/.gibson/repos/repository-name

   # Force re-clone
   gibson payload repository sync repository-name --force
   ```

2. **Network Timeouts**:
   ```bash
   # Configure Git timeout settings
   git config --global http.lowSpeedLimit 1000
   git config --global http.lowSpeedTime 300

   # Use wired connection if possible
   # Retry during off-peak hours
   ```

3. **Rate Limiting**:
   ```bash
   # Check rate limit status (GitHub)
   curl -H "Authorization: token YOUR_TOKEN" \
        https://api.github.com/rate_limit

   # Use authenticated requests
   gibson credential add --name github-token --type token

   # Wait and retry (GitHub allows 5000 requests/hour with auth)
   ```

### Payload Processing Issues

**Problem**: Payloads from Git repositories are not imported correctly

**Diagnosis**:
```bash
# Check imported payloads from repository
gibson payload list --repository repo-name

# Search for specific payloads
gibson payload search "test" --repository repo-name

# Validate payload file format
cat ~/.gibson/repos/repo-name/payloads/example.json | jq .
```

**Solutions**:

1. **Invalid Payload Format**:
   ```bash
   # Validate JSON syntax
   find ~/.gibson/repos/repo-name -name "*.json" -exec jq . {} \;

   # Check payload schema
   gibson payload validate --file payload.json
   ```

2. **Missing Repository Structure**:
   ```bash
   # Verify expected repository structure
   tree ~/.gibson/repos/repo-name

   # Repository should contain:
   # payloads/           # Directory with payload files
   # metadata/           # Optional metadata files
   # README.md           # Documentation
   ```

3. **Payload Categorization Issues**:
   ```bash
   # Check payload categories
   gibson payload list --category injection

   # Verify supported categories
   gibson help payload add
   ```

### Authentication Troubleshooting

**Problem**: Git authentication fails during repository operations

**Advanced Debugging**:
```bash
# Enable Git credential debugging
export GIT_TRACE=1
export GIT_CURL_VERBOSE=1

# Test Git operations with debugging
git clone https://github.com/user/repo.git

# Check Git credential configuration
git config --list | grep credential

# Test SSH configuration
ssh -vT git@github.com
```

**Solutions by Authentication Type**:

1. **SSH Key Issues**:
   ```bash
   # Check SSH key format and permissions
   ls -la ~/.ssh/
   chmod 600 ~/.ssh/id_*
   chmod 644 ~/.ssh/id_*.pub

   # Add SSH key to multiple Git providers
   ssh-add ~/.ssh/id_ed25519  # Add to agent
   # Then upload public key to GitHub, GitLab, etc.
   ```

2. **Personal Access Token Issues**:
   ```bash
   # Test token directly with curl
   curl -H "Authorization: token YOUR_TOKEN" \
        https://api.github.com/user

   # Check token permissions and expiration
   # Token needs "repo" scope for private repositories
   ```

3. **Two-Factor Authentication**:
   ```bash
   # 2FA requires token authentication for HTTPS
   # SSH keys work normally with 2FA enabled

   # Use app passwords for GitLab/Bitbucket
   # Use personal access tokens for GitHub
   ```

### Repository Management Best Practices

**Prevention**:
1. **Regular Health Checks**:
   ```bash
   # Daily repository status check
   gibson payload repository list --show-status

   # Weekly sync health
   gibson payload repository sync --progress

   # Monthly credential validation
   gibson credential validate --all
   ```

2. **Monitoring Setup**:
   ```bash
   # Monitor repository sync success
   gibson logs --component git --follow

   # Set up automated sync scheduling
   # Add to crontab: 0 6 * * * gibson payload repository sync
   ```

3. **Security Practices**:
   ```bash
   # Rotate credentials quarterly
   gibson credential rotate --name github-token

   # Use read-only tokens when possible
   # Monitor repository access logs

   # Regular audit of repository access
   gibson credential list --include-usage
   ```

**Recovery Procedures**:
```bash
# Complete repository reset
gibson payload repository remove repo-name --purge-payloads
gibson payload repository add repo-name https://github.com/user/repo.git

# Credential recovery
gibson credential delete --name old-token
gibson credential add --name new-token --type token --provider github

# Full Gibson reset (last resort)
cp ~/.gibson/gibson.db ~/.gibson/gibson.db.backup
gibson init --reset
# Then reconfigure targets, credentials, and repositories
```

**Error Code Reference**:
- `AUTH_FAILED`: Invalid or expired credentials
- `REPO_NOT_FOUND`: Repository doesn't exist or no access
- `NETWORK_ERROR`: Connectivity or DNS issues
- `CLONE_FAILED`: Git clone operation failed
- `SYNC_FAILED`: Repository synchronization failed
- `PAYLOAD_INVALID`: Payload format validation failed

## Network and Connectivity Issues

### Cannot Connect to Gibson API

**Problem**: API requests fail or timeout

**Diagnosis**:
```bash
# Test local connectivity
curl http://localhost:8080/health

# Check if service is listening
sudo netstat -tlpn | grep :8080

# Test from remote host
curl http://gibson-server:8080/health

# Check firewall
sudo ufw status
```

**Solutions**:

1. **Check bind address**:
   ```yaml
   # In config.yaml
   server:
     host: "0.0.0.0"  # Allow external connections
     port: 8080
   ```

2. **Configure firewall**:
   ```bash
   # Allow port through firewall
   sudo ufw allow 8080/tcp

   # For specific hosts only
   sudo ufw allow from 192.168.1.0/24 to any port 8080
   ```

3. **Check proxy/load balancer**:
   ```bash
   # Test direct connection
   curl -H "Host: gibson.example.com" http://server-ip:8080/health
   ```

### TLS/SSL Certificate Issues

**Problem**: HTTPS connections fail or certificate errors

**Diagnosis**:
```bash
# Test TLS connection
openssl s_client -connect gibson.example.com:443

# Check certificate validity
openssl x509 -in /etc/gibson/certs/server.crt -text -noout

# Check certificate permissions
ls -la /etc/gibson/certs/
```

**Solutions**:

1. **Fix certificate paths**:
   ```yaml
   # In config.yaml
   server:
     tls:
       enabled: true
       cert_file: "/etc/gibson/certs/server.crt"
       key_file: "/etc/gibson/certs/server.key"
   ```

2. **Generate self-signed certificate**:
   ```bash
   sudo mkdir -p /etc/gibson/certs
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout /etc/gibson/certs/server.key \
     -out /etc/gibson/certs/server.crt
   sudo chown gibson:gibson /etc/gibson/certs/*
   ```

3. **Use Let's Encrypt**:
   ```bash
   # Install certbot
   sudo apt install certbot

   # Obtain certificate
   sudo certbot certonly --standalone -d gibson.example.com

   # Configure gibson to use certificates
   sudo ln -s /etc/letsencrypt/live/gibson.example.com/fullchain.pem /etc/gibson/certs/server.crt
   sudo ln -s /etc/letsencrypt/live/gibson.example.com/privkey.pem /etc/gibson/certs/server.key
   ```

## Performance Issues

### High CPU Usage

**Problem**: Gibson consuming excessive CPU

**Diagnosis**:
```bash
# Check process CPU usage
top -p $(pgrep gibson)

# Check plugin activity
gibson plugin list --status

# Profile application
gibson profile cpu --duration 30s
```

**Solutions**:

1. **Limit concurrent plugins**:
   ```yaml
   # In config.yaml
   plugins:
     max_concurrent: 5  # Reduce from default
   ```

2. **Identify problematic plugins**:
   ```bash
   # Disable plugins one by one
   gibson plugin disable plugin-name

   # Monitor CPU usage
   watch -n 1 'ps aux | grep gibson'
   ```

3. **Adjust scheduling**:
   ```bash
   # Nice the process
   sudo renice 10 $(pgrep gibson)

   # Set CPU limits (systemd)
   sudo systemctl edit gibson
   # Add:
   # [Service]
   # CPUQuota=50%
   ```

### High Memory Usage

**Problem**: Gibson consuming excessive memory

**Diagnosis**:
```bash
# Check memory usage
ps aux | grep gibson

# Check for memory leaks
gibson profile memory --duration 60s

# Monitor memory over time
watch -n 5 'ps -o pid,vsz,rss,comm -p $(pgrep gibson)'
```

**Solutions**:

1. **Restart service regularly**:
   ```bash
   # Add to crontab for weekly restart
   echo "0 2 * * 0 systemctl restart gibson" | sudo crontab -
   ```

2. **Set memory limits**:
   ```bash
   # Set systemd memory limit
   sudo systemctl edit gibson
   # Add:
   # [Service]
   # MemoryMax=512M
   ```

3. **Tune garbage collection**:
   ```bash
   # Set environment variable
   export GOGC=50  # More aggressive GC
   ```

### Slow Database Operations

**Problem**: Database queries are slow

**Diagnosis**:
```bash
# Check database size
du -h /var/lib/gibson/gibson.db

# Check for locks
lsof /var/lib/gibson/gibson.db

# Analyze database
sqlite3 /var/lib/gibson/gibson.db "PRAGMA table_info(scans);"
```

**Solutions**:

1. **Optimize database**:
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Analyze and vacuum
   sqlite3 /var/lib/gibson/gibson.db "ANALYZE; VACUUM;"

   # Start service
   sudo systemctl start gibson
   ```

2. **Archive old data**:
   ```bash
   # Archive old scans
   gibson scan archive --older-than 30d

   # Clean up old findings
   gibson finding cleanup --older-than 90d
   ```

## Configuration Issues

### Invalid Configuration

**Problem**: Configuration validation fails

**Diagnosis**:
```bash
# Validate configuration
gibson validate --config /etc/gibson/config.yaml

# Check YAML syntax
yamllint /etc/gibson/config.yaml

# Show current configuration
gibson config show
```

**Solutions**:

1. **Fix YAML syntax**:
   ```bash
   # Check for common issues
   grep -n "	" /etc/gibson/config.yaml  # Check for tabs

   # Use online YAML validator or
   python -c "import yaml; yaml.safe_load(open('/etc/gibson/config.yaml'))"
   ```

2. **Reset to defaults**:
   ```bash
   # Backup current config
   sudo cp /etc/gibson/config.yaml /etc/gibson/config.yaml.backup

   # Generate default config
   gibson config generate > /tmp/config.yaml
   sudo mv /tmp/config.yaml /etc/gibson/config.yaml
   ```

3. **Incremental validation**:
   ```bash
   # Comment out sections and test
   gibson validate --config /etc/gibson/config.yaml

   # Add sections back gradually
   ```

### Environment Variable Issues

**Problem**: Environment variables not being recognized

**Diagnosis**:
```bash
# Check environment variables
env | grep GIBSON

# Test variable parsing
gibson config show --debug

# Check systemd environment
sudo systemctl show gibson -p Environment
```

**Solutions**:

1. **Set in systemd service**:
   ```bash
   sudo systemctl edit gibson
   # Add:
   # [Service]
   # Environment=GIBSON_LOG_LEVEL=debug
   # Environment=GIBSON_API_KEY=your-key
   ```

2. **Use environment file**:
   ```bash
   # Create environment file
   echo "GIBSON_LOG_LEVEL=debug" | sudo tee /etc/gibson/environment

   # Update service file
   sudo systemctl edit gibson
   # Add:
   # [Service]
   # EnvironmentFile=/etc/gibson/environment
   ```

## Permission Issues

### File Permission Errors

**Problem**: Permission denied errors in logs

**Diagnosis**:
```bash
# Check file ownership
ls -la /var/lib/gibson/
ls -la /etc/gibson/
ls -la /var/log/gibson/

# Check running user
ps aux | grep gibson

# Check SELinux context (if applicable)
ls -Z /var/lib/gibson/
```

**Solutions**:

1. **Fix ownership**:
   ```bash
   sudo chown -R gibson:gibson /var/lib/gibson
   sudo chown -R root:gibson /etc/gibson
   sudo chown -R gibson:gibson /var/log/gibson
   ```

2. **Fix permissions**:
   ```bash
   sudo chmod 755 /var/lib/gibson
   sudo chmod 644 /var/lib/gibson/gibson.db
   sudo chmod 750 /etc/gibson
   sudo chmod 640 /etc/gibson/config.yaml
   sudo chmod 755 /var/log/gibson
   ```

3. **SELinux issues**:
   ```bash
   # Check SELinux status
   sestatus

   # Set appropriate context
   sudo semanage fcontext -a -t admin_home_t "/var/lib/gibson(/.*)?"
   sudo restorecon -R /var/lib/gibson
   ```

## Logging and Debugging

### Enable Debug Logging

```bash
# Temporary debug logging
gibson serve --log-level debug

# Permanent debug logging in config.yaml
logging:
  level: "debug"

# Enable specific module debugging
gibson serve --debug-modules "plugin,database"
```

### Log Rotation Issues

**Problem**: Log files growing too large

**Solutions**:

1. **Configure log rotation**:
   ```bash
   # Edit logrotate configuration
   sudo vim /etc/logrotate.d/gibson

   # Add:
   /var/log/gibson/*.log {
       daily
       rotate 30
       compress
       delaycompress
       missingok
       notifempty
       create 644 gibson gibson
       postrotate
           systemctl reload gibson
       endscript
   }
   ```

2. **Manual log cleanup**:
   ```bash
   # Archive old logs
   sudo gzip /var/log/gibson/gibson.log.1

   # Clean very old logs
   sudo find /var/log/gibson -name "*.log.*" -mtime +30 -delete
   ```

### Collecting Debug Information

```bash
#!/bin/bash
# Debug information collection script

echo "=== Gibson Debug Information ===" > gibson-debug.txt
echo "Date: $(date)" >> gibson-debug.txt
echo "" >> gibson-debug.txt

echo "=== System Information ===" >> gibson-debug.txt
uname -a >> gibson-debug.txt
echo "" >> gibson-debug.txt

echo "=== Gibson Version ===" >> gibson-debug.txt
gibson --version >> gibson-debug.txt 2>&1
echo "" >> gibson-debug.txt

echo "=== Service Status ===" >> gibson-debug.txt
systemctl status gibson >> gibson-debug.txt 2>&1
echo "" >> gibson-debug.txt

echo "=== Configuration ===" >> gibson-debug.txt
gibson validate --config /etc/gibson/config.yaml >> gibson-debug.txt 2>&1
echo "" >> gibson-debug.txt

echo "=== Logs (last 50 lines) ===" >> gibson-debug.txt
tail -50 /var/log/gibson/gibson.log >> gibson-debug.txt 2>&1
echo "" >> gibson-debug.txt

echo "=== File Permissions ===" >> gibson-debug.txt
ls -la /var/lib/gibson/ >> gibson-debug.txt 2>&1
ls -la /etc/gibson/ >> gibson-debug.txt 2>&1
echo "" >> gibson-debug.txt

echo "Debug information collected in gibson-debug.txt"
```

## Recovery Procedures

### Emergency Recovery

1. **Service won't start**:
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Reset to known good state
   sudo /opt/gibson/scripts/restore.sh /var/backups/gibson/latest_backup.tar.gz

   # Start service
   sudo systemctl start gibson
   ```

2. **Complete system recovery**:
   ```bash
   # Reinstall gibson
   curl -fsSL https://example.com/install.sh | bash

   # Restore data
   sudo /opt/gibson/scripts/restore.sh backup_file.tar.gz

   # Verify
   gibson status
   ```

### Data Recovery

1. **Database recovery**:
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Backup current state
   sudo cp /var/lib/gibson/gibson.db /tmp/gibson.db.$(date +%s)

   # Restore from backup
   sudo tar -xzf backup.tar.gz -C /tmp
   sudo cp /tmp/database.db /var/lib/gibson/gibson.db
   sudo chown gibson:gibson /var/lib/gibson/gibson.db

   # Start service
   sudo systemctl start gibson
   ```

2. **Configuration recovery**:
   ```bash
   # Restore configuration
   sudo cp config_backup.yaml /etc/gibson/config.yaml
   sudo chown root:gibson /etc/gibson/config.yaml
   sudo chmod 640 /etc/gibson/config.yaml

   # Reload service
   sudo systemctl reload gibson
   ```

## Getting Help

### Information to Collect

When seeking help, please provide:

1. **System Information**:
   ```bash
   uname -a
   gibson --version
   systemctl --version
   ```

2. **Service Status**:
   ```bash
   systemctl status gibson
   gibson status
   gibson health
   ```

3. **Recent Logs**:
   ```bash
   journalctl -u gibson --since "1 hour ago"
   tail -100 /var/log/gibson/gibson.log
   ```

4. **Configuration**:
   ```bash
   gibson validate --config /etc/gibson/config.yaml
   # Sanitized config (remove sensitive data)
   ```

### Support Channels

- **GitHub Issues**: https://github.com/gibson-sec/gibson-framework-2/issues
- **Documentation**: https://github.com/gibson-sec/gibson-framework-2/docs
- **Discussions**: https://github.com/gibson-sec/gibson-framework-2/discussions
- **Security Issues**: security@gibson-sec.com

### Contributing Fixes

If you've found a solution to a problem:

1. Update this troubleshooting guide
2. Submit a pull request
3. Consider creating an issue template
4. Share in community discussions

## Preventive Measures

### Regular Maintenance

1. **Weekly Tasks**:
   ```bash
   # Check service health
   gibson health

   # Update plugins
   gibson plugin update --all

   # Clean old logs
   sudo logrotate -f /etc/logrotate.d/gibson
   ```

2. **Monthly Tasks**:
   ```bash
   # Create backup
   sudo /opt/gibson/scripts/backup.sh

   # Check disk usage
   df -h /var/lib/gibson

   # Optimize database
   gibson maintenance optimize
   ```

3. **Monitoring Setup**:
   ```bash
   # Set up basic monitoring
   gibson serve --metrics-enabled

   # Configure alerts for common issues
   # (Implementation depends on your monitoring system)
   ```

Remember: Regular backups and monitoring can prevent many issues from becoming critical problems.