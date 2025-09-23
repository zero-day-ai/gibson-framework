# Gibson Framework Deployment Guide

This comprehensive guide covers all aspects of deploying the Gibson Framework in production environments.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Production Deployment](#production-deployment)
- [Container Deployment](#container-deployment)
- [Security Considerations](#security-considerations)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling and Performance](#scaling-and-performance)
- [Troubleshooting](#troubleshooting)
- [Migration and Upgrades](#migration-and-upgrades)

## Quick Start

For a rapid production deployment on Ubuntu/Debian systems:

```bash
# Download and run the installation script
curl -fsSL https://raw.githubusercontent.com/gibson-sec/gibson-framework-2/main/scripts/install.sh | bash

# Start the service
sudo systemctl start gibson
sudo systemctl enable gibson

# Check status
sudo systemctl status gibson
```

## Installation Methods

### 1. Automated Installation Script (Recommended)

The installation script supports Linux, macOS, and FreeBSD:

```bash
# Install latest version
curl -fsSL https://raw.githubusercontent.com/gibson-sec/gibson-framework-2/main/scripts/install.sh | bash

# Install specific version
curl -fsSL https://raw.githubusercontent.com/gibson-sec/gibson-framework-2/main/scripts/install.sh | bash -s -- --version v2.0.0

# Verify installation
gibson --version
```

**Features:**
- Automatic platform detection
- System user creation
- Service configuration
- Shell completion setup
- Security hardening

### 2. Package Managers

#### Homebrew (macOS)

```bash
# Add tap (if not done automatically)
brew tap gibson-sec/gibson

# Install gibson
brew install gibson

# Start service
brew services start gibson
```

#### APT (Ubuntu/Debian)

```bash
# Download and install DEB package
wget https://github.com/gibson-sec/gibson-framework-2/releases/latest/download/gibson_VERSION_amd64.deb
sudo dpkg -i gibson_VERSION_amd64.deb
sudo apt-get install -f  # Fix any dependency issues
```

#### YUM/DNF (CentOS/RHEL/Fedora)

```bash
# Download and install RPM package
wget https://github.com/gibson-sec/gibson-framework-2/releases/latest/download/gibson-VERSION-1.x86_64.rpm
sudo rpm -ivh gibson-VERSION-1.x86_64.rpm
```

### 3. Manual Installation

#### Binary Installation

```bash
# Download binary for your platform
wget https://github.com/gibson-sec/gibson-framework-2/releases/latest/download/gibson-linux-amd64.tar.gz

# Extract and install
tar -xzf gibson-linux-amd64.tar.gz
sudo mv gibson-linux-amd64 /usr/local/bin/gibson
sudo chmod +x /usr/local/bin/gibson

# Create directories
sudo mkdir -p /etc/gibson /var/lib/gibson /var/log/gibson

# Create service user
sudo useradd --system --shell /bin/false gibson
```

#### From Source

```bash
# Prerequisites
go version  # Requires Go 1.24+

# Clone repository
git clone https://github.com/gibson-sec/gibson-framework-2.git
cd gibson-framework-2

# Build
make build

# Install
sudo make install
```

## Configuration

### Basic Configuration

Gibson uses YAML configuration files located at `/etc/gibson/config.yaml`:

```yaml
# Server configuration
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: "/etc/gibson/certs/server.crt"
    key_file: "/etc/gibson/certs/server.key"

# Database configuration
database:
  path: "/var/lib/gibson/gibson.db"
  max_connections: 25
  connection_timeout: 30s

# Logging configuration
logging:
  level: "info"  # debug, info, warn, error
  file: "/var/log/gibson/gibson.log"
  max_size: 100 # MB
  max_backups: 5
  max_age: 30 # days
  format: "json"  # json, text

# Plugin configuration
plugins:
  directory: "/var/lib/gibson/plugins"
  timeout: 300 # seconds
  max_concurrent: 10
  auto_discovery: true
  health_check_interval: 60s

# Security configuration
security:
  api_key_required: true
  api_keys:
    - name: "admin"
      key: "your-secure-api-key-here"
      permissions: ["read", "write", "admin"]
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst: 200
  audit_logging: true

# Plugin management
plugin_management:
  discovery_interval: 60s
  health_check_interval: 300s
  plugin_timeout: 600s
  auto_restart_failed: true

# Monitoring
monitoring:
  metrics_enabled: true
  metrics_port: 9090
  health_check_endpoint: "/health"
  profiling_enabled: false
```

### Environment Variables

Gibson supports environment variable overrides:

```bash
# Server configuration
export GIBSON_SERVER_HOST=0.0.0.0
export GIBSON_SERVER_PORT=8080

# Database configuration
export GIBSON_DATABASE_PATH=/var/lib/gibson/gibson.db

# Logging configuration
export GIBSON_LOG_LEVEL=info
export GIBSON_LOG_FILE=/var/log/gibson/gibson.log

# Security
export GIBSON_API_KEY=your-secure-key
export GIBSON_AUDIT_LOGGING=true
```

### Configuration Validation

```bash
# Validate configuration
gibson validate --config /etc/gibson/config.yaml

# Test configuration
gibson test-config --config /etc/gibson/config.yaml
```

## Production Deployment

### Systemd Service (Linux)

The service file is automatically installed with the script or packages:

```ini
[Unit]
Description=Gibson Framework - AI/ML Security Testing
Documentation=https://github.com/gibson-sec/gibson-framework-2
After=network.target
Wants=network.target

[Service]
Type=simple
User=gibson
Group=gibson
ExecStart=/usr/local/bin/gibson serve --config /etc/gibson/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gibson /var/log/gibson

[Install]
WantedBy=multi-user.target
```

**Service Management:**

```bash
# Start service
sudo systemctl start gibson

# Enable at boot
sudo systemctl enable gibson

# Check status
sudo systemctl status gibson

# View logs
sudo journalctl -u gibson -f

# Reload configuration
sudo systemctl reload gibson

# Restart service
sudo systemctl restart gibson
```

### Launchd Service (macOS)

For Homebrew installations, services are managed with:

```bash
# Start service
brew services start gibson

# Stop service
brew services stop gibson

# Restart service
brew services restart gibson
```

### Init Scripts (Legacy Systems)

For systems without systemd, create `/etc/init.d/gibson`:

```bash
#!/bin/bash
# gibson        Gibson Framework service
# chkconfig: 35 80 20
# description: Gibson Framework AI/ML Security Testing

. /etc/rc.d/init.d/functions

USER="gibson"
DAEMON="gibson"
ROOT_DIR="/var/lib/gibson"
DAEMON_PATH="/usr/local/bin"
CONFIG_FILE="/etc/gibson/config.yaml"

LOCK_FILE="/var/lock/subsys/gibson"

start() {
    if [ -f $LOCK_FILE ]; then
        echo "Gibson is already running."
        exit 1
    fi

    echo -n "Starting $DAEMON: "
    runuser -l "$USER" -c "$DAEMON_PATH/$DAEMON serve --config $CONFIG_FILE" && echo_success || echo_failure
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && touch $LOCK_FILE
    return $RETVAL
}

stop() {
    echo -n "Shutting down $DAEMON: "
    pid=`ps -aefw | grep "$DAEMON" | grep -v " grep " | awk '{print $2}'`
    kill -9 $pid > /dev/null 2>&1
    [ $? -eq 0 ] && echo_success || echo_failure
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && rm -f $LOCK_FILE
    return $RETVAL
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status)
        if [ -f $LOCK_FILE ]; then
            echo "$DAEMON is running."
        else
            echo "$DAEMON is stopped."
        fi
        ;;
    *)
        echo "Usage: {start|stop|restart|status}"
        exit 1
        ;;
esac

exit $?
```

## Container Deployment

### Docker

#### Basic Docker Deployment

```bash
# Pull the latest image
docker pull ghcr.io/gibson-sec/gibson-framework-2:latest

# Run container
docker run -d \
  --name gibson \
  -p 8080:8080 \
  -v gibson-data:/var/lib/gibson \
  -v gibson-config:/etc/gibson \
  -v gibson-logs:/var/log/gibson \
  ghcr.io/gibson-sec/gibson-framework-2:latest
```

#### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  gibson:
    image: ghcr.io/gibson-sec/gibson-framework-2:latest
    container_name: gibson
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "9090:9090"  # Metrics port
    volumes:
      - gibson-data:/var/lib/gibson
      - gibson-config:/etc/gibson
      - gibson-logs:/var/log/gibson
      - ./config.yaml:/etc/gibson/config.yaml:ro
    environment:
      - GIBSON_LOG_LEVEL=info
      - GIBSON_DATABASE_PATH=/var/lib/gibson/gibson.db
    healthcheck:
      test: ["CMD", "gibson", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  gibson-data:
  gibson-config:
  gibson-logs:
```

Start with:

```bash
docker-compose up -d
```

### Kubernetes

#### Basic Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gibson
  labels:
    app: gibson
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gibson
  template:
    metadata:
      labels:
        app: gibson
    spec:
      containers:
      - name: gibson
        image: ghcr.io/gibson-sec/gibson-framework-2:latest
        ports:
        - containerPort: 8080
        - containerPort: 9090
        env:
        - name: GIBSON_LOG_LEVEL
          value: "info"
        - name: GIBSON_DATABASE_PATH
          value: "/var/lib/gibson/gibson.db"
        volumeMounts:
        - name: gibson-data
          mountPath: /var/lib/gibson
        - name: gibson-config
          mountPath: /etc/gibson
        - name: gibson-logs
          mountPath: /var/log/gibson
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: gibson-data
        persistentVolumeClaim:
          claimName: gibson-data-pvc
      - name: gibson-config
        configMap:
          name: gibson-config
      - name: gibson-logs
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: gibson-service
spec:
  selector:
    app: gibson
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: gibson-data-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: gibson-config
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 8080
    database:
      path: "/var/lib/gibson/gibson.db"
    logging:
      level: "info"
      file: "/var/log/gibson/gibson.log"
    plugins:
      directory: "/var/lib/gibson/plugins"
    security:
      api_key_required: true
```

#### Helm Chart

Create a Helm chart for more complex deployments:

```bash
# Install gibson with Helm
helm repo add gibson https://gibson-sec.github.io/helm-charts
helm install gibson gibson/gibson-framework-2
```

## Security Considerations

### Network Security

1. **Firewall Configuration**
   ```bash
   # Allow only necessary ports
   sudo ufw allow 8080/tcp  # Gibson API
   sudo ufw allow 9090/tcp  # Metrics (if needed)
   ```

2. **TLS Configuration**
   ```yaml
   server:
     tls:
       enabled: true
       cert_file: "/etc/gibson/certs/server.crt"
       key_file: "/etc/gibson/certs/server.key"
       min_version: "1.2"
       cipher_suites:
         - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
         - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
   ```

3. **Reverse Proxy with Nginx**
   ```nginx
   server {
       listen 443 ssl http2;
       server_name gibson.example.com;

       ssl_certificate /etc/ssl/certs/gibson.crt;
       ssl_certificate_key /etc/ssl/private/gibson.key;

       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Access Control

1. **API Key Management**
   ```yaml
   security:
     api_key_required: true
     api_keys:
       - name: "admin"
         key: "admin-key-32-chars-minimum-length"
         permissions: ["read", "write", "admin"]
       - name: "readonly"
         key: "readonly-key-32-chars-minimum"
         permissions: ["read"]
   ```

2. **Rate Limiting**
   ```yaml
   security:
     rate_limiting:
       enabled: true
       requests_per_minute: 100
       burst: 200
       key_func: "ip"  # or "api_key"
   ```

3. **Audit Logging**
   ```yaml
   security:
     audit_logging: true
     audit_log_file: "/var/log/gibson/audit.log"
     audit_events:
       - "login"
       - "logout"
       - "api_call"
       - "config_change"
   ```

### File System Security

1. **File Permissions**
   ```bash
   # Set proper permissions
   sudo chown -R gibson:gibson /var/lib/gibson
   sudo chmod 750 /var/lib/gibson
   sudo chmod 640 /var/lib/gibson/gibson.db

   sudo chown -R root:gibson /etc/gibson
   sudo chmod 750 /etc/gibson
   sudo chmod 640 /etc/gibson/config.yaml
   ```

2. **SELinux/AppArmor**

   For SELinux:
   ```bash
   # Create and install SELinux policy
   sudo setsebool -P httpd_can_network_connect 1
   sudo semanage port -a -t http_port_t -p tcp 8080
   ```

## Monitoring and Logging

### Prometheus Metrics

Gibson exposes Prometheus metrics on port 9090:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'gibson'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    metrics_path: '/metrics'
```

**Key Metrics:**
- `gibson_scans_total` - Total number of scans
- `gibson_plugins_active` - Number of active plugins
- `gibson_requests_duration_seconds` - Request duration histogram
- `gibson_database_connections` - Database connection pool status

### Grafana Dashboard

Import the Gibson Grafana dashboard:

```bash
# Download dashboard
wget https://raw.githubusercontent.com/gibson-sec/gibson-framework-2/main/monitoring/grafana-dashboard.json

# Import in Grafana UI or via API
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @grafana-dashboard.json
```

### Log Management

#### Structured Logging

Configure JSON logging for better parsing:

```yaml
logging:
  format: "json"
  level: "info"
  file: "/var/log/gibson/gibson.log"
  fields:
    service: "gibson"
    version: "2.0.0"
```

#### Log Rotation

Using logrotate:

```bash
# /etc/logrotate.d/gibson
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

#### Centralized Logging with ELK Stack

Filebeat configuration:

```yaml
# /etc/filebeat/conf.d/gibson.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/gibson/*.log
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    service: gibson
    environment: production

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "gibson-%{+yyyy.MM.dd}"
```

## Backup and Recovery

### Automated Backups

Set up automated backups using the provided script:

```bash
# Create backup
sudo /opt/gibson/scripts/backup.sh

# Schedule daily backups
echo "0 2 * * * root /opt/gibson/scripts/backup.sh" | sudo tee -a /etc/crontab

# Configure backup retention
export GIBSON_BACKUP_RETENTION=30  # days
```

### Backup Configuration

```bash
# Environment variables for backup script
export GIBSON_BACKUP_DIR="/var/backups/gibson"
export GIBSON_BACKUP_RETENTION=30
export GIBSON_BACKUP_COMPRESSION=gzip

# S3 backup (optional)
export GIBSON_S3_BUCKET="gibson-backups"
export GIBSON_S3_REGION="us-west-2"
```

### Disaster Recovery

1. **Full System Recovery**
   ```bash
   # Restore from backup
   sudo /opt/gibson/scripts/restore.sh /var/backups/gibson/gibson_backup_20240915_120000.tar.gz

   # Verify restoration
   sudo systemctl start gibson
   gibson status
   ```

2. **Database Recovery**
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Restore database only
   sudo cp backup/gibson.db /var/lib/gibson/gibson.db
   sudo chown gibson:gibson /var/lib/gibson/gibson.db

   # Start service
   sudo systemctl start gibson
   ```

3. **Configuration Recovery**
   ```bash
   # Restore configuration
   sudo cp backup/config/* /etc/gibson/
   sudo chown -R root:gibson /etc/gibson
   sudo chmod 640 /etc/gibson/*.yaml

   # Reload service
   sudo systemctl reload gibson
   ```

## Scaling and Performance

### Horizontal Scaling

Gibson can be scaled horizontally using a shared database:

```yaml
# Load balancer configuration (HAProxy example)
backend gibson_servers
    balance roundrobin
    server gibson1 10.0.1.10:8080 check
    server gibson2 10.0.1.11:8080 check
    server gibson3 10.0.1.12:8080 check
```

### Database Optimization

1. **SQLite Optimization**
   ```yaml
   database:
     path: "/var/lib/gibson/gibson.db"
     pragma:
       journal_mode: "WAL"
       synchronous: "NORMAL"
       cache_size: "-64000"  # 64MB
       temp_store: "memory"
   ```

2. **PostgreSQL Backend** (if supported)
   ```yaml
   database:
     type: "postgresql"
     host: "postgres.example.com"
     port: 5432
     name: "gibson"
     user: "gibson"
     password: "secure-password"
     sslmode: "require"
     max_connections: 25
   ```

### Performance Tuning

1. **System Resources**
   ```bash
   # Increase file limits
   echo "gibson soft nofile 65536" | sudo tee -a /etc/security/limits.conf
   echo "gibson hard nofile 65536" | sudo tee -a /etc/security/limits.conf
   ```

2. **Gibson Configuration**
   ```yaml
   plugins:
     max_concurrent: 20  # Increase based on CPU cores
     timeout: 600
     worker_pool_size: 100

   server:
     read_timeout: 30s
     write_timeout: 30s
     idle_timeout: 120s
     max_header_bytes: 1048576
   ```

3. **Operating System Tuning**
   ```bash
   # Kernel parameters
   echo "net.core.somaxconn = 1024" | sudo tee -a /etc/sysctl.conf
   echo "net.ipv4.tcp_max_syn_backlog = 1024" | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```

## Migration and Upgrades

### Version Upgrades

1. **Automated Migration**
   ```bash
   # Check migration status
   gibson migrate status

   # Perform migration
   gibson migrate auto
   ```

2. **Manual Migration**
   ```bash
   # Stop service
   sudo systemctl stop gibson

   # Backup data
   sudo /opt/gibson/scripts/backup.sh

   # Update binary
   sudo wget -O /usr/local/bin/gibson https://github.com/gibson-sec/gibson-framework-2/releases/latest/download/gibson-linux-amd64
   sudo chmod +x /usr/local/bin/gibson

   # Run migration
   sudo -u gibson gibson migrate

   # Start service
   sudo systemctl start gibson
   ```

### Zero-Downtime Deployment

For critical environments:

```bash
#!/bin/bash
# Zero-downtime deployment script

# Start new instance on different port
gibson serve --port 8081 --config /etc/gibson/config.yaml &
NEW_PID=$!

# Wait for health check
while ! curl -s http://localhost:8081/health; do
    sleep 1
done

# Update load balancer to point to new instance
# (Implementation depends on your load balancer)

# Stop old instance
kill $OLD_PID

# Update load balancer back to port 8080
# Start production instance on port 8080
gibson serve --port 8080 --config /etc/gibson/config.yaml &

# Stop temporary instance
kill $NEW_PID
```

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   # Check service status
   sudo systemctl status gibson

   # Check logs
   sudo journalctl -u gibson -f

   # Validate configuration
   gibson validate --config /etc/gibson/config.yaml
   ```

2. **Permission Issues**
   ```bash
   # Fix permissions
   sudo chown -R gibson:gibson /var/lib/gibson
   sudo chmod 755 /var/lib/gibson
   sudo chmod 644 /var/lib/gibson/gibson.db
   ```

3. **Database Issues**
   ```bash
   # Check database integrity
   sqlite3 /var/lib/gibson/gibson.db "PRAGMA integrity_check;"

   # Backup and restore
   sudo /opt/gibson/scripts/backup.sh
   sudo /opt/gibson/scripts/restore.sh backup_file.tar.gz
   ```

### Performance Issues

1. **High CPU Usage**
   ```bash
   # Check plugin usage
   gibson plugin list --status

   # Reduce concurrent plugins
   # Edit /etc/gibson/config.yaml
   plugins:
     max_concurrent: 5
   ```

2. **Memory Issues**
   ```bash
   # Monitor memory usage
   sudo systemctl status gibson

   # Restart service to clear memory
   sudo systemctl restart gibson
   ```

3. **Database Performance**
   ```bash
   # Analyze database
   sqlite3 /var/lib/gibson/gibson.db "ANALYZE;"

   # Vacuum database
   sqlite3 /var/lib/gibson/gibson.db "VACUUM;"
   ```

For more troubleshooting information, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Support and Resources

- **Documentation**: https://github.com/gibson-sec/gibson-framework-2/docs
- **Issues**: https://github.com/gibson-sec/gibson-framework-2/issues
- **Discussions**: https://github.com/gibson-sec/gibson-framework-2/discussions
- **Security Issues**: security@gibson-sec.com

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.