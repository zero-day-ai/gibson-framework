#!/bin/bash
# Gibson Framework Migration Script
# Handles version upgrades, schema migrations, and data transformations

set -e

# Configuration
GIBSON_DATA_DIR="${GIBSON_DATA_DIR:-/var/lib/gibson}"
GIBSON_CONFIG_DIR="${GIBSON_CONFIG_DIR:-/etc/gibson}"
GIBSON_LOG_DIR="${GIBSON_LOG_DIR:-/var/log/gibson}"
MIGRATION_LOG="${GIBSON_LOG_DIR}/migration.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    local msg="[INFO] $1"
    echo -e "${BLUE}${msg}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$MIGRATION_LOG" 2>/dev/null || true
}

log_success() {
    local msg="[SUCCESS] $1"
    echo -e "${GREEN}${msg}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$MIGRATION_LOG" 2>/dev/null || true
}

log_warning() {
    local msg="[WARNING] $1"
    echo -e "${YELLOW}${msg}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$MIGRATION_LOG" 2>/dev/null || true
}

log_error() {
    local msg="[ERROR] $1"
    echo -e "${RED}${msg}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${msg}" >> "$MIGRATION_LOG" 2>/dev/null || true
}

# Initialize migration log
init_log() {
    mkdir -p "$GIBSON_LOG_DIR" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Migration started" >> "$MIGRATION_LOG" 2>/dev/null || true
}

# Get current gibson version
get_current_version() {
    if command -v gibson >/dev/null 2>&1; then
        gibson --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown"
    else
        echo "unknown"
    fi
}

# Get database schema version
get_db_version() {
    local db_file="${GIBSON_DATA_DIR}/gibson.db"

    if [[ ! -f "$db_file" ]]; then
        echo "0.0.0"
        return
    fi

    if command -v sqlite3 >/dev/null 2>&1; then
        # Try to get version from metadata table
        local version=$(sqlite3 "$db_file" "SELECT version FROM schema_metadata ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")

        if [[ -z "$version" ]]; then
            # Fallback: check if basic tables exist to determine version
            local table_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('targets', 'scans', 'findings');" 2>/dev/null || echo "0")

            case $table_count in
                3) echo "1.0.0" ;;
                *) echo "0.0.0" ;;
            esac
        else
            echo "$version"
        fi
    else
        log_warning "sqlite3 not available, cannot determine database version"
        echo "unknown"
    fi
}

# Compare versions (returns 0 if v1 == v2, 1 if v1 > v2, -1 if v1 < v2)
compare_versions() {
    local v1="$1"
    local v2="$2"

    if [[ "$v1" == "$v2" ]]; then
        echo 0
        return
    fi

    local IFS=.
    local i ver1=($v1) ver2=($v2)

    # Fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done

    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            echo 1
            return
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            echo -1
            return
        fi
    done

    echo 0
}

# Create backup before migration
create_migration_backup() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_dir="/tmp/gibson_migration_backup_${timestamp}"

    log_info "Creating migration backup"
    mkdir -p "$backup_dir"

    # Backup database
    if [[ -f "${GIBSON_DATA_DIR}/gibson.db" ]]; then
        cp "${GIBSON_DATA_DIR}/gibson.db" "${backup_dir}/gibson.db"
    fi

    # Backup configuration
    if [[ -d "$GIBSON_CONFIG_DIR" ]]; then
        cp -r "$GIBSON_CONFIG_DIR" "${backup_dir}/config"
    fi

    # Backup plugins
    if [[ -d "${GIBSON_DATA_DIR}/plugins" ]]; then
        cp -r "${GIBSON_DATA_DIR}/plugins" "${backup_dir}/plugins"
    fi

    echo "$backup_dir"
    log_success "Migration backup created: $backup_dir"
}

# Database migration functions

# Migrate from 0.0.0 to 1.0.0 (initial schema)
migrate_db_0_0_0_to_1_0_0() {
    local db_file="${GIBSON_DATA_DIR}/gibson.db"

    log_info "Migrating database from 0.0.0 to 1.0.0"

    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$db_file" <<'EOF'
-- Create initial schema
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at DATETIME,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS plugins (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    type TEXT NOT NULL,
    enabled BOOLEAN DEFAULT 1,
    config TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create metadata table
CREATE TABLE IF NOT EXISTS schema_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    migrated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial version
INSERT INTO schema_metadata (version) VALUES ('1.0.0');

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_plugins_enabled ON plugins(enabled);
EOF

        log_success "Database migrated to version 1.0.0"
    else
        log_error "sqlite3 not available, cannot migrate database"
        return 1
    fi
}

# Migrate from 1.0.0 to 1.1.0 (add credentials and payloads)
migrate_db_1_0_0_to_1_1_0() {
    local db_file="${GIBSON_DATA_DIR}/gibson.db"

    log_info "Migrating database from 1.0.0 to 1.1.0"

    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$db_file" <<'EOF'
-- Add credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    username TEXT,
    password TEXT,
    token TEXT,
    key_data TEXT,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add payloads table
CREATE TABLE IF NOT EXISTS payloads (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    tags TEXT,
    severity TEXT,
    enabled BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add reports table
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    format TEXT NOT NULL,
    content TEXT NOT NULL,
    filename TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Add new columns to existing tables
ALTER TABLE targets ADD COLUMN description TEXT;
ALTER TABLE targets ADD COLUMN metadata TEXT;
ALTER TABLE scans ADD COLUMN config TEXT;
ALTER TABLE findings ADD COLUMN remediation TEXT;
ALTER TABLE findings ADD COLUMN references TEXT;

-- Create new indexes
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);
CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);
CREATE INDEX IF NOT EXISTS idx_payloads_enabled ON payloads(enabled);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);

-- Update metadata
INSERT INTO schema_metadata (version) VALUES ('1.1.0');
EOF

        log_success "Database migrated to version 1.1.0"
    else
        log_error "sqlite3 not available, cannot migrate database"
        return 1
    fi
}

# Migrate from 1.1.0 to 2.0.0 (plugin architecture updates)
migrate_db_1_1_0_to_2_0_0() {
    local db_file="${GIBSON_DATA_DIR}/gibson.db"

    log_info "Migrating database from 1.1.0 to 2.0.0"

    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$db_file" <<'EOF'
-- Add plugin_instances table for better plugin management
CREATE TABLE IF NOT EXISTS plugin_instances (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    domain TEXT NOT NULL,
    capabilities TEXT,
    config TEXT,
    status TEXT DEFAULT 'inactive',
    last_seen DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plugin_id) REFERENCES plugins(id)
);

-- Add scan_plugin_results for detailed plugin execution results
CREATE TABLE IF NOT EXISTS scan_plugin_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    plugin_instance_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    results TEXT,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (plugin_instance_id) REFERENCES plugin_instances(id)
);

-- Add audit_log table for security auditing
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Update plugins table schema
ALTER TABLE plugins ADD COLUMN domain TEXT DEFAULT 'unknown';
ALTER TABLE plugins ADD COLUMN capabilities TEXT;
ALTER TABLE plugins ADD COLUMN status TEXT DEFAULT 'inactive';
ALTER TABLE plugins ADD COLUMN last_seen DATETIME;

-- Update scans table
ALTER TABLE scans ADD COLUMN total_plugins INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN completed_plugins INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN failed_plugins INTEGER DEFAULT 0;

-- Create new indexes
CREATE INDEX IF NOT EXISTS idx_plugin_instances_domain ON plugin_instances(domain);
CREATE INDEX IF NOT EXISTS idx_plugin_instances_status ON plugin_instances(status);
CREATE INDEX IF NOT EXISTS idx_scan_plugin_results_scan_id ON scan_plugin_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_plugin_results_status ON scan_plugin_results(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- Update metadata
INSERT INTO schema_metadata (version) VALUES ('2.0.0');
EOF

        log_success "Database migrated to version 2.0.0"
    else
        log_error "sqlite3 not available, cannot migrate database"
        return 1
    fi
}

# Configuration migration functions

# Migrate configuration files
migrate_config() {
    local from_version="$1"
    local to_version="$2"

    log_info "Migrating configuration from $from_version to $to_version"

    local config_file="${GIBSON_CONFIG_DIR}/config.yaml"

    # Create backup of current config
    if [[ -f "$config_file" ]]; then
        cp "$config_file" "${config_file}.backup.$(date +%s)"
    fi

    # Version-specific configuration migrations
    case "$to_version" in
        "1.1.0")
            migrate_config_to_1_1_0
            ;;
        "2.0.0")
            migrate_config_to_2_0_0
            ;;
    esac

    log_success "Configuration migration completed"
}

# Migrate config to version 1.1.0
migrate_config_to_1_1_0() {
    local config_file="${GIBSON_CONFIG_DIR}/config.yaml"

    log_info "Updating configuration for version 1.1.0"

    # Add new configuration sections if they don't exist
    if [[ -f "$config_file" ]]; then
        # Add credentials section if missing
        if ! grep -q "credentials:" "$config_file"; then
            cat >> "$config_file" <<EOF

# Credentials configuration
credentials:
  encryption_key: ""
  storage_path: "${GIBSON_DATA_DIR}/credentials"
EOF
        fi

        # Add payloads section if missing
        if ! grep -q "payloads:" "$config_file"; then
            cat >> "$config_file" <<EOF

# Payloads configuration
payloads:
  directory: "${GIBSON_DATA_DIR}/payloads"
  auto_load: true
  validation: true
EOF
        fi
    fi
}

# Migrate config to version 2.0.0
migrate_config_to_2_0_0() {
    local config_file="${GIBSON_CONFIG_DIR}/config.yaml"

    log_info "Updating configuration for version 2.0.0"

    if [[ -f "$config_file" ]]; then
        # Add plugin management section
        if ! grep -q "plugin_management:" "$config_file"; then
            cat >> "$config_file" <<EOF

# Plugin management configuration
plugin_management:
  discovery_interval: 60 # seconds
  health_check_interval: 300 # seconds
  plugin_timeout: 600 # seconds
  max_concurrent_plugins: 10
  auto_restart_failed: true
EOF
        fi

        # Add security section
        if ! grep -q "security:" "$config_file"; then
            cat >> "$config_file" <<EOF

# Security configuration
security:
  audit_logging: true
  api_key_required: true
  rate_limiting:
    enabled: true
    requests_per_minute: 100
  plugin_sandboxing: true
EOF
        fi

        # Add monitoring section
        if ! grep -q "monitoring:" "$config_file"; then
            cat >> "$config_file" <<EOF

# Monitoring configuration
monitoring:
  metrics_enabled: true
  metrics_port: 9090
  health_check_endpoint: "/health"
  profiling_enabled: false
EOF
        fi
    fi
}

# Plugin migration functions
migrate_plugins() {
    local from_version="$1"
    local to_version="$2"

    log_info "Migrating plugins from $from_version to $to_version"

    local plugins_dir="${GIBSON_DATA_DIR}/plugins"

    if [[ ! -d "$plugins_dir" ]]; then
        log_info "No plugins directory found, creating it"
        mkdir -p "$plugins_dir"
        return
    fi

    # Version-specific plugin migrations
    case "$to_version" in
        "2.0.0")
            migrate_plugins_to_2_0_0
            ;;
    esac

    log_success "Plugin migration completed"
}

# Migrate plugins to version 2.0.0
migrate_plugins_to_2_0_0() {
    local plugins_dir="${GIBSON_DATA_DIR}/plugins"

    log_info "Updating plugins for version 2.0.0"

    # Update plugin manifests to include domain information
    find "$plugins_dir" -name "plugin.yaml" -o -name "plugin.yml" | while read -r manifest; do
        if ! grep -q "domain:" "$manifest"; then
            # Try to determine domain from plugin name/path
            local plugin_path=$(dirname "$manifest")
            local plugin_name=$(basename "$plugin_path")
            local domain="unknown"

            # Simple heuristics to determine domain
            case "$plugin_name" in
                *injection*|*xss*|*sql*|*prompt*) domain="interface" ;;
                *model*|*extraction*|*inversion*) domain="model" ;;
                *data*|*poison*|*corrupt*) domain="data" ;;
                *infra*|*dos*|*auth*) domain="infrastructure" ;;
                *output*|*leak*|*bias*) domain="output" ;;
                *supply*|*governance*) domain="process" ;;
            esac

            # Add domain to manifest
            echo "domain: $domain" >> "$manifest"
            log_info "Added domain '$domain' to plugin: $plugin_name"
        fi
    done
}

# Perform complete migration
perform_migration() {
    local from_version="$1"
    local to_version="$2"

    log_info "Starting migration from $from_version to $to_version"

    # Create backup
    local backup_dir=$(create_migration_backup)

    # Stop gibson service if running
    local service_was_running=false
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active gibson.service >/dev/null 2>&1; then
        log_info "Stopping gibson service for migration"
        systemctl stop gibson.service
        service_was_running=true
    fi

    # Perform migrations based on version path
    local current_version="$from_version"

    # Define migration path
    while [[ $(compare_versions "$current_version" "$to_version") -lt 0 ]]; do
        case "$current_version" in
            "0.0.0")
                migrate_db_0_0_0_to_1_0_0
                current_version="1.0.0"
                ;;
            "1.0.0")
                migrate_db_1_0_0_to_1_1_0
                migrate_config "$current_version" "1.1.0"
                current_version="1.1.0"
                ;;
            "1.1.0")
                migrate_db_1_1_0_to_2_0_0
                migrate_config "$current_version" "2.0.0"
                migrate_plugins "$current_version" "2.0.0"
                current_version="2.0.0"
                ;;
            *)
                log_error "Unknown migration path from version: $current_version"
                break
                ;;
        esac
    done

    # Set proper permissions
    if [[ -d "$GIBSON_DATA_DIR" ]]; then
        chown -R gibson:gibson "$GIBSON_DATA_DIR" 2>/dev/null || true
    fi

    # Restart service if it was running
    if [[ "$service_was_running" == "true" ]]; then
        log_info "Restarting gibson service"
        systemctl start gibson.service
    fi

    log_success "Migration completed successfully!"
    log_info "Backup created at: $backup_dir"
}

# Show migration status
show_status() {
    echo "Gibson Framework Migration Status"
    echo "================================="
    echo

    local current_version=$(get_current_version)
    local db_version=$(get_db_version)

    echo "Current gibson version: $current_version"
    echo "Database schema version: $db_version"
    echo

    if [[ "$current_version" == "unknown" ]]; then
        log_warning "Gibson binary not found or not working"
    elif [[ "$db_version" == "unknown" ]]; then
        log_warning "Cannot determine database version"
    else
        local comparison=$(compare_versions "$db_version" "$current_version")

        if [[ $comparison -eq 0 ]]; then
            log_success "Database schema is up to date"
        elif [[ $comparison -lt 0 ]]; then
            log_warning "Database schema is outdated (migration needed)"
            echo "Run: $0 migrate"
        else
            log_error "Database schema is newer than gibson binary"
            echo "Update gibson binary or restore from backup"
        fi
    fi
}

# Auto-migrate if needed
auto_migrate() {
    local current_version=$(get_current_version)
    local db_version=$(get_db_version)

    if [[ "$current_version" == "unknown" || "$db_version" == "unknown" ]]; then
        log_error "Cannot determine versions for auto-migration"
        return 1
    fi

    local comparison=$(compare_versions "$db_version" "$current_version")

    if [[ $comparison -lt 0 ]]; then
        log_info "Database schema is outdated, performing auto-migration"
        perform_migration "$db_version" "$current_version"
    else
        log_info "No migration needed"
    fi
}

# Show usage
usage() {
    echo "Gibson Framework Migration Tool"
    echo "==============================="
    echo
    echo "Usage: $0 [command] [options]"
    echo
    echo "Commands:"
    echo "  status              Show current migration status"
    echo "  migrate             Perform migration if needed"
    echo "  auto                Auto-migrate (non-interactive)"
    echo "  force <from> <to>   Force migration between specific versions"
    echo "  help                Show this help message"
    echo
    echo "Environment Variables:"
    echo "  GIBSON_DATA_DIR     Data directory (default: /var/lib/gibson)"
    echo "  GIBSON_CONFIG_DIR   Config directory (default: /etc/gibson)"
    echo "  GIBSON_LOG_DIR      Log directory (default: /var/log/gibson)"
    echo
    echo "Examples:"
    echo "  $0 status                 Show migration status"
    echo "  $0 migrate                Interactive migration"
    echo "  $0 auto                   Auto-migrate without prompts"
    echo "  $0 force 1.0.0 2.0.0      Force migration from 1.0.0 to 2.0.0"
}

# Main function
main() {
    init_log

    case "${1:-status}" in
        status)
            show_status
            ;;
        migrate)
            local current_version=$(get_current_version)
            local db_version=$(get_db_version)

            if [[ "$current_version" == "unknown" || "$db_version" == "unknown" ]]; then
                log_error "Cannot determine versions for migration"
                exit 1
            fi

            local comparison=$(compare_versions "$db_version" "$current_version")

            if [[ $comparison -lt 0 ]]; then
                echo "Migration needed from $db_version to $current_version"
                read -p "Continue with migration? [y/N]: " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    perform_migration "$db_version" "$current_version"
                else
                    log_info "Migration cancelled"
                fi
            else
                log_info "No migration needed"
            fi
            ;;
        auto)
            auto_migrate
            ;;
        force)
            if [[ -z "$2" || -z "$3" ]]; then
                log_error "Force migration requires from and to versions"
                usage
                exit 1
            fi
            perform_migration "$2" "$3"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            echo "Unknown command: $1"
            echo
            usage
            exit 1
            ;;
    esac
}

# Check for required commands
for cmd in sqlite3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_warning "$cmd not found, some migration features may not work"
    fi
done

# Run main function
main "$@"