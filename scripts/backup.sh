#!/bin/bash
# Gibson Framework Backup Script
# Creates compressed backups of gibson data, configuration, and logs

set -e

# Configuration
GIBSON_DATA_DIR="${GIBSON_DATA_DIR:-/var/lib/gibson}"
GIBSON_CONFIG_DIR="${GIBSON_CONFIG_DIR:-/etc/gibson}"
GIBSON_LOG_DIR="${GIBSON_LOG_DIR:-/var/log/gibson}"
BACKUP_DIR="${GIBSON_BACKUP_DIR:-/var/backups/gibson}"
BACKUP_RETENTION_DAYS="${GIBSON_BACKUP_RETENTION:-30}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if gibson service is running
check_service() {
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active gibson.service >/dev/null 2>&1; then
            log_warning "Gibson service is running. Consider stopping it for consistent backup."
            read -p "Stop gibson service during backup? [y/N]: " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                log_info "Stopping gibson service"
                sudo systemctl stop gibson.service
                RESTART_SERVICE=true
            fi
        fi
    fi
}

# Create backup directory
create_backup_dir() {
    sudo mkdir -p "$BACKUP_DIR"
    if [[ $? -ne 0 ]]; then
        log_error "Failed to create backup directory: $BACKUP_DIR"
        exit 1
    fi
}

# Backup database
backup_database() {
    local db_file="${GIBSON_DATA_DIR}/gibson.db"
    local backup_file="${TEMP_DIR}/database.db"

    if [[ -f "$db_file" ]]; then
        log_info "Backing up database"

        # Use sqlite3 to create a consistent backup if available
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$db_file" ".backup ${backup_file}"
        else
            # Fallback to file copy
            cp "$db_file" "$backup_file"
        fi

        if [[ -f "$backup_file" ]]; then
            log_success "Database backup created"
        else
            log_error "Failed to backup database"
            return 1
        fi
    else
        log_warning "Database file not found: $db_file"
    fi
}

# Backup configuration
backup_configuration() {
    if [[ -d "$GIBSON_CONFIG_DIR" ]]; then
        log_info "Backing up configuration"
        cp -r "$GIBSON_CONFIG_DIR" "${TEMP_DIR}/config"
        log_success "Configuration backup created"
    else
        log_warning "Configuration directory not found: $GIBSON_CONFIG_DIR"
    fi
}

# Backup plugins
backup_plugins() {
    local plugins_dir="${GIBSON_DATA_DIR}/plugins"

    if [[ -d "$plugins_dir" ]]; then
        log_info "Backing up plugins"
        cp -r "$plugins_dir" "${TEMP_DIR}/plugins"
        log_success "Plugins backup created"
    else
        log_info "No plugins directory found"
    fi
}

# Backup logs (optional, last 7 days)
backup_logs() {
    if [[ -d "$GIBSON_LOG_DIR" ]]; then
        log_info "Backing up recent logs (last 7 days)"
        mkdir -p "${TEMP_DIR}/logs"

        # Find and copy log files modified in last 7 days
        find "$GIBSON_LOG_DIR" -name "*.log" -mtime -7 -exec cp {} "${TEMP_DIR}/logs/" \; 2>/dev/null || true

        log_success "Recent logs backup created"
    else
        log_warning "Log directory not found: $GIBSON_LOG_DIR"
    fi
}

# Create metadata file
create_metadata() {
    local metadata_file="${TEMP_DIR}/backup_metadata.json"

    log_info "Creating backup metadata"

    cat > "$metadata_file" <<EOF
{
    "backup_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "gibson_version": "$(gibson --version 2>/dev/null || echo "unknown")",
    "hostname": "$(hostname)",
    "platform": "$(uname -s)",
    "architecture": "$(uname -m)",
    "backup_script_version": "1.0.0",
    "directories": {
        "data": "$GIBSON_DATA_DIR",
        "config": "$GIBSON_CONFIG_DIR",
        "logs": "$GIBSON_LOG_DIR"
    },
    "components": {
        "database": $([ -f "${TEMP_DIR}/database.db" ] && echo "true" || echo "false"),
        "configuration": $([ -d "${TEMP_DIR}/config" ] && echo "true" || echo "false"),
        "plugins": $([ -d "${TEMP_DIR}/plugins" ] && echo "true" || echo "false"),
        "logs": $([ -d "${TEMP_DIR}/logs" ] && echo "true" || echo "false")
    }
}
EOF

    log_success "Backup metadata created"
}

# Create compressed archive
create_archive() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="${BACKUP_DIR}/gibson_backup_${timestamp}.tar.gz"

    log_info "Creating compressed backup archive"

    cd "$TEMP_DIR"
    tar -czf "$backup_file" .

    if [[ -f "$backup_file" ]]; then
        local size=$(du -h "$backup_file" | cut -f1)
        log_success "Backup created: $backup_file (${size})"

        # Create checksum
        cd "$BACKUP_DIR"
        sha256sum "$(basename "$backup_file")" > "${backup_file}.sha256"
        log_success "Checksum created: ${backup_file}.sha256"

        echo "$backup_file"
    else
        log_error "Failed to create backup archive"
        return 1
    fi
}

# Clean old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups (older than ${BACKUP_RETENTION_DAYS} days)"

    local deleted_count=0
    while IFS= read -r -d '' file; do
        rm -f "$file" "${file}.sha256"
        ((deleted_count++))
        log_info "Deleted old backup: $(basename "$file")"
    done < <(find "$BACKUP_DIR" -name "gibson_backup_*.tar.gz" -mtime +${BACKUP_RETENTION_DAYS} -print0 2>/dev/null)

    if [[ $deleted_count -eq 0 ]]; then
        log_info "No old backups to clean up"
    else
        log_success "Cleaned up $deleted_count old backup(s)"
    fi
}

# Restart service if it was stopped
restart_service() {
    if [[ "$RESTART_SERVICE" == "true" ]]; then
        log_info "Restarting gibson service"
        sudo systemctl start gibson.service

        # Wait a moment and check status
        sleep 2
        if systemctl is-active gibson.service >/dev/null 2>&1; then
            log_success "Gibson service restarted successfully"
        else
            log_error "Failed to restart gibson service"
        fi
    fi
}

# List existing backups
list_backups() {
    echo "Existing Gibson backups:"
    echo "========================"

    if [[ -d "$BACKUP_DIR" ]]; then
        local count=0
        while IFS= read -r -d '' file; do
            local size=$(du -h "$file" | cut -f1)
            local date=$(stat -c %Y "$file" | xargs -I {} date -d @{} "+%Y-%m-%d %H:%M:%S")
            echo "$(basename "$file") - ${size} - ${date}"
            ((count++))
        done < <(find "$BACKUP_DIR" -name "gibson_backup_*.tar.gz" -print0 2>/dev/null | sort -z)

        if [[ $count -eq 0 ]]; then
            echo "No backups found"
        else
            echo
            echo "Total backups: $count"
        fi
    else
        echo "Backup directory does not exist: $BACKUP_DIR"
    fi
}

# Verify backup integrity
verify_backup() {
    local backup_file="$1"

    if [[ -z "$backup_file" ]]; then
        log_error "Backup file not specified"
        return 1
    fi

    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi

    log_info "Verifying backup integrity: $(basename "$backup_file")"

    # Check checksum if available
    local checksum_file="${backup_file}.sha256"
    if [[ -f "$checksum_file" ]]; then
        cd "$(dirname "$backup_file")"
        if sha256sum -c "$(basename "$checksum_file")" >/dev/null 2>&1; then
            log_success "Checksum verification passed"
        else
            log_error "Checksum verification failed"
            return 1
        fi
    else
        log_warning "No checksum file found"
    fi

    # Test archive integrity
    if tar -tzf "$backup_file" >/dev/null 2>&1; then
        log_success "Archive integrity check passed"
    else
        log_error "Archive integrity check failed"
        return 1
    fi

    # Check for metadata
    if tar -tzf "$backup_file" | grep -q "backup_metadata.json"; then
        log_success "Backup metadata found"
    else
        log_warning "No backup metadata found (older backup format?)"
    fi

    log_success "Backup verification completed successfully"
}

# Main backup function
create_backup() {
    log_info "Starting Gibson Framework backup"

    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    # Check service status
    check_service

    # Create backup directory
    create_backup_dir

    # Perform backup operations
    backup_database
    backup_configuration
    backup_plugins
    backup_logs
    create_metadata

    # Create archive
    local backup_file
    backup_file=$(create_archive)

    # Verify the backup
    verify_backup "$backup_file"

    # Cleanup old backups
    cleanup_old_backups

    # Restart service if needed
    restart_service

    log_success "Backup completed successfully!"
    echo
    echo "Backup location: $backup_file"
    echo "To restore: $0 restore $backup_file"
}

# Show usage
usage() {
    echo "Gibson Framework Backup & Restore Tool"
    echo "======================================"
    echo
    echo "Usage: $0 [command] [options]"
    echo
    echo "Commands:"
    echo "  backup              Create a new backup (default)"
    echo "  list                List existing backups"
    echo "  verify <file>       Verify backup integrity"
    echo "  help                Show this help message"
    echo
    echo "Environment Variables:"
    echo "  GIBSON_DATA_DIR           Data directory (default: /var/lib/gibson)"
    echo "  GIBSON_CONFIG_DIR         Config directory (default: /etc/gibson)"
    echo "  GIBSON_LOG_DIR            Log directory (default: /var/log/gibson)"
    echo "  GIBSON_BACKUP_DIR         Backup directory (default: /var/backups/gibson)"
    echo "  GIBSON_BACKUP_RETENTION   Backup retention days (default: 30)"
    echo
    echo "Examples:"
    echo "  $0 backup                 Create a backup"
    echo "  $0 list                   List all backups"
    echo "  $0 verify backup.tar.gz   Verify backup integrity"
}

# Main function
main() {
    case "${1:-backup}" in
        backup)
            create_backup
            ;;
        list)
            list_backups
            ;;
        verify)
            verify_backup "$2"
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
if ! command -v tar >/dev/null 2>&1; then
    log_error "tar command not found"
    exit 1
fi

# Run main function
main "$@"