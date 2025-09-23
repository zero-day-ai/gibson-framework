#!/bin/bash
# Gibson Framework Restore Script
# Restores gibson data from compressed backup archives

set -e

# Configuration
GIBSON_DATA_DIR="${GIBSON_DATA_DIR:-/var/lib/gibson}"
GIBSON_CONFIG_DIR="${GIBSON_CONFIG_DIR:-/etc/gibson}"
GIBSON_LOG_DIR="${GIBSON_LOG_DIR:-/var/log/gibson}"

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

# Check if running as root (required for system directories)
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_info "Please run with sudo: sudo $0"
        exit 1
    fi
}

# Verify backup file
verify_backup_file() {
    local backup_file="$1"

    if [[ -z "$backup_file" ]]; then
        log_error "Backup file not specified"
        return 1
    fi

    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi

    log_info "Verifying backup file: $(basename "$backup_file")"

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
        log_warning "No checksum file found, skipping checksum verification"
    fi

    # Test archive integrity
    if tar -tzf "$backup_file" >/dev/null 2>&1; then
        log_success "Archive integrity check passed"
    else
        log_error "Archive integrity check failed"
        return 1
    fi

    return 0
}

# Stop gibson service
stop_service() {
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active gibson.service >/dev/null 2>&1; then
            log_info "Stopping gibson service"
            systemctl stop gibson.service
            SERVICE_WAS_RUNNING=true

            # Wait for service to stop
            local timeout=30
            while systemctl is-active gibson.service >/dev/null 2>&1 && [[ $timeout -gt 0 ]]; do
                sleep 1
                ((timeout--))
            done

            if systemctl is-active gibson.service >/dev/null 2>&1; then
                log_error "Failed to stop gibson service"
                return 1
            else
                log_success "Gibson service stopped"
            fi
        else
            log_info "Gibson service is not running"
        fi
    else
        log_warning "systemctl not available, cannot manage service"
    fi
}

# Create backup of current data
backup_current_data() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local current_backup_dir="/tmp/gibson_restore_backup_${timestamp}"

    log_info "Creating backup of current data before restore"
    mkdir -p "$current_backup_dir"

    # Backup current database
    if [[ -f "${GIBSON_DATA_DIR}/gibson.db" ]]; then
        cp "${GIBSON_DATA_DIR}/gibson.db" "${current_backup_dir}/gibson.db.bak"
        log_info "Current database backed up"
    fi

    # Backup current configuration
    if [[ -d "$GIBSON_CONFIG_DIR" ]]; then
        cp -r "$GIBSON_CONFIG_DIR" "${current_backup_dir}/config.bak"
        log_info "Current configuration backed up"
    fi

    # Backup current plugins
    if [[ -d "${GIBSON_DATA_DIR}/plugins" ]]; then
        cp -r "${GIBSON_DATA_DIR}/plugins" "${current_backup_dir}/plugins.bak"
        log_info "Current plugins backed up"
    fi

    echo "$current_backup_dir"
    log_success "Current data backed up to: $current_backup_dir"
}

# Extract backup archive
extract_backup() {
    local backup_file="$1"
    local extract_dir="$2"

    log_info "Extracting backup archive"
    tar -xzf "$backup_file" -C "$extract_dir"

    if [[ $? -eq 0 ]]; then
        log_success "Backup archive extracted"
    else
        log_error "Failed to extract backup archive"
        return 1
    fi
}

# Show backup information
show_backup_info() {
    local extract_dir="$1"
    local metadata_file="${extract_dir}/backup_metadata.json"

    if [[ -f "$metadata_file" ]]; then
        log_info "Backup Information:"
        echo "==================="

        if command -v jq >/dev/null 2>&1; then
            echo "Backup Date: $(jq -r '.backup_date' "$metadata_file")"
            echo "Gibson Version: $(jq -r '.gibson_version' "$metadata_file")"
            echo "Source Hostname: $(jq -r '.hostname' "$metadata_file")"
            echo "Source Platform: $(jq -r '.platform' "$metadata_file")"
            echo "Components:"
            echo "  Database: $(jq -r '.components.database' "$metadata_file")"
            echo "  Configuration: $(jq -r '.components.configuration' "$metadata_file")"
            echo "  Plugins: $(jq -r '.components.plugins' "$metadata_file")"
            echo "  Logs: $(jq -r '.components.logs' "$metadata_file")"
        else
            cat "$metadata_file"
        fi
        echo
    else
        log_warning "No backup metadata found (older backup format)"
    fi
}

# Restore database
restore_database() {
    local extract_dir="$1"
    local db_backup="${extract_dir}/database.db"

    if [[ -f "$db_backup" ]]; then
        log_info "Restoring database"

        # Create data directory if it doesn't exist
        mkdir -p "$GIBSON_DATA_DIR"

        # Restore database
        cp "$db_backup" "${GIBSON_DATA_DIR}/gibson.db"
        chown gibson:gibson "${GIBSON_DATA_DIR}/gibson.db" 2>/dev/null || true
        chmod 644 "${GIBSON_DATA_DIR}/gibson.db"

        log_success "Database restored"
    else
        log_warning "No database found in backup"
    fi
}

# Restore configuration
restore_configuration() {
    local extract_dir="$1"
    local config_backup="${extract_dir}/config"

    if [[ -d "$config_backup" ]]; then
        log_info "Restoring configuration"

        # Create config directory if it doesn't exist
        mkdir -p "$GIBSON_CONFIG_DIR"

        # Restore configuration files
        cp -r "${config_backup}"/* "$GIBSON_CONFIG_DIR/"
        chown -R root:root "$GIBSON_CONFIG_DIR" 2>/dev/null || true
        chmod -R 644 "$GIBSON_CONFIG_DIR"/*

        log_success "Configuration restored"
    else
        log_warning "No configuration found in backup"
    fi
}

# Restore plugins
restore_plugins() {
    local extract_dir="$1"
    local plugins_backup="${extract_dir}/plugins"

    if [[ -d "$plugins_backup" ]]; then
        log_info "Restoring plugins"

        # Create plugins directory if it doesn't exist
        mkdir -p "${GIBSON_DATA_DIR}/plugins"

        # Restore plugins
        cp -r "${plugins_backup}"/* "${GIBSON_DATA_DIR}/plugins/"
        chown -R gibson:gibson "${GIBSON_DATA_DIR}/plugins" 2>/dev/null || true
        chmod -R 755 "${GIBSON_DATA_DIR}/plugins"

        log_success "Plugins restored"
    else
        log_info "No plugins found in backup"
    fi
}

# Restore logs (optional)
restore_logs() {
    local extract_dir="$1"
    local logs_backup="${extract_dir}/logs"

    if [[ -d "$logs_backup" ]] && [[ "$(ls -A "$logs_backup")" ]]; then
        read -p "Restore logs from backup? This will overwrite current logs [y/N]: " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Restoring logs"

            # Create log directory if it doesn't exist
            mkdir -p "$GIBSON_LOG_DIR"

            # Restore logs
            cp "${logs_backup}"/* "$GIBSON_LOG_DIR/"
            chown -R gibson:gibson "$GIBSON_LOG_DIR" 2>/dev/null || true
            chmod -R 644 "$GIBSON_LOG_DIR"/*

            log_success "Logs restored"
        else
            log_info "Skipping log restoration"
        fi
    else
        log_info "No logs found in backup"
    fi
}

# Set proper permissions
set_permissions() {
    log_info "Setting proper permissions"

    # Set data directory permissions
    if [[ -d "$GIBSON_DATA_DIR" ]]; then
        chown -R gibson:gibson "$GIBSON_DATA_DIR" 2>/dev/null || true
        chmod 755 "$GIBSON_DATA_DIR"
    fi

    # Set config directory permissions
    if [[ -d "$GIBSON_CONFIG_DIR" ]]; then
        chown -R root:root "$GIBSON_CONFIG_DIR" 2>/dev/null || true
        chmod 755 "$GIBSON_CONFIG_DIR"
        find "$GIBSON_CONFIG_DIR" -type f -exec chmod 644 {} \;
    fi

    # Set log directory permissions
    if [[ -d "$GIBSON_LOG_DIR" ]]; then
        chown -R gibson:gibson "$GIBSON_LOG_DIR" 2>/dev/null || true
        chmod 755 "$GIBSON_LOG_DIR"
        find "$GIBSON_LOG_DIR" -type f -exec chmod 644 {} \; 2>/dev/null || true
    fi

    log_success "Permissions set"
}

# Start gibson service
start_service() {
    if [[ "$SERVICE_WAS_RUNNING" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
        log_info "Starting gibson service"
        systemctl start gibson.service

        # Wait a moment and check status
        sleep 3
        if systemctl is-active gibson.service >/dev/null 2>&1; then
            log_success "Gibson service started successfully"
        else
            log_error "Failed to start gibson service"
            log_info "Check service status: systemctl status gibson.service"
        fi
    fi
}

# Validate restored data
validate_restoration() {
    log_info "Validating restoration"

    # Check database
    if [[ -f "${GIBSON_DATA_DIR}/gibson.db" ]]; then
        if command -v sqlite3 >/dev/null 2>&1; then
            if sqlite3 "${GIBSON_DATA_DIR}/gibson.db" "SELECT COUNT(*) FROM sqlite_master;" >/dev/null 2>&1; then
                log_success "Database validation passed"
            else
                log_error "Database validation failed"
                return 1
            fi
        else
            log_info "sqlite3 not available, skipping database validation"
        fi
    fi

    # Check configuration
    if [[ -f "${GIBSON_CONFIG_DIR}/config.yaml" ]]; then
        log_success "Configuration file found"
    else
        log_warning "Configuration file not found"
    fi

    # Check gibson binary
    if command -v gibson >/dev/null 2>&1; then
        if gibson --version >/dev/null 2>&1; then
            log_success "Gibson binary validation passed"
        else
            log_error "Gibson binary validation failed"
        fi
    else
        log_warning "Gibson binary not found in PATH"
    fi

    log_success "Validation completed"
}

# Interactive restoration mode
interactive_restore() {
    local backup_file="$1"

    echo "Gibson Framework Interactive Restore"
    echo "===================================="
    echo
    echo "This will restore Gibson from: $(basename "$backup_file")"
    echo
    log_warning "This operation will overwrite existing Gibson data!"
    echo

    # Create temporary directory and extract backup
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    extract_backup "$backup_file" "$temp_dir"
    show_backup_info "$temp_dir"

    # Confirm restoration
    read -p "Continue with restoration? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Restoration cancelled"
        exit 0
    fi

    # Component selection
    echo "Select components to restore:"
    echo "============================"

    local restore_database=false
    local restore_config=false
    local restore_plugins=false

    if [[ -f "${temp_dir}/database.db" ]]; then
        read -p "Restore database? [y/N]: " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && restore_database=true
    fi

    if [[ -d "${temp_dir}/config" ]]; then
        read -p "Restore configuration? [y/N]: " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && restore_config=true
    fi

    if [[ -d "${temp_dir}/plugins" ]]; then
        read -p "Restore plugins? [y/N]: " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && restore_plugins=true
    fi

    echo

    # Perform restoration
    stop_service
    local current_backup=$(backup_current_data)

    if [[ "$restore_database" == "true" ]]; then
        restore_database "$temp_dir"
    fi

    if [[ "$restore_config" == "true" ]]; then
        restore_configuration "$temp_dir"
    fi

    if [[ "$restore_plugins" == "true" ]]; then
        restore_plugins "$temp_dir"
    fi

    restore_logs "$temp_dir"
    set_permissions
    validate_restoration
    start_service

    log_success "Restoration completed successfully!"
    echo
    echo "Current data backed up to: $current_backup"
    echo "To rollback: cp -r ${current_backup}/* <target_directories>"
}

# Full restoration mode
full_restore() {
    local backup_file="$1"

    log_info "Starting full restoration from: $(basename "$backup_file")"

    # Create temporary directory and extract backup
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    extract_backup "$backup_file" "$temp_dir"
    show_backup_info "$temp_dir"

    # Perform restoration
    stop_service
    local current_backup=$(backup_current_data)

    restore_database "$temp_dir"
    restore_configuration "$temp_dir"
    restore_plugins "$temp_dir"
    restore_logs "$temp_dir"
    set_permissions
    validate_restoration
    start_service

    log_success "Full restoration completed successfully!"
    echo
    echo "Current data backed up to: $current_backup"
}

# Show usage
usage() {
    echo "Gibson Framework Restore Tool"
    echo "============================"
    echo
    echo "Usage: $0 [command] <backup_file>"
    echo
    echo "Commands:"
    echo "  restore <file>      Interactive restoration (default)"
    echo "  full <file>         Full restoration (non-interactive)"
    echo "  info <file>         Show backup information"
    echo "  verify <file>       Verify backup integrity"
    echo "  help                Show this help message"
    echo
    echo "Environment Variables:"
    echo "  GIBSON_DATA_DIR     Data directory (default: /var/lib/gibson)"
    echo "  GIBSON_CONFIG_DIR   Config directory (default: /etc/gibson)"
    echo "  GIBSON_LOG_DIR      Log directory (default: /var/log/gibson)"
    echo
    echo "Examples:"
    echo "  $0 restore backup.tar.gz     Interactive restoration"
    echo "  $0 full backup.tar.gz         Full restoration"
    echo "  $0 info backup.tar.gz         Show backup information"
    echo "  $0 verify backup.tar.gz       Verify backup integrity"
}

# Show backup information only
show_info() {
    local backup_file="$1"

    if ! verify_backup_file "$backup_file"; then
        exit 1
    fi

    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    extract_backup "$backup_file" "$temp_dir"
    show_backup_info "$temp_dir"
}

# Main function
main() {
    case "${1:-restore}" in
        restore)
            check_root
            if [[ -z "$2" ]]; then
                log_error "Backup file not specified"
                usage
                exit 1
            fi
            verify_backup_file "$2" && interactive_restore "$2"
            ;;
        full)
            check_root
            if [[ -z "$2" ]]; then
                log_error "Backup file not specified"
                usage
                exit 1
            fi
            verify_backup_file "$2" && full_restore "$2"
            ;;
        info)
            if [[ -z "$2" ]]; then
                log_error "Backup file not specified"
                usage
                exit 1
            fi
            show_info "$2"
            ;;
        verify)
            if [[ -z "$2" ]]; then
                log_error "Backup file not specified"
                usage
                exit 1
            fi
            verify_backup_file "$2"
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
for cmd in tar mkdir; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "$cmd command not found"
        exit 1
    fi
done

# Run main function
main "$@"