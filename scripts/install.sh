#!/bin/bash
# Gibson Framework Installation Script
# Supports: Linux (Ubuntu/Debian/CentOS/RHEL), macOS, FreeBSD

set -e

# Configuration
GITHUB_REPO="zero-day-ai/gibson-framework"
BINARY_NAME="gibson"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/gibson"
DATA_DIR="/var/lib/gibson"
LOG_DIR="/var/log/gibson"
SERVICE_USER="gibson"

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

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root"
        log_info "Please run as a normal user with sudo privileges"
        exit 1
    fi
}

# Detect operating system and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case $OS in
        linux)
            PLATFORM="linux"
            ;;
        darwin)
            PLATFORM="darwin"
            ;;
        freebsd)
            PLATFORM="freebsd"
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    BINARY_SUFFIX="${PLATFORM}-${ARCH}"
    log_info "Detected platform: ${PLATFORM}-${ARCH}"
}

# Get latest release version from GitHub
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget is available"
        exit 1
    fi

    if [[ -z "$VERSION" ]]; then
        log_error "Failed to get latest version"
        exit 1
    fi

    log_info "Latest version: $VERSION"
}

# Download and extract binary
download_binary() {
    local temp_dir=$(mktemp -d)
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}-${BINARY_SUFFIX}.tar.gz"

    if [[ $PLATFORM == "darwin" ]]; then
        download_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}-${BINARY_SUFFIX}.tar.gz"
    fi

    log_info "Downloading from: $download_url"

    if command -v curl >/dev/null 2>&1; then
        curl -L -o "${temp_dir}/${BINARY_NAME}.tar.gz" "$download_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "${temp_dir}/${BINARY_NAME}.tar.gz" "$download_url"
    fi

    # Extract binary
    cd "$temp_dir"
    tar -xzf "${BINARY_NAME}.tar.gz"

    # Make binary executable
    chmod +x "${BINARY_NAME}-${BINARY_SUFFIX}"

    # Copy to temp location
    cp "${BINARY_NAME}-${BINARY_SUFFIX}" "/tmp/${BINARY_NAME}"

    # Cleanup
    rm -rf "$temp_dir"

    log_success "Binary downloaded and extracted"
}

# Install binary
install_binary() {
    log_info "Installing binary to ${INSTALL_DIR}"

    # Create install directory if it doesn't exist
    sudo mkdir -p "$INSTALL_DIR"

    # Copy binary
    sudo cp "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    # Cleanup temp file
    rm -f "/tmp/${BINARY_NAME}"

    log_success "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

# Create system user
create_user() {
    if [[ $PLATFORM == "linux" ]]; then
        if ! id "$SERVICE_USER" &>/dev/null; then
            log_info "Creating system user: $SERVICE_USER"
            sudo useradd --system --shell /bin/false --home-dir /nonexistent --no-create-home "$SERVICE_USER"
            log_success "System user created: $SERVICE_USER"
        else
            log_info "System user already exists: $SERVICE_USER"
        fi
    fi
}

# Create directories
create_directories() {
    log_info "Creating application directories"

    # Create directories
    sudo mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

    # Set ownership and permissions
    if [[ $PLATFORM == "linux" ]]; then
        sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
        sudo chown -R root:root "$CONFIG_DIR"
        sudo chmod 755 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    else
        sudo chmod 755 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    fi

    log_success "Directories created and configured"
}

# Create default configuration
create_config() {
    local config_file="${CONFIG_DIR}/config.yaml"

    if [[ ! -f "$config_file" ]]; then
        log_info "Creating default configuration"

        sudo tee "$config_file" > /dev/null <<EOF
# Gibson Framework Configuration
# See https://github.com/zero-day-ai/gibson-framework for documentation

# Server configuration
server:
  host: "0.0.0.0"
  port: 8080

# Database configuration
database:
  path: "${DATA_DIR}/gibson.db"

# Logging configuration
logging:
  level: "info"
  file: "${LOG_DIR}/gibson.log"
  max_size: 100 # MB
  max_backups: 5
  max_age: 30 # days

# Plugin configuration
plugins:
  directory: "${DATA_DIR}/plugins"
  timeout: 300 # seconds

# Security configuration
security:
  api_key_required: true
  rate_limit: 100 # requests per minute
EOF

        sudo chmod 644 "$config_file"
        log_success "Default configuration created: $config_file"
    else
        log_info "Configuration file already exists: $config_file"
    fi
}

# Install systemd service (Linux only)
install_service() {
    if [[ $PLATFORM == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
        log_info "Installing systemd service"

        sudo tee /etc/systemd/system/gibson.service > /dev/null <<EOF
[Unit]
Description=Gibson Framework - AI/ML Security Testing
Documentation=https://github.com/zero-day-ai/gibson-framework
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=${INSTALL_DIR}/${BINARY_NAME} serve --config ${CONFIG_DIR}/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Working directory
WorkingDirectory=${DATA_DIR}

# Environment
Environment=GIBSON_CONFIG=${CONFIG_DIR}/config.yaml
Environment=GIBSON_DATA_DIR=${DATA_DIR}
Environment=GIBSON_LOG_DIR=${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF

        # Reload systemd and enable service
        sudo systemctl daemon-reload
        sudo systemctl enable gibson.service

        log_success "Systemd service installed and enabled"
    fi
}

# Install shell completion
install_completion() {
    if command -v "${INSTALL_DIR}/${BINARY_NAME}" >/dev/null 2>&1; then
        log_info "Installing shell completion"

        # Bash completion
        if [[ -d /etc/bash_completion.d ]]; then
            sudo "${INSTALL_DIR}/${BINARY_NAME}" completion bash > /tmp/gibson-completion.bash
            sudo mv /tmp/gibson-completion.bash /etc/bash_completion.d/gibson
            log_success "Bash completion installed"
        fi

        # Zsh completion
        if [[ -d /usr/local/share/zsh/site-functions ]]; then
            sudo "${INSTALL_DIR}/${BINARY_NAME}" completion zsh > /tmp/_gibson
            sudo mv /tmp/_gibson /usr/local/share/zsh/site-functions/_gibson
            log_success "Zsh completion installed"
        fi
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation"

    # Check binary
    if command -v "${INSTALL_DIR}/${BINARY_NAME}" >/dev/null 2>&1; then
        local version=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
        log_success "Gibson binary installed: $version"
    else
        log_error "Gibson binary not found in PATH"
        return 1
    fi

    # Check directories
    for dir in "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"; do
        if [[ -d "$dir" ]]; then
            log_success "Directory exists: $dir"
        else
            log_error "Directory missing: $dir"
            return 1
        fi
    done

    # Check service (Linux only)
    if [[ $PLATFORM == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled gibson.service >/dev/null 2>&1; then
            log_success "Systemd service enabled"
        else
            log_warning "Systemd service not enabled"
        fi
    fi

    return 0
}

# Show post-installation instructions
show_instructions() {
    echo
    log_success "Gibson Framework installation completed!"
    echo
    echo "Next steps:"
    echo "1. Review the configuration file: ${CONFIG_DIR}/config.yaml"
    echo "2. Start the service:"

    if [[ $PLATFORM == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
        echo "   sudo systemctl start gibson"
        echo "   sudo systemctl status gibson"
    else
        echo "   ${INSTALL_DIR}/${BINARY_NAME} serve --config ${CONFIG_DIR}/config.yaml"
    fi

    echo "3. Check the help:"
    echo "   ${BINARY_NAME} --help"
    echo "4. View logs:"
    echo "   tail -f ${LOG_DIR}/gibson.log"
    echo
    echo "Documentation: https://github.com/${GITHUB_REPO}"
    echo
}

# Uninstall function
uninstall() {
    log_info "Uninstalling Gibson Framework"

    # Stop and disable service
    if [[ $PLATFORM == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active gibson.service >/dev/null 2>&1; then
            sudo systemctl stop gibson.service
        fi
        if systemctl is-enabled gibson.service >/dev/null 2>&1; then
            sudo systemctl disable gibson.service
        fi
        sudo rm -f /etc/systemd/system/gibson.service
        sudo systemctl daemon-reload
    fi

    # Remove binary
    sudo rm -f "${INSTALL_DIR}/${BINARY_NAME}"

    # Remove completion
    sudo rm -f /etc/bash_completion.d/gibson
    sudo rm -f /usr/local/share/zsh/site-functions/_gibson

    # Optionally remove data (ask user)
    echo
    read -p "Remove data directory ${DATA_DIR}? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -rf "$DATA_DIR"
        log_success "Data directory removed"
    fi

    read -p "Remove configuration directory ${CONFIG_DIR}? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -rf "$CONFIG_DIR"
        log_success "Configuration directory removed"
    fi

    read -p "Remove log directory ${LOG_DIR}? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -rf "$LOG_DIR"
        log_success "Log directory removed"
    fi

    # Remove user
    if [[ $PLATFORM == "linux" ]] && id "$SERVICE_USER" &>/dev/null; then
        read -p "Remove system user ${SERVICE_USER}? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo userdel "$SERVICE_USER"
            log_success "System user removed"
        fi
    fi

    log_success "Gibson Framework uninstalled"
}

# Main installation function
main() {
    echo "Gibson Framework Installation Script"
    echo "===================================="
    echo

    # Parse command line arguments
    case "${1:-install}" in
        install)
            check_root
            detect_platform
            get_latest_version
            download_binary
            install_binary
            create_user
            create_directories
            create_config
            install_service
            install_completion
            if verify_installation; then
                show_instructions
            else
                log_error "Installation verification failed"
                exit 1
            fi
            ;;
        uninstall)
            uninstall
            ;;
        verify)
            verify_installation
            ;;
        *)
            echo "Usage: $0 [install|uninstall|verify]"
            echo
            echo "Commands:"
            echo "  install    Install Gibson Framework (default)"
            echo "  uninstall  Remove Gibson Framework"
            echo "  verify     Verify existing installation"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"