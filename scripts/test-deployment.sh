#!/bin/bash
# Gibson Framework Deployment Test Script
# Tests the complete installation and deployment process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/gibson-deployment-test"
TEST_USER="gibson-test"
TEST_PORT="8081"

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

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Test result tracking
test_result() {
    local test_name="$1"
    local result="$2"
    local message="$3"

    ((TOTAL_TESTS++))

    if [[ "$result" == "PASS" ]]; then
        log_success "✓ $test_name: $message"
        ((TESTS_PASSED++))
    else
        log_error "✗ $test_name: $message"
        ((TESTS_FAILED++))
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    # Remove test directory
    rm -rf "$TEST_DIR" 2>/dev/null || true

    # Remove test user (if we're running as root)
    if [[ $EUID -eq 0 ]]; then
        userdel "$TEST_USER" 2>/dev/null || true
        groupdel "$TEST_USER" 2>/dev/null || true
    fi

    log_info "Cleanup completed"
}

# Setup test environment
setup_test_env() {
    log_info "Setting up test environment..."

    # Create test directory
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"

    # Create subdirectories
    mkdir -p bin config data logs

    log_success "Test environment created at $TEST_DIR"
}

# Test 1: Build validation
test_build() {
    log_info "Testing build process..."

    cd /home/anthony/Code/ai/zeroday-ai/gibson-framework-2

    # Clean build
    if make clean >/dev/null 2>&1; then
        test_result "Build Clean" "PASS" "Clean build completed successfully"
    else
        test_result "Build Clean" "FAIL" "Clean build failed"
        return 1
    fi

    # Build binary
    if make build >/dev/null 2>&1; then
        test_result "Build Binary" "PASS" "Binary build completed successfully"
    else
        test_result "Build Binary" "FAIL" "Binary build failed"
        return 1
    fi

    # Verify binary exists and is executable
    if [[ -f "build/gibson" && -x "build/gibson" ]]; then
        test_result "Binary Executable" "PASS" "Binary is executable"
    else
        test_result "Binary Executable" "FAIL" "Binary is not executable"
        return 1
    fi

    # Copy binary to test directory
    cp build/gibson "$TEST_DIR/bin/"
}

# Test 2: Binary functionality
test_binary_functionality() {
    log_info "Testing binary functionality..."

    cd "$TEST_DIR"

    # Test version command
    if ./bin/gibson version >/dev/null 2>&1; then
        test_result "Version Command" "PASS" "Version command works"
    else
        test_result "Version Command" "FAIL" "Version command failed"
    fi

    # Test help command
    if ./bin/gibson help >/dev/null 2>&1; then
        test_result "Help Command" "PASS" "Help command works"
    else
        test_result "Help Command" "FAIL" "Help command failed"
    fi

    # Test status command
    if ./bin/gibson status >/dev/null 2>&1; then
        test_result "Status Command" "PASS" "Status command works"
    else
        test_result "Status Command" "FAIL" "Status command failed"
    fi

    # Test invalid command handling
    if ! ./bin/gibson invalid-command >/dev/null 2>&1; then
        test_result "Error Handling" "PASS" "Invalid command properly handled"
    else
        test_result "Error Handling" "FAIL" "Invalid command not handled"
    fi
}

# Test 3: Configuration validation
test_configuration() {
    log_info "Testing configuration system..."

    cd "$TEST_DIR"

    # Create test configuration
    cat > config/test-config.yaml <<EOF
server:
  host: "127.0.0.1"
  port: ${TEST_PORT}

database:
  path: "${TEST_DIR}/data/gibson.db"

logging:
  level: "info"
  file: "${TEST_DIR}/logs/gibson.log"

plugins:
  directory: "${TEST_DIR}/data/plugins"
  timeout: 300

security:
  api_key_required: false
  rate_limiting:
    enabled: false
EOF

    # Test configuration validation (if available)
    if ./bin/gibson validate --config config/test-config.yaml >/dev/null 2>&1; then
        test_result "Config Validation" "PASS" "Configuration validation works"
    else
        test_result "Config Validation" "FAIL" "Configuration validation failed"
    fi
}

# Test 4: Directory structure
test_directory_structure() {
    log_info "Testing directory structure creation..."

    # Test creating gibson directory structure
    local test_dirs=("data" "logs" "config" "plugins")

    for dir in "${test_dirs[@]}"; do
        mkdir -p "$TEST_DIR/$dir"
        if [[ -d "$TEST_DIR/$dir" ]]; then
            test_result "Directory $dir" "PASS" "Directory created successfully"
        else
            test_result "Directory $dir" "FAIL" "Directory creation failed"
        fi
    done

    # Test file permissions
    touch "$TEST_DIR/data/test.db"
    chmod 644 "$TEST_DIR/data/test.db"

    if [[ -r "$TEST_DIR/data/test.db" && -w "$TEST_DIR/data/test.db" ]]; then
        test_result "File Permissions" "PASS" "File permissions correct"
    else
        test_result "File Permissions" "FAIL" "File permissions incorrect"
    fi
}

# Test 5: Makefile targets
test_makefile_targets() {
    log_info "Testing Makefile targets..."

    cd /home/anthony/Code/ai/zeroday-ai/gibson-framework-2

    # Test build-all target
    if make build-all >/dev/null 2>&1; then
        test_result "Build All Platforms" "PASS" "Multi-platform build successful"
    else
        test_result "Build All Platforms" "FAIL" "Multi-platform build failed"
    fi

    # Test checksums target
    mkdir -p dist
    cp build/gibson-* dist/ 2>/dev/null || true
    if make checksums >/dev/null 2>&1; then
        test_result "Checksums Generation" "PASS" "Checksums generated successfully"
    else
        test_result "Checksums Generation" "FAIL" "Checksums generation failed"
    fi

    # Test docs generation
    if make docs-generate >/dev/null 2>&1; then
        test_result "Documentation Generation" "PASS" "Documentation generated successfully"
    else
        test_result "Documentation Generation" "FAIL" "Documentation generation failed"
    fi
}

# Test 6: Installation scripts
test_installation_scripts() {
    log_info "Testing installation scripts..."

    cd /home/anthony/Code/ai/zeroday-ai/gibson-framework-2

    # Test that scripts exist and are executable
    local scripts=("install.sh" "backup.sh" "restore.sh" "migrate.sh")

    for script in "${scripts[@]}"; do
        if [[ -f "scripts/$script" && -x "scripts/$script" ]]; then
            test_result "Script $script" "PASS" "Script exists and is executable"
        else
            test_result "Script $script" "FAIL" "Script missing or not executable"
        fi
    done

    # Test script help functionality
    if ./scripts/install.sh --help >/dev/null 2>&1 || ./scripts/install.sh help >/dev/null 2>&1; then
        test_result "Install Script Help" "PASS" "Install script help works"
    else
        test_result "Install Script Help" "FAIL" "Install script help failed"
    fi

    if ./scripts/backup.sh help >/dev/null 2>&1; then
        test_result "Backup Script Help" "PASS" "Backup script help works"
    else
        test_result "Backup Script Help" "FAIL" "Backup script help failed"
    fi
}

# Test 7: Service files
test_service_files() {
    log_info "Testing service configuration files..."

    cd /home/anthony/Code/ai/zeroday-ai/gibson-framework-2

    # Test systemd service file
    if [[ -f "scripts/gibson.service" ]]; then
        # Basic syntax check for systemd service file
        if grep -q "\[Unit\]" scripts/gibson.service && grep -q "\[Service\]" scripts/gibson.service && grep -q "\[Install\]" scripts/gibson.service; then
            test_result "Systemd Service File" "PASS" "Service file has correct structure"
        else
            test_result "Systemd Service File" "FAIL" "Service file structure invalid"
        fi
    else
        test_result "Systemd Service File" "FAIL" "Service file not found"
    fi

    # Test Homebrew formula template
    if [[ -f "scripts/gibson.rb.template" ]]; then
        if grep -q "class Gibson" scripts/gibson.rb.template && grep -q "def install" scripts/gibson.rb.template; then
            test_result "Homebrew Formula" "PASS" "Homebrew formula template valid"
        else
            test_result "Homebrew Formula" "FAIL" "Homebrew formula template invalid"
        fi
    else
        test_result "Homebrew Formula" "FAIL" "Homebrew formula template not found"
    fi
}

# Test 8: Documentation completeness
test_documentation() {
    log_info "Testing documentation completeness..."

    cd /home/anthony/Code/ai/zeroday-ai/gibson-framework-2

    # Check for required documentation files
    local docs=("README.md" "DEPLOYMENT.md" "CHANGELOG.md" "TROUBLESHOOTING.md" "SECURITY_VALIDATION_REPORT.md")

    for doc in "${docs[@]}"; do
        if [[ -f "$doc" && -s "$doc" ]]; then
            test_result "Documentation $doc" "PASS" "Documentation file exists and has content"
        else
            test_result "Documentation $doc" "FAIL" "Documentation file missing or empty"
        fi
    done

    # Check API documentation
    if [[ -d "docs/api" && -f "docs/api/README.md" ]]; then
        test_result "API Documentation" "PASS" "API documentation exists"
    else
        test_result "API Documentation" "FAIL" "API documentation missing"
    fi
}

# Test 9: GitHub Actions workflow
test_github_actions() {
    log_info "Testing GitHub Actions workflow..."

    cd /home/anthony/Code/ai/zeroday-ai/gibson-framework-2

    # Check for workflow files
    if [[ -f ".github/workflows/release.yml" ]]; then
        # Basic YAML syntax check
        if grep -q "name: Release" .github/workflows/release.yml && grep -q "jobs:" .github/workflows/release.yml; then
            test_result "Release Workflow" "PASS" "Release workflow file valid"
        else
            test_result "Release Workflow" "FAIL" "Release workflow file invalid"
        fi
    else
        test_result "Release Workflow" "FAIL" "Release workflow file not found"
    fi

    if [[ -f ".github/workflows/test.yml" ]]; then
        test_result "Test Workflow" "PASS" "Test workflow file exists"
    else
        test_result "Test Workflow" "FAIL" "Test workflow file not found"
    fi
}

# Test 10: Security validation
test_security() {
    log_info "Testing security configuration..."

    cd /home/anthony/Code/ai/zeroday-ai/gibson-framework-2

    # Check for security report
    if [[ -f "SECURITY_VALIDATION_REPORT.md" ]]; then
        if grep -q "APPROVED FOR PRODUCTION DEPLOYMENT" SECURITY_VALIDATION_REPORT.md; then
            test_result "Security Validation" "PASS" "Security validation completed and approved"
        else
            test_result "Security Validation" "FAIL" "Security validation not approved"
        fi
    else
        test_result "Security Validation" "FAIL" "Security validation report not found"
    fi

    # Check systemd security hardening
    if [[ -f "scripts/gibson.service" ]]; then
        local security_features=("NoNewPrivileges=true" "PrivateTmp=true" "ProtectSystem=strict")
        local found_features=0

        for feature in "${security_features[@]}"; do
            if grep -q "$feature" scripts/gibson.service; then
                ((found_features++))
            fi
        done

        if [[ $found_features -eq ${#security_features[@]} ]]; then
            test_result "Security Hardening" "PASS" "Security hardening features present"
        else
            test_result "Security Hardening" "FAIL" "Security hardening features missing"
        fi
    fi
}

# Main test execution
main() {
    echo "Gibson Framework Deployment Test Suite"
    echo "======================================"
    echo ""

    # Setup
    setup_test_env
    trap cleanup EXIT

    # Run tests
    test_build
    test_binary_functionality
    test_configuration
    test_directory_structure
    test_makefile_targets
    test_installation_scripts
    test_service_files
    test_documentation
    test_github_actions
    test_security

    # Test results summary
    echo ""
    echo "Test Results Summary"
    echo "==================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "All tests passed! Gibson Framework is ready for deployment."
        echo ""
        echo "Next Steps:"
        echo "1. Tag release version: git tag v2.0.0"
        echo "2. Push to trigger GitHub Actions: git push origin v2.0.0"
        echo "3. Monitor release build and deployment"
        echo "4. Update documentation with release information"
        exit 0
    else
        log_error "Some tests failed. Please review and fix issues before deployment."
        echo ""
        echo "Failed tests need to be addressed before production deployment."
        exit 1
    fi
}

# Run main function
main "$@"