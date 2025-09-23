#!/bin/bash

# Integration tests for Gibson delete commands with positional arguments
# This script tests that delete commands properly handle positional arguments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to print test results
print_result() {
    local test_name="$1"
    local result="$2"
    local expected="$3"
    local actual="$4"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓${NC} $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗${NC} $test_name"
        echo -e "  Expected: $expected"
        echo -e "  Actual: $actual"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Function to test command help output
test_help_output() {
    local cmd="$1"
    local test_name="$2"
    local expected_pattern="$3"

    echo -e "${YELLOW}Testing:${NC} $test_name"

    # Run the help command and capture output
    local output
    output=$(./gibson $cmd --help 2>&1) || true

    # Check if the output contains the expected pattern
    if echo "$output" | grep -q "$expected_pattern"; then
        print_result "$test_name" "PASS" "Contains '$expected_pattern'" "Found in output"
    else
        print_result "$test_name" "FAIL" "Contains '$expected_pattern'" "Not found in output"
    fi
}

# Function to test command error handling
test_error_handling() {
    local cmd="$1"
    local test_name="$2"
    local expected_error="$3"

    echo -e "${YELLOW}Testing:${NC} $test_name"

    # Run the command and capture error output
    local output
    local exit_code
    output=$(./gibson $cmd 2>&1) || exit_code=$?

    # Check if we got an error and it contains the expected message
    if [ "$exit_code" != "0" ] && echo "$output" | grep -q "$expected_error"; then
        print_result "$test_name" "PASS" "Error: '$expected_error'" "Got expected error"
    else
        print_result "$test_name" "FAIL" "Error: '$expected_error'" "Exit code: $exit_code, Output: $output"
    fi
}

# Function to test command flag parsing
test_flag_parsing() {
    local cmd="$1"
    local test_name="$2"
    local flags="$3"
    local expected_success="$4"

    echo -e "${YELLOW}Testing:${NC} $test_name"

    # Run the command with flags and capture output
    local output
    local exit_code=0
    output=$(eval "./gibson $cmd $flags --help" 2>&1) || exit_code=$?

    if [ "$expected_success" = "true" ]; then
        if [ "$exit_code" = "0" ]; then
            print_result "$test_name" "PASS" "Command accepts flags" "Command executed successfully"
        else
            print_result "$test_name" "FAIL" "Command accepts flags" "Exit code: $exit_code"
        fi
    else
        if [ "$exit_code" != "0" ]; then
            print_result "$test_name" "PASS" "Command rejects invalid flags" "Command failed as expected"
        else
            print_result "$test_name" "FAIL" "Command rejects invalid flags" "Command succeeded unexpectedly"
        fi
    fi
}

echo "=============================================="
echo "Gibson Delete Commands Integration Tests"
echo "=============================================="

# Check if gibson binary exists
if [ ! -f "./gibson" ]; then
    echo -e "${RED}Error:${NC} gibson binary not found. Please run 'go build -o gibson main.go' first."
    exit 1
fi

echo -e "${YELLOW}Testing target delete command...${NC}"

# Test target delete help contains positional argument syntax
test_help_output "target delete" "Target delete help shows positional syntax" "delete \[NAME\]"

# Test target delete help shows examples with positional arguments
test_help_output "target delete" "Target delete help shows positional examples" "gibson target delete my-target"

# Test target delete error handling without arguments
test_error_handling "target delete" "Target delete requires identifier" "either target name or ID must be specified"

# Test target delete flag parsing
test_flag_parsing "target delete" "Target delete accepts --name flag" "--name test-target" "true"
test_flag_parsing "target delete" "Target delete accepts --id flag" "--id target-123" "true"
test_flag_parsing "target delete" "Target delete accepts --all flag" "--all" "true"
test_flag_parsing "target delete" "Target delete accepts --force flag" "--force" "true"

echo -e "${YELLOW}Testing credential delete command...${NC}"

# Test credential delete help contains positional argument syntax
test_help_output "credential delete" "Credential delete help shows positional syntax" "delete \[NAME\]"

# Test credential delete help shows examples with positional arguments
test_help_output "credential delete" "Credential delete help shows positional examples" "gibson credential delete my-credential"

# Test credential delete error handling without arguments
test_error_handling "credential delete" "Credential delete requires identifier" "either credential name, ID, or --all flag must be specified"

# Test credential delete flag parsing
test_flag_parsing "credential delete" "Credential delete accepts --name flag" "--name test-credential" "true"
test_flag_parsing "credential delete" "Credential delete accepts --id flag" "--id cred-123" "true"
test_flag_parsing "credential delete" "Credential delete accepts --all flag" "--all" "true"
test_flag_parsing "credential delete" "Credential delete accepts --force flag" "--force" "true"

echo -e "${YELLOW}Testing scan delete command...${NC}"

# Test scan delete help contains positional argument syntax
test_help_output "scan delete" "Scan delete help shows positional syntax" "delete \[SCAN_ID\]"

# Test scan delete help shows examples with positional arguments
test_help_output "scan delete" "Scan delete help shows positional examples" "gibson scan delete scan-123"

# Test scan delete error handling without arguments
test_error_handling "scan delete" "Scan delete requires identifier" "either scan ID or --all flag must be specified"

# Test scan delete flag parsing
test_flag_parsing "scan delete" "Scan delete accepts --id flag" "--id scan-123" "true"
test_flag_parsing "scan delete" "Scan delete accepts --all flag" "--all" "true"

echo -e "${YELLOW}Testing payload remove command...${NC}"

# Test payload remove help contains positional argument syntax
test_help_output "payload remove" "Payload remove help shows positional syntax" "remove \[NAME\]"

# Test payload remove help shows examples with positional arguments
test_help_output "payload remove" "Payload remove help shows positional examples" "gibson payload remove injection-001"

# Test payload remove error handling without arguments
test_error_handling "payload remove" "Payload remove requires identifier" "either payload name, ID, tags, or category must be specified"

# Test payload remove flag parsing
test_flag_parsing "payload remove" "Payload remove accepts --name flag" "--name test-payload" "true"
test_flag_parsing "payload remove" "Payload remove accepts --id flag" "--id payload-123" "true"
test_flag_parsing "payload remove" "Payload remove accepts --force flag" "--force" "true"

echo -e "${YELLOW}Testing plugin uninstall command...${NC}"

# Test plugin uninstall help contains positional argument syntax
test_help_output "plugin uninstall" "Plugin uninstall help shows positional syntax" "uninstall \[NAME\]"

# Test plugin uninstall help shows examples with positional arguments
test_help_output "plugin uninstall" "Plugin uninstall help shows positional examples" "gibson plugin uninstall my-plugin"

# Test plugin uninstall error handling without arguments
test_error_handling "plugin uninstall" "Plugin uninstall requires identifier" "either plugin name or ID must be specified"

# Test plugin uninstall flag parsing
test_flag_parsing "plugin uninstall" "Plugin uninstall accepts --name flag" "--name test-plugin" "true"
test_flag_parsing "plugin uninstall" "Plugin uninstall accepts --id flag" "--id plugin-123" "true"
test_flag_parsing "plugin uninstall" "Plugin uninstall accepts --force flag" "--force" "true"

# Test command aliases work correctly
echo -e "${YELLOW}Testing command aliases...${NC}"

test_help_output "target del" "Target del alias works" "Delete one or more AI/ML targets"
test_help_output "target rm" "Target rm alias works" "Delete one or more AI/ML targets"
test_help_output "credential del" "Credential del alias works" "Delete one or more AI/ML provider credentials"
test_help_output "credential rm" "Credential rm alias works" "Delete one or more AI/ML provider credentials"
test_help_output "scan del" "Scan del alias works" "Delete completed or failed scans"
test_help_output "scan rm" "Scan rm alias works" "Delete completed or failed scans"
test_help_output "payload delete" "Payload delete alias works" "Remove one or more security payloads"
test_help_output "payload del" "Payload del alias works" "Remove one or more security payloads"
test_help_output "payload rm" "Payload rm alias works" "Remove one or more security payloads"
test_help_output "plugin remove" "Plugin remove alias works" "Uninstall security testing plugins"
test_help_output "plugin delete" "Plugin delete alias works" "Uninstall security testing plugins"

echo ""
echo "=============================================="
echo "Test Results Summary"
echo "=============================================="
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed! ✗${NC}"
    exit 1
fi