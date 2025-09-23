# Gibson Framework Tests

This directory contains comprehensive tests for the Gibson Framework, including unit tests, integration tests, and end-to-end tests.

## Test Structure

```
tests/
├── integration/           # Integration tests for core functionality
│   ├── db_test.go        # Database integration tests
│   ├── service_test.go   # Service layer integration tests
│   ├── git_operations_test.go          # Git operations integration tests (comprehensive)
│   └── git_operations_simple_test.go   # Git operations integration tests (basic)
├── e2e/                  # End-to-end tests
│   ├── cli_workflows_test.go           # CLI workflow tests
│   └── payload_repository_test.go      # Payload repository E2E tests
└── README.md            # This file
```

## Running Tests

### Quick Test Commands

```bash
# Run all unit tests
make test-unit

# Run integration tests
make test-integration

# Run e2e tests
make test-e2e

# Run all tests
make test
```

### Manual Test Commands

```bash
# Run basic integration tests (no network required)
go test -tags=integration ./tests/integration/git_operations_simple_test.go -v

# Run comprehensive integration tests (requires network)
go test -tags=integration ./tests/integration/git_operations_test.go -v

# Run integration tests in short mode (skips network tests)
go test -tags=integration ./tests/integration/ -v -short

# Run e2e tests (requires building binary)
go test -tags=e2e ./tests/e2e/payload_repository_test.go -v

# Run e2e tests in short mode
go test -tags=e2e ./tests/e2e/ -v -short
```

## Git Integration Tests

### git_operations_simple_test.go
- **Purpose**: Basic Git service functionality tests that don't require network access
- **Coverage**: Service initialization, configuration, local validation, input validation
- **Dependencies**: None (fully isolated)
- **Runtime**: Fast (< 1 second)

### git_operations_test.go
- **Purpose**: Comprehensive Git operations testing including real network operations
- **Coverage**:
  - Git cloning (shallow and full)
  - Git pulling
  - Repository validation
  - Authentication scenarios (SSH, HTTPS, tokens)
  - Network failure handling
  - Concurrent operations
  - Context cancellation
- **Dependencies**: Network access for real Git repositories
- **Runtime**: Slower (may take several seconds per test)
- **Note**: Network-dependent tests are skipped in short mode

## E2E Tests

### payload_repository_test.go
- **Purpose**: Complete workflow validation from repository add to payload usage
- **Coverage**:
  - Complete add → sync → search → scan workflow
  - Multiple repository management
  - Authentication scenarios
  - Performance characteristics
  - Error handling and recovery
  - CLI usability and help messages
- **Dependencies**:
  - Network access for test repositories
  - Successful binary build
  - Temporary file system access
- **Runtime**: Slowest (several seconds to minutes)

## Test Data and Fixtures

### Test Repositories
The tests use a combination of:
- **Real public repositories**: For realistic testing scenarios
- **Generated test repositories**: Created during test execution for isolated testing
- **Mock servers**: For specific error condition testing

### Test Repository Structure
Generated test repositories include realistic payload structures:
```
test-repo/
├── interface/
│   ├── xss/
│   │   ├── basic.yaml
│   │   └── advanced.yaml
│   └── sqli/
│       └── union.yaml
├── data/
│   └── pii/
│       ├── ssn.yaml
│       └── email.yaml
├── model/
│   └── jailbreak/
│       ├── ignore.yaml
│       └── roleplay.yaml
├── infrastructure/
│   └── paths/
│       ├── traversal.yaml
│       └── windows.yaml
├── output/
│   └── formatting/
│       └── json_injection.yaml
├── process/
│   └── workflow/
│       └── bypass.yaml
└── README.md
```

## Test Requirements Coverage

The tests validate all Git-related requirements:

### Repository Management (Requirements 1.1-1.5)
- ✅ URL validation and accessibility checking
- ✅ SSH and HTTPS authentication support
- ✅ Shallow cloning with configurable depth
- ✅ Full clone support with --full flag
- ✅ Specific error messages with troubleshooting
- ✅ Repository listing with sync status

### Synchronization (Requirement 2.1)
- ✅ Pull latest changes from remote
- ✅ Payload indexing and categorization
- ✅ Conflict resolution strategies
- ✅ Error handling with state preservation

### Authentication (Requirements 4.1-4.5)
- ✅ SSH key auto-discovery
- ✅ HTTPS token authentication
- ✅ Credential caching
- ✅ Authentication failure guidance

### Performance (Requirements 5.1-5.2)
- ✅ Progress indicators during operations
- ✅ Offline operation after initial sync
- ✅ Efficient shallow cloning
- ✅ Batch processing verification

## CI/CD Integration

The tests are designed to run reliably in CI environments:

- **Short mode**: Skips network-dependent tests for faster feedback
- **Isolation**: Each test uses temporary directories and avoids global state
- **Cleanup**: Automatic cleanup of test artifacts
- **Error reporting**: Detailed error messages for troubleshooting

## Troubleshooting

### Common Issues

1. **Network timeouts**: Use `-short` flag to skip network tests
2. **Build failures**: Ensure all dependencies are properly implemented
3. **Permission errors**: Check file system permissions for test directories
4. **Git authentication**: Tests handle authentication gracefully with fallbacks

### Debug Mode

Enable verbose logging for test debugging:
```bash
go test -tags=integration -v -run TestSpecificTest ./tests/integration/
```

### Test Coverage

Generate test coverage reports:
```bash
go test -tags=integration -coverprofile=coverage.out ./tests/integration/
go tool cover -html=coverage.out -o coverage.html
```

## Contributing

When adding new tests:

1. **Follow existing patterns**: Use table-driven tests and proper setup/teardown
2. **Add both success and failure cases**: Ensure comprehensive coverage
3. **Use appropriate build tags**: `integration` for integration tests, `e2e` for e2e tests
4. **Document test purpose**: Include clear comments about what each test validates
5. **Consider CI constraints**: Make tests reliable in automated environments

## Performance Benchmarks

Some tests include benchmark functions:

```bash
# Run Git operation benchmarks
go test -tags=integration -bench=BenchmarkGitService ./tests/integration/ -benchmem
```

This helps ensure Git operations maintain acceptable performance characteristics.