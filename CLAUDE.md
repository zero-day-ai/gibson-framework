# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Building
```bash
make build          # Build the gibson binary for current platform
make build-all      # Build binaries for all platforms (linux, darwin, windows)
make install        # Build and install gibson binary to GOPATH/bin
```

### Testing
```bash
make test           # Run unit and integration tests with coverage
make test-unit      # Run unit tests only
make test-integration  # Run integration tests with timeout
make test-e2e       # Run end-to-end tests (requires build)
make test-short     # Run quick tests for development
make test-coverage  # Generate test coverage report with HTML output
make test-all       # Run all test suites (unit, integration, e2e)
```

### Code Quality
```bash
make fmt            # Format code with gofmt and goimports
make lint           # Run comprehensive linting with golangci-lint
make lint-fix       # Run linting with auto-fix where possible
make vet            # Run go vet
make security       # Run security analysis with gosec
make ci             # Run complete CI pipeline (fmt, vet, lint, test-coverage, security, deps-check)
```

### Dependencies
```bash
make deps-check     # Check for dependency issues and vulnerabilities
make sdk-test       # Test SDK integration
make sdk-update     # Update SDK dependency to latest version
```

### Development Workflow
```bash
make dev            # Quick development cycle (fmt, vet, test-short, build)
make dev-setup      # Set up development environment with all tools
make watch-test     # Continuous testing (requires fswatch)
```

### Documentation & Schema
```bash
make generate-schema  # Generate JSON Schema from PayloadDB struct
make docs-generate   # Generate API documentation
```

## High-Level Architecture

### Core Components

**Plugin System**
- The framework uses HashiCorp's go-plugin for a robust plugin architecture
- Plugins are managed through `internal/plugin/manager.go`
- Plugin interfaces are defined via the gibson-sdk (referenced as a local module replacement)
- Example plugin implementation in `plugins/examples/injection/`

**Command Structure**
- Entry point: `main.go` -> `cmd.Execute()`
- All CLI commands defined in `cmd/` directory
- Major commands: init, scan, target, plugin, credential, payload, report, console
- Each command handles specific security testing operations

**Data Models**
- Core types in `internal/model/types.go` and `internal/model/`
- Database models in `pkg/core/database/models/`
- Payload handling through PayloadDB structure
- Support for JSON, YAML, and other structured data formats

**Security Features**
- Audit logging in `internal/audit/`
- Security validation in `internal/security/` and `internal/validation/`
- Rate limiting in `internal/ratelimit/`
- Vulnerability scanning in `internal/vul/`

**Service Architecture**
- Data Access Objects (DAO) pattern in `internal/dao/`
- Service layer in `internal/service/` and `pkg/services/`
- Worker pool for concurrent operations in `internal/pool/`
- File watching capabilities in `internal/watch/`

**Configuration**
- Viper-based configuration in `internal/config/`
- Support for environment variables and config files
- Structured logging via slog with tint formatter

**UI/View Layer**
- Terminal UI components in `internal/ui/` and `internal/view/`
- Color support via fatih/color
- Health monitoring in `internal/health/`
- Metrics collection in `internal/metrics/`

### Testing Strategy
- Unit tests alongside source files (*_test.go)
- Integration tests with build tags
- E2E tests in `tests/e2e/`
- Test utilities in `internal/testutil/`
- Coverage threshold: 70%

### Key Dependencies
- Cobra for CLI commands
- Viper for configuration management
- SQLx with SQLite for database operations
- HashiCorp go-plugin for plugin architecture
- go-git for Git operations
- LangChain Go for AI/ML integrations
- Structured logging with slog

### Development Notes
- Go 1.24 required (uses latest Go features)
- Local SDK development via module replacement to ../gibson-plugin-sdk
- Comprehensive linting via golangci-lint with custom configuration
- Security-focused - includes gosec scanning and vulnerability checks
- Follow existing code patterns and conventions when making changes