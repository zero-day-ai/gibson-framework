# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build Commands
- `make build` - Build the gibson binary for current platform
- `make build-all` - Build binaries for all platforms (Linux, macOS, Windows)
- `make install` - Build and install gibson binary to GOPATH/bin
- `make clean` - Clean build artifacts

### Test Commands
- `make test` - Run all tests with reasonable defaults (unit + integration)
- `make test-unit` - Run unit tests only
- `make test-integration` - Run integration tests (requires network)
- `make test-e2e` - Run end-to-end tests (requires binary build)
- `make test-short` - Run quick tests for development
- `make test-coverage` - Generate and display test coverage report
- `go test -tags=integration ./tests/integration/ -v -short` - Run integration tests without network

### Code Quality
- `make lint` - Run comprehensive linting with golangci-lint
- `make lint-fix` - Run linting with auto-fix where possible
- `make fmt` - Format code with gofmt and goimports
- `make vet` - Run go vet
- `make security` - Run security analysis with gosec
- `make ci` - Run complete CI pipeline (fmt, vet, lint, test-coverage, security, deps-check)

### Development Helpers
- `make dev` - Quick development cycle (fmt, vet, test-short, build)
- `make dev-setup` - Install development tools
- `make deps-check` - Check for dependency issues and vulnerabilities

### Schema Generation
- `make generate-schema` - Generate JSON Schema from PayloadDB struct

## Architecture Overview

### Dual Model System
Gibson uses a dual-model architecture for clean separation:
- **Core Models** (`pkg/core/models/`): Business logic models (TargetDB, ScanDB, FindingDB, etc.)
- **Database Models** (`pkg/core/database/models/`): SQLite persistence models with same field structure
- **Type Conversion**: Manual conversion functions between core and database models

### Result Pattern
Uses functional error handling throughout the codebase:
```go
type Result[T any] struct {
    value T
    err   error
}
// Usage: models.Ok(value), models.Err[T](error), result.IsOk(), result.Unwrap()
```

### Repository Pattern
Data access abstraction with interfaces:
- Repository interfaces in `pkg/core/database/repositories/interfaces.go`
- SQLite implementations use sqlx for database operations
- All methods return Result[T] types for consistent error handling

### Service Factory Pattern
Enterprise-grade dependency injection through service factory:
```go
factory := service.NewServiceFactory(repository, logger, encryptionKey)
credService := factory.CredentialService()
scanService := factory.ScanService()
targetService := factory.TargetService()
```

## Key Import Patterns

### Critical Import Aliases
```go
import (
    coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
    dbmodels "github.com/gibson-sec/gibson-framework-2/pkg/core/database/models"
    "github.com/gibson-sec/gibson-framework-2/pkg/core/database"
)
```

### Common Import Patterns
- `"github.com/gibson-sec/gibson-framework-2/pkg/cli/config"` - Configuration management
- `"github.com/gibson-sec/gibson-framework-2/pkg/services"` - Business logic services
- `"github.com/spf13/cobra"` + `"github.com/spf13/viper"` - CLI framework
- `"github.com/jmoiron/sqlx"` - Database operations

### Variable Shadowing Warning
**CRITICAL**: Avoid variable names that shadow package names:
```go
// BAD: Shadows the plugin package
go func(plugin plugin.Plugin) {
    // plugin package is now shadowed
}

// GOOD: Use different parameter name
go func(p plugin.Plugin) {
    // plugin package remains accessible
}
```
Common shadowing issues: `config`, `models`, `context`, `plugin` parameters.

## Code Organization

### CLI Structure (Cobra Framework)
- Root command in `cmd/gibson/`
- Commands in `cmd/` directory (status.go, target.go, version.go, etc.)
- Global flags and configuration in `pkg/cli/config/`
- Output formatters in `pkg/cli/output/` (JSON, YAML, Table, CSV)

### Plugin System
- Domain-based plugin architecture: Model, Data, Interface, Infrastructure, Output, Process
- Plugin interfaces in `pkg/core/plugin/`
- Plugin discovery and loading system
- Shared plugin module in `shared/` directory

### Database Layer
- SQLite with sqlx for type-safe queries
- Migration system for schema evolution
- Connection pooling and health checks
- WAL mode for better concurrent access

### Security & Validation
- Comprehensive input validation in `internal/validation/`
- AES-256-GCM credential encryption
- Rate limiting and DoS protection
- SQL injection, XSS, and command injection prevention

## Testing Structure

### Test Categories
- **Unit Tests**: Alongside source files (*_test.go)
- **Integration Tests**: In `tests/integration/` with `-tags=integration`
- **E2E Tests**: In `tests/e2e/` with `-tags=e2e`

### Running Specific Tests
```bash
# Run specific test file
go test ./pkg/services/git_service_test.go -v

# Run tests with tags
go test -tags=integration ./tests/integration/ -v

# Run without network (short mode)
go test -tags=integration ./tests/integration/ -v -short
```

## Common Patterns

### Type Conversion Between Models
```go
// Core to Database
func convertToDatabase(core *coremodels.TargetDB) *dbmodels.TargetDB {
    return &dbmodels.TargetDB{
        ID: core.ID,
        Name: core.Name,
        // ... map all fields
    }
}

// Database to Core
func convertFromDatabase(db *dbmodels.TargetDB) *coremodels.TargetDB {
    return &coremodels.TargetDB{
        ID: db.ID,
        Name: db.Name,
        // ... map all fields
    }
}
```

### Error Handling with Results
```go
result := service.SomeOperation(ctx, params)
if result.IsErr() {
    return models.Err[ReturnType](result.Error())
}
value := result.Unwrap()
return models.Ok(value)
```

### Service Configuration
```go
// Service with default configuration
service := services.NewGitService(services.GetDefaultConfig())

// Service with custom configuration
config := services.GitServiceConfig{
    DefaultDepth:      1,
    DefaultBranch:     "main",
    BaseDir:           "/tmp/gibson-repos",
}
service := services.NewGitService(config)
```

## Build System Notes

### Cross-Platform Builds
The Makefile supports building for multiple platforms:
- Linux AMD64/ARM64
- macOS AMD64/ARM64 (Apple Silicon)
- Windows AMD64

### Go Version
- Requires Go 1.24+
- Uses Go modules with replace directive for shared package

### Linting Configuration
Comprehensive linting rules in `.golangci.yml`:
- Security-focused rules (gosec)
- Performance rules
- Style and complexity rules
- Custom exclusions for test files

## Security Considerations

### Credential Handling
- All credentials encrypted with AES-256-GCM
- Key derivation using scrypt
- Automatic rotation support
- Never log or expose credentials in plaintext

### Input Validation
- Comprehensive validation in `internal/validation/`
- SQL injection prevention
- XSS and command injection detection
- Rate limiting for DoS protection

### Audit Trail
- Complete operation logging
- Security event tracking
- Compliance-ready audit logs

## Plugin Development

### Plugin Domains
1. **Model**: AI model-specific attacks
2. **Data**: Data-centric security assessments
3. **Interface**: Prompt and interface vulnerability testing
4. **Infrastructure**: System and infrastructure security
5. **Output**: Output security and content validation
6. **Process**: Operational and governance security

### Plugin Structure
```go
type CustomPlugin struct {
    plugin.BasePlugin
    config map[string]interface{}
}

func (p *CustomPlugin) Execute(ctx context.Context, target *shared.Target) (*shared.SecurityResult, error) {
    // Implementation
}
```

## Database Schema

### Core Entities
- **PayloadDB**: Security testing payloads with repository tracking
- **TargetDB**: AI/ML target configurations
- **ScanDB**: Security scan definitions and results
- **FindingDB**: Security findings and vulnerabilities
- **CredentialDB**: Encrypted credential storage

### Payload Categories
- `model`, `data`, `interface`, `infrastructure`, `output`, `process`

### Payload Types
- `prompt`, `query`, `input`, `code`, `data`, `script`

## Configuration

### Config File Location
- `~/.gibson/config.yaml`
- Environment variables with `GIBSON_` prefix override config

### Key Configuration Areas
- Database settings (connection pooling, timeouts)
- Security settings (encryption, audit logging)
- Plugin configuration (directories, timeouts, memory limits)
- Monitoring and health checks
- Network and API settings

## Common Issues & Solutions

### Missing Output Functions
If you see `undefined: output.OutputJSON` or `undefined: output.OutputYAML`:
- These are convenience functions in `pkg/cli/output/convenience.go`
- They wrap the formatter classes for simple JSON/YAML output

### Import Conflicts
If you see `undefined: models`:
- Check import aliases - use `coremodels` vs `dbmodels`
- Core models: business logic and validation
- Database models: SQLite persistence layer

### Repository Interface Errors
When implementing repositories, ensure:
- All methods return `models.Result[T]` types
- Use proper import aliases for model types
- Implement all interface methods with correct signatures

## Performance Notes

### Optimization Features
- Connection pooling for database operations
- Query caching for frequent operations
- Batch processing for bulk operations
- Resource limits to prevent exhaustion
- Goroutine management with worker pools

### Benchmarks
- Plugin execution: < 50ms startup time
- Database operations: < 5ms for most queries
- Memory usage: < 30MB base footprint
- Supports up to 100 parallel operations

## Git Repository Management

### Authentication Support
- SSH key authentication with auto-discovery
- HTTPS basic authentication
- GitHub token authentication
- SSH agent support

### Clone Operations
- Default shallow clone with depth=1
- Support for `--depth` and `--full` flags
- Progress callbacks for UI feedback
- Single branch cloning for efficiency

### Error Handling
- Uses Gibson's Result[T] pattern
- Comprehensive error messages with troubleshooting guidance
- Graceful fallbacks and cleanup