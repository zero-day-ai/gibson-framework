# Technology Stack

## Project Type
Terminal-based UI application for AI/ML security testing, modeled after k9s architecture patterns. CLI tool with interactive TUI for real-time monitoring and management.

## Core Technologies

### Primary Language(s)
- **Language**: Go 1.21+ (following k9s patterns)
- **Runtime**: Native compiled binaries for cross-platform support
- **Language-specific tools**: go mod for dependency management, golangci-lint for quality

### Key Dependencies/Libraries
- **github.com/spf13/cobra**: CLI framework and command structure
- **github.com/spf13/viper**: Configuration management
- **github.com/jqlx/sqlx**: Type-safe SQL with SQLite
- **github.com/gdamore/tcell/v2**: Terminal UI rendering (following k9s approach)
- **github.com/rivo/tview**: High-level terminal UI components
- **github.com/olekukonko/tablewriter**: Table rendering with tw API
- **github.com/fatih/color**: Terminal color output
- **github.com/google/uuid**: UUID generation for unique identifiers

### Application Architecture
**Plugin-Based Event-Driven Architecture** optimized for parallel execution:
- Domain-segregated plugins (Model, Data, Interface, Infrastructure, Output, Process)
- Reactive UI with event-driven updates
- Repository pattern with Result[T] functional error handling
- Dual-model system for clean separation (Core vs Database models)
- Command pattern via Cobra for CLI operations
- Observer pattern for real-time UI updates

### Data Storage
- **Primary storage**: SQLite with WAL mode for concurrent access
- **Connection pooling**: Persistent connection pool for performance
- **Migration system**: Schema evolution with versioned migrations
- **Data formats**: JSON for complex fields, native types for primitives
- **Audit trail**: Complete scan history with timestamp tracking

### External Integrations
- **Plugin Interface**: Standardized plugin execution protocol
- **LLM Providers**: OpenAI, Anthropic, Google AI integrations
- **Git Repositories**: Payload synchronization from remote sources
- **Export Formats**: JSON, YAML, CSV for reporting

### Monitoring & Terminal UI Technologies
- **TUI Framework**: tcell/tview for k9s-like terminal interface
- **Real-time Communication**: Event channels for UI updates
- **Visualization**: Terminal-based tables, progress bars, sparklines
- **State Management**: In-memory state with SQLite as source of truth
- **Navigation**: Vim-like keybindings with context awareness

## Development Environment

### Build & Development Tools
- **Build System**: Makefile with comprehensive targets
- **Package Management**: go mod with vendoring support
- **Development workflow**: Air for hot reload, go run for rapid testing
- **Cross-compilation**: GOOS/GOARCH matrix builds

### Code Quality Tools
- **Static Analysis**: golangci-lint, gosec for security
- **Formatting**: gofmt, goimports for consistency
- **Testing Framework**: Standard library testing, testify for assertions
- **Documentation**: godoc comments, markdown docs

### Version Control & Collaboration
- **VCS**: Git with conventional commits
- **Branching Strategy**: Feature branches with main as stable
- **Code Review Process**: AI agent-assisted reviews for parallel development
- **Commit Standards**: Atomic commits with clear messages

### Parallel Development Support
- **AI Agent Optimization**: Clear interfaces for parallel implementation
- **Task Decomposition**: Plugin-based architecture for independent work
- **Integration Points**: Well-defined boundaries for merge-free development
- **Testing Isolation**: Independent test suites per module

## Deployment & Distribution
- **Target Platform(s)**: Linux, macOS, Windows (cross-platform binaries)
- **Distribution Method**: Single binary deployment, homebrew, package managers
- **Installation Requirements**: No runtime dependencies, SQLite embedded
- **Update Mechanism**: Binary replacement with version checking

## Technical Requirements & Constraints

### Performance Requirements
- **UI Response**: < 100ms for all navigation operations
- **Query Performance**: < 50ms for database operations
- **Plugin Execution**: Support 10+ concurrent operations
- **Memory Usage**: < 100MB baseline, < 500MB under load
- **Startup Time**: < 500ms to interactive UI

### Compatibility Requirements
- **Platform Support**: Linux (amd64, arm64), macOS (amd64, arm64), Windows (amd64)
- **Go Version**: 1.21+ for modern features and performance
- **Terminal Requirements**: 256-color support, UTF-8 encoding
- **Database**: SQLite 3.32+ for modern SQL features

### Security & Compliance
- **Security Requirements**: Secure plugin execution, credential encryption
- **Input Validation**: Comprehensive validation at all entry points
- **Audit Logging**: Complete operation history with timestamps
- **Data Protection**: Local storage only, no external transmission

### Scalability & Reliability
- **Concurrent Operations**: Goroutine pools for parallel execution
- **Resource Management**: Bounded queues and worker pools
- **Error Recovery**: Graceful degradation with Result[T] pattern
- **Database Integrity**: ACID compliance with SQLite transactions

## Technical Decisions & Rationale

### Decision Log
1. **Go Language**: Native performance, excellent concurrency, single binary deployment
2. **SQLite Storage**: Zero-configuration, embedded, sufficient for audit trails
3. **Plugin Architecture**: Enables parallel development by AI agents, clear boundaries
4. **Terminal UI**: Follows k9s success pattern, keyboard efficiency for power users
5. **Result[T] Pattern**: Explicit error handling without exceptions, functional approach
6. **Dual Model System**: Clean separation of concerns, flexibility in evolution
7. **No Stubs/Mocks**: Production-ready code only, simplifies AI agent development
8. **Parallel-First Design**: Everything built for concurrent execution from day one

## Known Limitations

- **Terminal Only**: No web UI (by design, following k9s philosophy)
- **Local Storage**: SQLite limits to single-machine deployment (federation planned)
- **Plugin Protocol**: Version 1 protocol, evolution requires compatibility layer