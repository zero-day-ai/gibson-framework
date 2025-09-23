# Project Structure

## Directory Organization

```
gibson-framework/
├── cmd/
│   └── gibson/                # Main CLI entry point
│       └── main.go            # Application bootstrap
├── pkg/
│   ├── cli/                   # CLI layer (following k9s pattern)
│   │   ├── commands/          # Cobra commands (status, target, scan, etc.)
│   │   ├── config/            # Configuration management
│   │   ├── output/            # Formatters (JSON, YAML, Table, CSV)
│   │   └── ui/                # Terminal UI components
│   │       ├── views/         # Different UI views (list, detail, xray)
│   │       ├── widgets/       # Reusable UI widgets
│   │       └── keys/          # Keyboard binding definitions
│   ├── core/                  # Core business logic
│   │   ├── models/            # Core business models (no database deps)
│   │   ├── plugin/            # Plugin system interfaces
│   │   │   ├── interfaces.go  # Plugin contracts
│   │   │   ├── registry/      # Plugin discovery and registration
│   │   │   └── executor/      # Parallel plugin execution
│   │   └── database/          # Data persistence layer
│   │       ├── models/        # Database models (SQLite specific)
│   │       ├── repositories/  # Repository implementations
│   │       └── migrations/    # Schema migrations
│   └── services/              # Business services layer
│       ├── scanner/           # Scan orchestration
│       ├── target/            # Target management
│       ├── finding/           # Finding analysis
│       └── plugin/            # Plugin coordination
├── plugins/                    # Plugin implementations
│   ├── model/                 # Model testing plugins
│   ├── data/                  # Data validation plugins
│   ├── interface/             # Interface testing plugins
│   ├── infrastructure/        # Infrastructure plugins
│   ├── output/                # Output generation plugins
│   └── process/               # Process automation plugins
├── internal/                   # Internal packages (not exported)
│   ├── terminal/              # Terminal helpers
│   ├── utils/                 # General utilities
│   └── validators/            # Input validation
├── tests/                      # Integration tests
│   ├── fixtures/              # Test data
│   └── e2e/                   # End-to-end tests
└── build/                      # Build artifacts and scripts
```

## Naming Conventions

### Files
- **Commands**: `command_name.go` (snake_case for multi-word)
- **Services**: `service_name_service.go` (explicit service suffix)
- **Models**: `model_name.go` (singular, descriptive)
- **Repositories**: `model_repository.go` (model name + repository)
- **Tests**: `file_name_test.go` (standard Go convention)
- **Interfaces**: `interfaces.go` (grouped by package)

### Code
- **Interfaces**: `PascalCase` with descriptive names (e.g., `PluginExecutor`)
- **Structs**: `PascalCase` for exported, `camelCase` for internal
- **Functions**: `PascalCase` for exported, `camelCase` for internal
- **Constants**: `PascalCase` for exported (avoid SCREAMING_CASE)
- **Variables**: `camelCase` throughout
- **Packages**: Single word, lowercase (following Go conventions)

## Import Patterns

### Import Order
```go
import (
    // Standard library
    "context"
    "fmt"

    // Third-party libraries
    "github.com/spf13/cobra"
    "github.com/jmoiron/sqlx"

    // Internal packages with aliases
    coremodels "github.com/gibson-sec/gibson/pkg/core/models"
    dbmodels "github.com/gibson-sec/gibson/pkg/core/database/models"

    // Internal packages without aliases
    "github.com/gibson-sec/gibson/pkg/services"
)
```

### Critical Import Aliases
```go
// ALWAYS use these aliases to avoid confusion
coremodels "github.com/gibson-sec/gibson/pkg/core/models"
dbmodels "github.com/gibson-sec/gibson/pkg/core/database/models"
```

## Code Structure Patterns

### Service Pattern
```go
type ScannerService struct {
    repo     repositories.ScanRepository
    plugins  plugin.Registry
    executor plugin.Executor
}

// Constructor with dependency injection
func NewScannerService(repo repositories.ScanRepository, ...) *ScannerService {
    return &ScannerService{
        repo:     repo,
        plugins:  plugins,
        executor: executor,
    }
}

// Methods follow Result[T] pattern
func (s *ScannerService) StartScan(ctx context.Context, target *coremodels.Target) models.Result[*coremodels.Scan] {
    // Implementation
}
```

### Repository Pattern
```go
type scanRepository struct {
    db *sqlx.DB
}

func (r *scanRepository) Create(scan *dbmodels.Scan) models.Result[*dbmodels.Scan] {
    // Direct implementation - NO STUBS
    query := `INSERT INTO scans (...) VALUES (...) RETURNING *`
    err := r.db.Get(scan, query, ...)
    if err != nil {
        return models.Err[*dbmodels.Scan](err)
    }
    return models.Ok(scan)
}
```

### UI View Pattern (Following k9s)
```go
type ScanListView struct {
    *tview.Table
    app     *tview.Application
    service services.ScannerService
}

func NewScanListView(app *tview.Application, service services.ScannerService) *ScanListView {
    // Full implementation - NO PLACEHOLDERS
}

func (v *ScanListView) Update() {
    // Real-time updates - COMPLETE IMPLEMENTATION
}
```

## Code Organization Principles

### NO STUBS, MOCKS, OR TODOS
1. **Every function must be complete**: No `// TODO` comments or `panic("not implemented")`
2. **Real implementations only**: No mock services or stub methods
3. **Immediate functionality**: Code works on first commit, not "will work later"
4. **Test with real components**: Integration tests use actual services

### Parallel Development Rules
1. **Clear boundaries**: Each plugin/service can be developed independently
2. **Interface contracts**: Define interfaces first, implement in parallel
3. **No cross-dependencies**: Services communicate through interfaces only
4. **Atomic commits**: Each commit is complete and functional

### Simplicity Guidelines
1. **Direct implementation**: Avoid unnecessary abstraction layers
2. **Clear code paths**: Linear flow without complex branching
3. **Explicit over implicit**: Clear parameter passing, no magic
4. **Single responsibility**: Each component does one thing well

## Module Boundaries

### Core Boundaries
- **pkg/cli**: Terminal UI and user interaction (can run independently)
- **pkg/core**: Business logic and data models (no UI dependencies)
- **pkg/services**: Orchestration layer (depends on core, not CLI)
- **plugins/**: Independent plugin modules (communicate via interfaces)

### Plugin Boundaries
- Each plugin is self-contained with its own dependencies
- Plugins communicate only through defined interfaces
- No direct plugin-to-plugin dependencies
- Plugins can be developed/tested in complete isolation

### Data Flow
```
CLI Commands → Services → Repositories → Database
     ↓            ↓            ↓
Terminal UI ← Services ← Core Models ← DB Models
```

## Code Size Guidelines

### Strict Limits for AI Agent Development
- **File size**: Maximum 500 lines per file (aids parallel work)
- **Function size**: Maximum 50 lines per function (complete, no stubs)
- **Interface size**: Maximum 10 methods per interface
- **Struct fields**: Maximum 15 fields per struct
- **Nesting depth**: Maximum 3 levels of nesting

### Package Organization
- **Commands**: One command per file
- **Services**: One service per file
- **Models**: Related models grouped logically
- **UI Views**: One view type per file

## Terminal UI Structure (k9s Pattern)

### View Organization
```
pkg/cli/ui/
├── app.go              # Main application controller
├── views/
│   ├── list.go        # Generic list view
│   ├── detail.go      # Detail/inspection view
│   ├── xray.go        # Deep inspection mode
│   └── logs.go        # Log streaming view
├── widgets/
│   ├── header.go      # Top header with cluster info
│   ├── crumbs.go      # Navigation breadcrumbs
│   ├── help.go        # Context-sensitive help
│   └── flash.go       # Status messages
└── keys/
    ├── bindings.go    # Keyboard mappings
    └── actions.go     # Action definitions
```

### View Principles
- Each view is complete and functional
- Real-time updates via event channels
- Context-aware keyboard shortcuts
- No placeholder UI elements

## Documentation Standards

### Code Documentation
- Exported functions MUST have godoc comments
- Complex algorithms include inline explanation
- No TODO comments - implement immediately
- Examples in godoc for public APIs

### Inline Comments
- Explain WHY, not WHAT
- Complex business rules documented
- Performance considerations noted
- Security implications highlighted

### AI Agent Instructions
Each package includes `.ai-development.md` with:
- Package purpose and boundaries
- Interface contracts to implement
- Parallel development guidelines
- Integration points with other packages