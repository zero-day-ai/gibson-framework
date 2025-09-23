# Gibson Framework 2.0 - Architecture Documentation

This document provides a comprehensive overview of the Gibson Framework 2.0 architecture, which is heavily inspired by k9s patterns and designed for scalable AI/ML security testing.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [k9s-Inspired Patterns](#k9s-inspired-patterns)
3. [Core Components](#core-components)
4. [Resource Management](#resource-management)
5. [Plugin Architecture](#plugin-architecture)
6. [Database Layer](#database-layer)
7. [CLI Interface](#cli-interface)
8. [Event System](#event-system)
9. [Configuration Management](#configuration-management)
10. [Security Architecture](#security-architecture)
11. [Performance Considerations](#performance-considerations)

## Architecture Overview

Gibson Framework 2.0 follows a modular, event-driven architecture inspired by k9s patterns. The system is designed around the concept of **resources** (targets, scans, payloads, etc.) with **watchers** that monitor and react to state changes.

```
┌─────────────────────────────────────────────────────────────┐
│                        Gibson CLI                          │
├─────────────────────────────────────────────────────────────┤
│                    Command Layer                           │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────┬──────┐ │
│  │ Target  │  Scan   │ Payload │ Plugin  │ Report  │ Cred │ │
│  └─────────┴─────────┴─────────┴─────────┴─────────┴──────┘ │
├─────────────────────────────────────────────────────────────┤
│                     Service Layer                          │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │         Resource Watchers & Event System               │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                      Plugin System                         │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────┬──────┐ │
│  │  Model  │  Data   │Interface│ Infra   │ Output  │ Proc │ │
│  └─────────┴─────────┴─────────┴─────────┴─────────┴──────┘ │
├─────────────────────────────────────────────────────────────┤
│                      Data Layer                            │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              SQLite Database                            │ │
│  │  ┌─────────┬─────────┬─────────┬─────────┬──────────┐   │ │
│  │  │ Targets │  Scans  │Payloads │ Plugins │ Reports  │   │ │
│  │  └─────────┴─────────┴─────────┴─────────┴──────────┘   │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## k9s-Inspired Patterns

Gibson Framework 2.0 adopts several key architectural patterns from k9s:

### 1. Resource-Centric Design

Everything in Gibson is modeled as a **resource** with standardized operations:

```go
type Resource interface {
    GetID() string
    GetName() string
    GetStatus() ResourceStatus
    GetMetadata() map[string]interface{}
}
```

**Resource Types:**
- **Targets**: AI/ML systems under test
- **Scans**: Security scanning operations
- **Payloads**: Security test payloads
- **Plugins**: Security testing modules
- **Reports**: Assessment reports
- **Credentials**: Provider authentication

### 2. Watcher Pattern

Resource state changes are monitored using **watchers**:

```go
type ResourceWatcher interface {
    Start(ctx context.Context) error
    Stop() error
    Resource() string
    HasSynced() bool
}
```

**Implementation Example:**
```go
// internal/watch/factory.go
type Factory struct {
    watchers map[string]ResourceWatcher
    eventCh  chan Event
}

func (f *Factory) RegisterWatcher(resource string, watcher ResourceWatcher) {
    f.watchers[resource] = watcher
    go f.watchResource(resource, watcher)
}
```

### 3. Event-Driven Architecture

All state changes generate events that are processed asynchronously:

```go
type Event struct {
    Type      EventType     `json:"type"`
    Resource  string        `json:"resource"`
    Object    interface{}   `json:"object"`
    Timestamp time.Time     `json:"timestamp"`
}
```

### 4. Factory Pattern

Resource management uses factory patterns for consistency:

```go
type Factory interface {
    CreateWatcher(resource string) (ResourceWatcher, error)
    ListWatchers() []string
    GetWatcher(resource string) (ResourceWatcher, bool)
}
```

## Core Components

### 1. CLI Interface (`cmd/`)

The CLI layer implements the user interface using Cobra framework:

```
cmd/
├── console.go       # Interactive console mode
├── credential.go    # Credential management commands
├── help.go         # Enhanced help system
├── payload.go      # Payload management commands
├── plugin.go       # Plugin management commands
├── report.go       # Report management commands
├── root.go         # Root command and global flags
├── scan.go         # Scan management commands
├── status.go       # System status command
├── target.go       # Target management commands
└── version.go      # Version information
```

### 2. Internal Core (`internal/`)

The internal package contains the core business logic:

```
internal/
├── config/         # Configuration management
├── dao/           # Data Access Objects
├── model/         # Domain models and events
├── plugin/        # Plugin management system
├── pool/          # Resource pooling and execution
├── slogs/         # Structured logging
├── test/          # Test utilities
├── testutil/      # Test database utilities
├── ui/            # UI components and types
├── view/          # View layer components
└── watch/         # Resource watchers
```

### 3. Plugin System (`pkg/`)

Extensible plugin architecture for security testing:

```
pkg/
├── core/
│   ├── models/    # Core domain models
│   └── plugin/    # Plugin interfaces and types
```

## Resource Management

### Resource Lifecycle

All resources follow a standardized lifecycle:

1. **Creation**: Resource is created with validation
2. **Registration**: Resource is registered with watchers
3. **Monitoring**: Watchers monitor resource state
4. **Events**: State changes generate events
5. **Processing**: Events trigger appropriate handlers
6. **Persistence**: Changes are persisted to database

### Resource State Management

```go
type ResourceStatus string

const (
    StatusPending   ResourceStatus = "pending"
    StatusRunning   ResourceStatus = "running"
    StatusCompleted ResourceStatus = "completed"
    StatusFailed    ResourceStatus = "failed"
    StatusStopped   ResourceStatus = "stopped"
)
```

### Watcher Implementation

```go
// internal/watch/watcher.go
type ScannerWatcher struct {
    resource string
    factory  Factory
    stopCh   chan struct{}
    synced   bool
}

func (w *ScannerWatcher) Start(ctx context.Context) error {
    go w.syncLoop(ctx)
    return nil
}

func (w *ScannerWatcher) syncLoop(ctx context.Context) {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-w.stopCh:
            return
        case <-ticker.C:
            w.sync()
        }
    }
}
```

## Plugin Architecture

### Plugin Domains

Gibson organizes security plugins into six domains based on AI/ML attack surfaces:

#### 1. Model Domain
- **Purpose**: AI model-specific attacks
- **Examples**: Model extraction, inversion, backdoor detection
- **Interface**: ModelPlugin

#### 2. Data Domain
- **Purpose**: Data poisoning and extraction attacks
- **Examples**: Training data poisoning, data extraction
- **Interface**: DataPlugin

#### 3. Interface Domain
- **Purpose**: Prompt and interface attacks
- **Examples**: Prompt injection, jailbreaking
- **Interface**: InterfacePlugin

#### 4. Infrastructure Domain
- **Purpose**: Infrastructure and deployment attacks
- **Examples**: DoS attacks, authentication bypass
- **Interface**: InfrastructurePlugin

#### 5. Output Domain
- **Purpose**: Output manipulation and analysis
- **Examples**: Harmful content generation, bias detection
- **Interface**: OutputPlugin

#### 6. Process Domain
- **Purpose**: Process and governance attacks
- **Examples**: Supply chain attacks, compliance violations
- **Interface**: ProcessPlugin

### Plugin Interface

```go
// pkg/core/plugin/interfaces.go
type Plugin interface {
    Info() PluginInfo
    Execute(ctx context.Context, target *Target) (*Result, error)
    Validate(config map[string]interface{}) error
    Stop() error
}

type PluginInfo struct {
    Name        string            `json:"name"`
    Version     string            `json:"version"`
    Domain      PluginDomain      `json:"domain"`
    Description string            `json:"description"`
    Author      string            `json:"author"`
    Config      map[string]interface{} `json:"config"`
}
```

### Plugin Manager

```go
// internal/plugin/manager.go
type Manager struct {
    plugins    map[string]Plugin
    configs    map[string]PluginConfig
    logger     Logger
    grpcServer *grpc.Server
}

func (m *Manager) LoadPlugins(dir string) error {
    return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
            return m.loadPluginConfig(path)
        }
        return nil
    })
}
```

## Database Layer

### DAO Pattern

Gibson uses the Data Access Object (DAO) pattern for database operations:

```go
// internal/dao/types.go
type Factory interface {
    Targets() TargetAccessor
    Scans() ScanAccessor
    Payloads() PayloadAccessor
    Plugins() PluginAccessor
    Reports() ReportAccessor
    Credentials() CredentialAccessor
}

type TargetAccessor interface {
    Get(ctx context.Context, id uuid.UUID) (*model.Target, error)
    List(ctx context.Context) ([]*model.Target, error)
    Create(ctx context.Context, target *model.Target) error
    Update(ctx context.Context, target *model.Target) error
    Delete(ctx context.Context, id uuid.UUID) error
}
```

### Database Schema

```sql
-- Core tables
CREATE TABLE targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    endpoint TEXT,
    configuration TEXT,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    started_at DATETIME,
    completed_at DATETIME,
    configuration TEXT,
    results TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Additional tables for payloads, plugins, reports, credentials...
```

### Migration System

```go
// internal/dao/migrations.go
type Migration struct {
    Version int
    Name    string
    Up      string
    Down    string
}

var migrations = []Migration{
    {
        Version: 1,
        Name:    "create_targets_table",
        Up:      createTargetsTable,
        Down:    dropTargetsTable,
    },
    // Additional migrations...
}
```

## CLI Interface

### Command Structure

Gibson uses Cobra for CLI command management:

```go
// cmd/root.go
var rootCmd = &cobra.Command{
    Use:   "gibson",
    Short: "AI/ML Security Testing Framework",
    Long:  `Gibson is a CLI to view and manage AI/ML security testing workflows.`,
    Run:   runConsole,
}

func init() {
    rootCmd.AddCommand(versionCmd)
    rootCmd.AddCommand(statusCmd)
    rootCmd.AddCommand(consoleCmd)
    rootCmd.AddCommand(targetCmd)
    rootCmd.AddCommand(scanCmd)
    rootCmd.AddCommand(payloadCmd)
    rootCmd.AddCommand(credentialCmd)
    rootCmd.AddCommand(pluginCmd)
    rootCmd.AddCommand(reportCmd)
}
```

### Configuration Integration

```go
// internal/config/config.go
type Config struct {
    Database struct {
        Path           string `yaml:"path" mapstructure:"path"`
        MaxConnections int    `yaml:"max_connections" mapstructure:"max_connections"`
    } `yaml:"database" mapstructure:"database"`

    Logging struct {
        Level string `yaml:"level" mapstructure:"level"`
        File  string `yaml:"file" mapstructure:"file"`
    } `yaml:"logging" mapstructure:"logging"`

    Plugins struct {
        Directory string        `yaml:"directory" mapstructure:"directory"`
        Timeout   time.Duration `yaml:"timeout" mapstructure:"timeout"`
    } `yaml:"plugins" mapstructure:"plugins"`
}
```

## Event System

### Event Types

```go
// internal/model/events.go
type EventType string

const (
    EventTypeTargetCreated   EventType = "target.created"
    EventTypeTargetUpdated   EventType = "target.updated"
    EventTypeScanStarted     EventType = "scan.started"
    EventTypeScanCompleted   EventType = "scan.completed"
    EventTypeScanFailed      EventType = "scan.failed"
    EventTypePluginExecuted  EventType = "plugin.executed"
)
```

### Event Dispatcher

```go
// internal/model/events.go
type EventDispatcher struct {
    listeners map[EventType][]EventListener
    mu        sync.RWMutex
}

func (ed *EventDispatcher) Subscribe(eventType EventType, listener EventListener) {
    ed.mu.Lock()
    defer ed.mu.Unlock()
    ed.listeners[eventType] = append(ed.listeners[eventType], listener)
}

func (ed *EventDispatcher) Dispatch(event Event) {
    ed.mu.RLock()
    listeners := ed.listeners[event.Type]
    ed.mu.RUnlock()

    for _, listener := range listeners {
        go listener.HandleEvent(event)
    }
}
```

## Configuration Management

### Configuration Hierarchy

1. **Default Values**: Built-in defaults
2. **Configuration File**: YAML configuration
3. **Environment Variables**: Runtime overrides
4. **Command Line Flags**: Immediate overrides

### Viper Integration

```go
// internal/config/loader.go
func LoadConfig() (*Config, error) {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath("$HOME/.gibson")
    viper.AddConfigPath(".")

    // Environment variable overrides
    viper.SetEnvPrefix("GIBSON")
    viper.AutomaticEnv()
    viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

    if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
            return nil, err
        }
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, err
    }

    return &config, nil
}
```

## Security Architecture

### Credential Encryption

```go
// internal/dao/credential.go
func (c *Credential) EncryptValue(value string) error {
    key := make([]byte, 32) // AES-256
    if _, err := rand.Read(key); err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
    c.EncryptedValue = base64.StdEncoding.EncodeToString(ciphertext)
    c.EncryptionKey = base64.StdEncoding.EncodeToString(key)

    return nil
}
```

### Input Validation

```go
// Comprehensive input validation using validator package
type Target struct {
    Name     string `json:"name" validate:"required,min=1,max=100"`
    Endpoint string `json:"endpoint" validate:"required,url"`
    Type     string `json:"type" validate:"required,oneof=llm ml_model api"`
}
```

### Audit Logging

All operations are logged with comprehensive audit trails:

```go
type AuditEvent struct {
    Timestamp time.Time              `json:"timestamp"`
    User      string                 `json:"user"`
    Action    string                 `json:"action"`
    Resource  string                 `json:"resource"`
    Details   map[string]interface{} `json:"details"`
}
```

## Performance Considerations

### Connection Pooling

```go
// Database connection configuration
db.SetMaxOpenConns(10)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(time.Hour)
```

### Caching Strategy

```go
// In-memory caching for frequently accessed data
type Cache struct {
    data sync.Map
    ttl  time.Duration
}

func (c *Cache) Get(key string) (interface{}, bool) {
    if item, ok := c.data.Load(key); ok {
        if entry := item.(*CacheEntry); time.Since(entry.Created) < c.ttl {
            return entry.Value, true
        }
        c.data.Delete(key)
    }
    return nil, false
}
```

### Resource Limits

```go
// Resource pooling for concurrent operations
type Pool struct {
    workers   chan struct{}
    workQueue chan Job
    wg        sync.WaitGroup
}

func NewPool(maxWorkers int) *Pool {
    return &Pool{
        workers:   make(chan struct{}, maxWorkers),
        workQueue: make(chan Job, maxWorkers*2),
    }
}
```

### Monitoring and Metrics

```go
// Performance monitoring
type Metrics struct {
    RequestCount    int64         `json:"request_count"`
    AverageLatency  time.Duration `json:"average_latency"`
    ErrorRate       float64       `json:"error_rate"`
    MemoryUsage     uint64        `json:"memory_usage"`
    ActiveSessions  int32         `json:"active_sessions"`
}
```

## Testing Architecture

### Test Organization

```
tests/
├── unit/           # Unit tests for individual components
├── integration/    # Integration tests for component interaction
└── e2e/           # End-to-end workflow tests
```

### Test Coverage

- **Core Models**: 96.5% coverage
- **Plugin System**: 85% coverage
- **Watch System**: 74% coverage
- **Overall Target**: 80%+ coverage

### Test Utilities

```go
// internal/testutil/db.go
type TestDatabase struct {
    DB *sqlx.DB
    t  *testing.T
}

func NewTestDatabase(t *testing.T) *TestDatabase {
    db, err := sqlx.Open("sqlite3", ":memory:")
    require.NoError(t, err)

    return &TestDatabase{DB: db, t: t}
}

func (td *TestDatabase) Close() {
    td.DB.Close()
}
```

This architecture provides a solid foundation for scalable AI/ML security testing while maintaining the flexibility and user experience that makes k9s so effective for Kubernetes management.