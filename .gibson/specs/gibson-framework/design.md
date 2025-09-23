# Gibson Framework Production Readiness - Design

## 1. System Architecture

### Current State
```
┌─────────────────────────────────────────────────┐
│                   CLI Layer                      │
│  (cmd/*.go - Commands with mock implementations) │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│                  View Layer                      │
│  (internal/view/*.go - Hardcoded mock data)     │
└─────────────────────┬───────────────────────────┘
                      │ [BROKEN CONNECTION]
┌─────────────────────┴───────────────────────────┐
│                   DAO Layer                      │
│  (internal/dao/*.go - Fully implemented)        │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│                SQLite Database                   │
│         (Not properly initialized)               │
└─────────────────────────────────────────────────┘
```

### Target State
```
┌─────────────────────────────────────────────────┐
│                   CLI Layer                      │
│        (cmd/*.go - Production ready)            │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│                  View Layer                      │
│    (internal/view/*.go - DAO integrated)        │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│                Service Layer                     │
│  (internal/service/*.go - Business logic)       │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│                   DAO Layer                      │
│     (internal/dao/*.go - Repository pattern)    │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│                SQLite Database                   │
│    (Properly initialized with migrations)       │
└─────────────────────────────────────────────────┘
```

## 2. Component Design

### 2.1 Database Initialization Component

**Location:** `cmd/init.go`

**Current Issue:** Creates empty file instead of initialized database

**Solution Design:**
```go
// Replace current initializeDatabase with:
func initializeDatabase(ctx context.Context, gibsonHome string) error {
    dbPath := filepath.Join(gibsonHome, "gibson.db")
    dsn := dbPath + "?_foreign_keys=on&_journal_mode=WAL&_timeout=5000"

    repository, err := dao.NewSQLiteRepository(dsn)
    if err != nil {
        return fmt.Errorf("failed to initialize database: %w", err)
    }
    defer repository.Close()

    // Migrations run automatically in NewSQLiteRepository

    if err := repository.Health(); err != nil {
        return fmt.Errorf("database health check failed: %w", err)
    }

    return nil
}
```

### 2.2 View Layer Service Integration

**Pattern:** View → Service → DAO

**Example Implementation for Credential View:**
```go
type credentialView struct {
    service *service.CredentialService
}

func NewCredentialView() (*credentialView, error) {
    // Get repository from context or factory
    repo := dao.GetDefaultRepository()
    service := service.NewCredentialService(repo)

    return &credentialView{
        service: service,
    }, nil
}

func (cv *credentialView) AddCredential(opts CredentialAddOptions) error {
    credential := &model.Credential{
        Name:     opts.Name,
        Provider: opts.Provider,
        Type:     opts.Type,
        // ... other fields
    }

    // Encrypt value before storage
    encrypted, err := cv.service.EncryptValue(opts.Value)
    if err != nil {
        return err
    }
    credential.EncryptedValue = encrypted

    return cv.service.Create(context.Background(), credential)
}
```

### 2.3 Security Key Management

**Location:** `internal/security/keystore.go` (new)

**Design:**
```go
type KeyStore interface {
    GetMasterKey() ([]byte, error)
    RotateMasterKey() error
    DeriveKey(purpose string) ([]byte, error)
}

type FileKeyStore struct {
    keyPath string
    cache   *secureCache
}

func NewFileKeyStore(gibsonHome string) (*FileKeyStore, error) {
    keyPath := filepath.Join(gibsonHome, ".encryption_key")

    // Check if key exists, create if not
    if _, err := os.Stat(keyPath); os.IsNotExist(err) {
        if err := generateMasterKey(keyPath); err != nil {
            return nil, err
        }
    }

    return &FileKeyStore{
        keyPath: keyPath,
        cache:   newSecureCache(),
    }, nil
}
```

### 2.4 Watch System Implementation

**Location:** `internal/watch/factory.go`

**Current Issue:** Placeholder synchronization

**Solution Design:**
```go
func (t *TargetWatcher) Sync(ctx context.Context) error {
    repo := t.factory.repository
    targets, err := repo.Targets().List(ctx)
    if err != nil {
        return fmt.Errorf("failed to list targets: %w", err)
    }

    t.logger.LogAttrs(ctx, slog.LevelInfo, "Synchronized targets",
        slogs.Component, "TargetWatcher",
        slogs.Count, len(targets),
        slogs.Status, "success",
    )

    t.lastSync = time.Now()
    return nil
}
```

### 2.5 Health Monitoring Enhancement

**Location:** `internal/health/health.go`

**Disk Space Implementation:**
```go
func (hc *healthChecker) checkDiskSpace(ctx context.Context) Check {
    check := Check{
        Name:   "disk_space",
        Status: StatusHealthy,
    }

    var stat syscall.Statfs_t
    gibsonHome := getGibsonHome()

    if err := syscall.Statfs(gibsonHome, &stat); err != nil {
        check.Status = StatusUnhealthy
        check.Message = fmt.Sprintf("Failed to check disk space: %v", err)
        return check
    }

    available := stat.Bavail * uint64(stat.Bsize)
    total := stat.Blocks * uint64(stat.Bsize)
    usedPercent := float64(total-available) / float64(total) * 100

    check.Details = map[string]interface{}{
        "available_bytes": available,
        "total_bytes":     total,
        "used_percent":    usedPercent,
    }

    if usedPercent > 90 {
        check.Status = StatusUnhealthy
        check.Message = fmt.Sprintf("Disk usage critical: %.1f%%", usedPercent)
    } else if usedPercent > 80 {
        check.Status = StatusDegraded
        check.Message = fmt.Sprintf("Disk usage high: %.1f%%", usedPercent)
    } else {
        check.Message = fmt.Sprintf("Disk usage normal: %.1f%%", usedPercent)
    }

    return check
}
```

## 3. Data Flow Design

### 3.1 Credential Management Flow
```
User Input → CLI Command → View Layer → Service Layer → Encryption → DAO → Database
                                ↓
                         Input Validation
                                ↓
                          Key Derivation
                                ↓
                           AES-256-GCM
```

### 3.2 Scan Execution Flow
```
Scan Request → Validation → Plugin Selection → Execution Pool → Results Collection
                    ↓              ↓                 ↓              ↓
                Database      Plugin Manager    Worker Pool    Finding Storage
```

## 4. Service Layer Design

### 4.1 Service Interfaces
```go
// internal/service/interfaces.go
type CredentialService interface {
    Create(ctx context.Context, cred *model.Credential) error
    Get(ctx context.Context, id string) (*model.Credential, error)
    List(ctx context.Context) ([]*model.Credential, error)
    Update(ctx context.Context, id string, cred *model.Credential) error
    Delete(ctx context.Context, id string) error
    Rotate(ctx context.Context, id string) error
    Validate(ctx context.Context, id string) error
}

type ScanService interface {
    Start(ctx context.Context, config *model.ScanConfig) (*model.Scan, error)
    Stop(ctx context.Context, id string) error
    GetStatus(ctx context.Context, id string) (*model.ScanStatus, error)
    GetResults(ctx context.Context, id string) ([]*model.Finding, error)
    RunBatch(ctx context.Context, configs []*model.ScanConfig) error
}

type TargetService interface {
    Create(ctx context.Context, target *model.Target) error
    Get(ctx context.Context, id string) (*model.Target, error)
    List(ctx context.Context) ([]*model.Target, error)
    Update(ctx context.Context, id string, target *model.Target) error
    Delete(ctx context.Context, id string) error
    TestConnection(ctx context.Context, id string) error
}
```

### 4.2 Service Implementation Pattern
```go
type credentialService struct {
    repo     dao.Repository
    keyStore security.KeyStore
    logger   *slog.Logger
}

func NewCredentialService(repo dao.Repository, keyStore security.KeyStore) *credentialService {
    return &credentialService{
        repo:     repo,
        keyStore: keyStore,
        logger:   slog.Default().With("service", "credential"),
    }
}
```

## 5. Database Schema Updates

No schema changes required - existing migrations are comprehensive:
1. Targets table with proper indexes
2. Credentials with encryption fields
3. Scans with progress tracking
4. Findings with relationships
5. Reports and schedules
6. Payloads with versioning
7. Plugin statistics

## 6. Configuration Updates

### 6.1 Application Configuration
```yaml
database:
  connection_pool_size: 25
  max_idle_connections: 5
  connection_max_lifetime: 3600

security:
  key_rotation_interval: 30d
  encryption_algorithm: "AES-256-GCM"
  key_derivation: "PBKDF2"

monitoring:
  health_check_interval: 60s
  metrics_retention: 7d
  disk_space_threshold: 80
```

## 7. Error Handling Strategy

### 7.1 Error Types
```go
type ErrorType int

const (
    ErrorTypeDatabase ErrorType = iota
    ErrorTypeValidation
    ErrorTypeSecurity
    ErrorTypeNetwork
    ErrorTypePlugin
    ErrorTypeConfiguration
)

type GibsonError struct {
    Type    ErrorType
    Message string
    Cause   error
    Context map[string]interface{}
}
```

### 7.2 Error Propagation
- View layer: User-friendly messages
- Service layer: Structured errors with context
- DAO layer: Database-specific errors
- All layers: Proper error wrapping

## 8. Testing Strategy

### 8.1 Unit Tests
- Service layer: Mock DAO interfaces
- View layer: Mock service interfaces
- DAO layer: In-memory SQLite
- Security: Test encryption/decryption

### 8.2 Integration Tests
- End-to-end CLI workflows
- Database migration tests
- Plugin execution tests
- Health monitoring tests

### 8.3 Test Data Management
```go
// internal/testutil/fixtures.go
func LoadTestFixtures(t *testing.T, repo dao.Repository) {
    // Load deterministic test data
    // No random/time-based values
}
```

## 9. Migration Strategy

### 9.1 Incremental Rollout
1. Phase 1: Database initialization fix
2. Phase 2: Credential management
3. Phase 3: Target and scan operations
4. Phase 4: Reporting and monitoring
5. Phase 5: Complete integration testing

### 9.2 Backward Compatibility
- Maintain existing CLI interface
- Support existing configuration files
- Preserve database schema
- No breaking API changes

## 10. Performance Considerations

### 10.1 Database Optimization
- Connection pooling configured
- Prepared statements cached
- Indexes on frequently queried columns
- WAL mode for concurrent access

### 10.2 Caching Strategy
- In-memory cache for credentials
- Plugin metadata cache
- Target configuration cache
- TTL-based invalidation

### 10.3 Concurrency Design
- Worker pools for scan execution
- Concurrent plugin execution
- Database connection pooling
- Rate limiting for API calls

## 11. Security Considerations

### 11.1 Credential Protection
- AES-256-GCM encryption
- Secure key derivation
- Memory protection for keys
- Audit logging for access

### 11.2 Input Validation
- SQL injection prevention
- Command injection prevention
- Path traversal prevention
- Size limits on inputs

### 11.3 Access Control
- Role-based permissions (future)
- Audit trail for changes
- Secure defaults
- Principle of least privilege

## 12. Monitoring & Observability

### 12.1 Metrics Collection
```go
type Metrics struct {
    DatabaseQueries   counter.Counter
    ScanDuration     histogram.Histogram
    CredentialAccess counter.Counter
    ErrorRate        gauge.Gauge
}
```

### 12.2 Logging Standards
- Structured logging throughout
- Correlation IDs for tracing
- Error context preservation
- Performance metrics logging

## 13. Documentation Updates

### 13.1 Code Documentation
- Package-level documentation
- Interface documentation
- Example usage in comments
- Error handling examples

### 13.2 User Documentation
- Updated CLI help text
- Configuration examples
- Troubleshooting guide
- Security best practices