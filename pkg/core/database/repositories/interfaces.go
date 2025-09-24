// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

// Repository represents the complete repository interface for all data access
// This follows the Repository pattern used throughout Gibson Framework
type Repository interface {
	// Core repository interfaces
	PayloadRepositories() PayloadRepositoryRepository

	// Database connection management
	DB() *sqlx.DB
	Close() error
	Health() error

	// Transaction support
	WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error
}

// BaseRepository provides common functionality for repository implementations
// This follows the existing patterns in Gibson Framework
type BaseRepository interface {
	// Connection management
	DB() *sqlx.DB
	Close() error
	Health() error

	// Transaction support
	BeginTx(ctx context.Context) (*sqlx.Tx, error)
	WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error
}

// CRUDRepository defines the basic CRUD operations interface
// This is the foundational interface that all entity repositories should implement
type CRUDRepository[T any] interface {
	Create(ctx context.Context, entity T) coremodels.Result[T]
	GetByID(ctx context.Context, id uuid.UUID) coremodels.Result[T]
	List(ctx context.Context) coremodels.Result[[]T]
	Update(ctx context.Context, entity T) coremodels.Result[T]
	Delete(ctx context.Context, id uuid.UUID) coremodels.Result[bool]
}

// NamedRepository extends CRUD to include name-based operations
// Many Gibson entities support lookup by name
type NamedRepository[T any] interface {
	CRUDRepository[T]
	GetByName(ctx context.Context, name string) coremodels.Result[T]
	ExistsByName(ctx context.Context, name string) coremodels.Result[bool]
}

// StatusRepository extends CRUD to include status-based operations
// Entities with status fields can be filtered and counted by status
type StatusRepository[T any, S comparable] interface {
	CRUDRepository[T]
	ListByStatus(ctx context.Context, status S) coremodels.Result[[]T]
	CountByStatus(ctx context.Context, status S) coremodels.Result[int64]
	UpdateStatus(ctx context.Context, id uuid.UUID, status S) coremodels.Result[bool]
}

// StatisticsRepository provides aggregate statistics functionality
// Repositories that need to provide dashboard or reporting data
type StatisticsRepository[T any] interface {
	GetStatistics(ctx context.Context) coremodels.Result[T]
}

// SearchRepository provides search and filtering capabilities
// For repositories that need complex query functionality
type SearchRepository[T any, F any] interface {
	Search(ctx context.Context, filters F) coremodels.Result[[]T]
	Count(ctx context.Context, filters F) coremodels.Result[int64]
}

// BulkRepository provides bulk operations for efficiency
// For repositories that need to handle large data sets
type BulkRepository[T any] interface {
	CreateMany(ctx context.Context, entities []T) coremodels.Result[[]T]
	UpdateMany(ctx context.Context, entities []T) coremodels.Result[[]T]
	DeleteMany(ctx context.Context, ids []uuid.UUID) coremodels.Result[int64]
}

// AuditableRepository provides audit trail functionality
// For entities that need to track creation and modification
type AuditableRepository[T any] interface {
	CRUDRepository[T]
	GetCreatedBy(ctx context.Context, createdBy string) coremodels.Result[[]T]
	GetModifiedSince(ctx context.Context, since string) coremodels.Result[[]T]
}

// VersionedRepository provides versioning functionality
// For entities that support multiple versions
type VersionedRepository[T any] interface {
	CRUDRepository[T]
	GetVersions(ctx context.Context, parentID uuid.UUID) coremodels.Result[[]T]
	CreateVersion(ctx context.Context, originalID uuid.UUID, newVersion T) coremodels.Result[T]
	GetLatestVersion(ctx context.Context, parentID uuid.UUID) coremodels.Result[T]
}

// CacheableRepository provides caching hints for repositories
// Repositories can implement this to indicate caching preferences
type CacheableRepository interface {
	GetCacheKey(id uuid.UUID) string
	GetCacheTTL() int // seconds
	InvalidateCache(keys ...string) error
}

// PayloadRepository defines interface for regular payload operations
// Supports filesystem to database synchronization and batch operations
type PayloadRepository interface {
	// CRUD operations for payloads
	Create(ctx context.Context, payload *coremodels.PayloadDB) coremodels.Result[*coremodels.PayloadDB]
	GetByID(ctx context.Context, id uuid.UUID) coremodels.Result[*coremodels.PayloadDB]
	GetByRepositoryPath(ctx context.Context, repositoryID uuid.UUID, repositoryPath string) coremodels.Result[*coremodels.PayloadDB]
	Update(ctx context.Context, payload *coremodels.PayloadDB) coremodels.Result[*coremodels.PayloadDB]
	Delete(ctx context.Context, id uuid.UUID) coremodels.Result[bool]

	// List operations for payload discovery
	List(ctx context.Context) coremodels.Result[[]*coremodels.PayloadDB]
	ListByDomain(ctx context.Context, domain string) coremodels.Result[[]*coremodels.PayloadDB]
	ListByPlugin(ctx context.Context, plugin string) coremodels.Result[[]*coremodels.PayloadDB]

	// Batch operations for efficiency
	CreateBatch(ctx context.Context, payloads []*coremodels.PayloadDB) coremodels.Result[[]*coremodels.PayloadDB]
	UpdateBatch(ctx context.Context, payloads []*coremodels.PayloadDB) coremodels.Result[[]*coremodels.PayloadDB]

	// Repository-specific operations
	ListByRepository(ctx context.Context, repositoryID uuid.UUID) coremodels.Result[[]*coremodels.PayloadDB]
	CountByRepository(ctx context.Context, repositoryID uuid.UUID) coremodels.Result[int64]
	DeleteOrphaned(ctx context.Context, repositoryID uuid.UUID, validPaths []string) coremodels.Result[int64]

	// Checksum-based operations (requirement 5.7)
	GetChecksumByPath(ctx context.Context, repositoryID uuid.UUID, repositoryPath string) coremodels.Result[string]
	UpdateChecksum(ctx context.Context, id uuid.UUID, checksum string) coremodels.Result[bool]
}

// Repository Factory provides dependency injection for repositories
// This allows for easy testing and modular architecture
type RepositoryFactory interface {
	// Core repositories
	NewPayloadRepositoryRepository() PayloadRepositoryRepository

	// Database management
	GetDB() *sqlx.DB
	Close() error
	Health() error
}

// TransactionManager provides transaction boundaries
// For operations that span multiple repositories
type TransactionManager interface {
	WithTransaction(ctx context.Context, fn func(ctx context.Context, tx *sqlx.Tx) error) error
}

// MigrationRepository handles database schema migrations
// Separate from entity repositories for clean separation of concerns
type MigrationRepository interface {
	GetCurrentVersion(ctx context.Context) coremodels.Result[int]
	ApplyMigration(ctx context.Context, version int, sql string) coremodels.Result[bool]
	RollbackMigration(ctx context.Context, version int, sql string) coremodels.Result[bool]
	GetMigrationHistory(ctx context.Context) coremodels.Result[[]MigrationRecord]
}

// MigrationRecord represents a database migration record
type MigrationRecord struct {
	ID          uuid.UUID `json:"id"`
	Version     int       `json:"version"`
	Description string    `json:"description"`
	Applied     bool      `json:"applied"`
	AppliedAt   string    `json:"applied_at"`
	SQL         string    `json:"sql"`
}

// HealthCheckRepository provides database health monitoring
// For monitoring and observability
type HealthCheckRepository interface {
	CheckConnection(ctx context.Context) coremodels.Result[bool]
	GetMetrics(ctx context.Context) coremodels.Result[DatabaseMetrics]
	GetTableStats(ctx context.Context) coremodels.Result[[]TableStatistics]
}

// DatabaseMetrics represents database performance metrics
type DatabaseMetrics struct {
	ConnectionCount    int64   `json:"connection_count"`
	ActiveQueries      int64   `json:"active_queries"`
	AverageQueryTime   float64 `json:"average_query_time_ms"`
	DatabaseSize       int64   `json:"database_size_bytes"`
	FreeSpace          int64   `json:"free_space_bytes"`
	TransactionCount   int64   `json:"transaction_count"`
	ErrorCount         int64   `json:"error_count"`
	CacheHitRatio      float64 `json:"cache_hit_ratio"`
}

// TableStatistics represents statistics for a database table
type TableStatistics struct {
	TableName    string `json:"table_name"`
	RowCount     int64  `json:"row_count"`
	SizeBytes    int64  `json:"size_bytes"`
	IndexCount   int    `json:"index_count"`
	LastAnalyzed string `json:"last_analyzed"`
}

// QueryBuilder provides dynamic query construction
// For repositories that need complex, dynamic queries
type QueryBuilder interface {
	Select(columns ...string) QueryBuilder
	From(table string) QueryBuilder
	Where(condition string, args ...interface{}) QueryBuilder
	OrderBy(column string, direction string) QueryBuilder
	Limit(limit int) QueryBuilder
	Offset(offset int) QueryBuilder
	Build() (string, []interface{})
}

// Repository implementation patterns and best practices:
//
// 1. Use Result[T] types for all operations to ensure consistent error handling
// 2. Implement proper transaction boundaries for data consistency
// 3. Use context.Context for cancellation and timeouts
// 4. Follow the single responsibility principle - one repository per entity
// 5. Use dependency injection for testability
// 6. Implement proper logging and observability
// 7. Use prepared statements for security and performance
// 8. Handle database connection pooling appropriately
// 9. Implement proper error wrapping with contextual information
// 10. Use consistent naming conventions across all repositories