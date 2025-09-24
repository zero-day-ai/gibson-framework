// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package dao

import (
	"context"
	"database/sql"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Factory represents a resource factory for SQLite operations.
type Factory interface {
	// DB returns the underlying SQLite database connection.
	DB() *sqlx.DB

	// Begin starts a new database transaction.
	Begin() (*sqlx.Tx, error)

	// Close closes the database connection.
	Close() error

	// Health checks database connectivity.
	Health() error
}

// Getter represents a resource getter.
type Getter interface {
	// Get return a given resource by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.Target, error)
}

// Lister represents a resource lister.
type Lister interface {
	// List returns a resource collection.
	List(ctx context.Context) ([]*model.Target, error)

	// ListByProvider returns resources filtered by provider.
	ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Target, error)

	// ListByStatus returns resources filtered by status.
	ListByStatus(ctx context.Context, status model.TargetStatus) ([]*model.Target, error)
}

// Creator represents a resource creator.
type Creator interface {
	// Create creates a new resource.
	Create(ctx context.Context, target *model.Target) error
}

// Updater represents a resource updater.
type Updater interface {
	// Update updates an existing resource.
	Update(ctx context.Context, target *model.Target) error

	// UpdateStatus updates only the status of a resource.
	UpdateStatus(ctx context.Context, id uuid.UUID, status model.TargetStatus) error
}

// Deleter represents a resource deleter.
type Deleter interface {
	// Delete removes a resource from the database.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteByName removes a resource by name.
	DeleteByName(ctx context.Context, name string) error
}

// Accessor represents an accessible Gibson resource with CRUD operations.
type Accessor interface {
	Lister
	Getter
	Creator
	Updater
	Deleter

	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string
}

// TargetAccessor represents specialized target operations.
type TargetAccessor interface {
	Accessor

	// GetByName returns a target by name.
	GetByName(ctx context.Context, name string) (*model.Target, error)

	// ExistsByName checks if a target exists by name.
	ExistsByName(ctx context.Context, name string) (bool, error)

	// CountByProvider returns count of targets by provider.
	CountByProvider(ctx context.Context, provider model.Provider) (int, error)

	// ListActiveTargets returns only active targets.
	ListActiveTargets(ctx context.Context) ([]*model.Target, error)
}

// ScanAccessor represents specialized scan operations.
type ScanAccessor interface {
	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string

	// Get returns a scan by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.Scan, error)

	// List returns all scans.
	List(ctx context.Context) ([]*model.Scan, error)

	// Create creates a new scan.
	Create(ctx context.Context, scan *model.Scan) error

	// Update updates an existing scan.
	Update(ctx context.Context, scan *model.Scan) error

	// Delete removes a scan.
	Delete(ctx context.Context, id uuid.UUID) error

	// GetByTargetID returns scans for a specific target.
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Scan, error)

	// ListByStatus returns scans filtered by status.
	ListByStatus(ctx context.Context, status model.ScanStatus) ([]*model.Scan, error)

	// UpdateProgress updates scan progress.
	UpdateProgress(ctx context.Context, id uuid.UUID, progress float64) error

	// UpdateStatus updates scan status.
	UpdateStatus(ctx context.Context, id uuid.UUID, status model.ScanStatus) error

	// GetRunningScans returns currently running scans.
	GetRunningScans(ctx context.Context) ([]*model.Scan, error)
}

// FindingAccessor represents specialized finding operations.
type FindingAccessor interface {
	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string

	// Get returns a finding by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.Finding, error)

	// List returns all findings.
	List(ctx context.Context) ([]*model.Finding, error)

	// Create creates a new finding.
	Create(ctx context.Context, finding *model.Finding) error

	// Update updates an existing finding.
	Update(ctx context.Context, finding *model.Finding) error

	// Delete removes a finding.
	Delete(ctx context.Context, id uuid.UUID) error

	// GetByScanID returns findings for a specific scan.
	GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Finding, error)

	// GetByTargetID returns findings for a specific target.
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Finding, error)

	// ListBySeverity returns findings filtered by severity.
	ListBySeverity(ctx context.Context, severity model.Severity) ([]*model.Finding, error)

	// ListByStatus returns findings filtered by status.
	ListByStatus(ctx context.Context, status model.FindingStatus) ([]*model.Finding, error)

	// UpdateStatus updates finding status.
	UpdateStatus(ctx context.Context, id uuid.UUID, status model.FindingStatus) error

	// CountBySeverity returns finding counts grouped by severity.
	CountBySeverity(ctx context.Context) (map[model.Severity]int, error)

	// GetHighSeverityFindings returns critical and high severity findings.
	GetHighSeverityFindings(ctx context.Context) ([]*model.Finding, error)
}

// CredentialAccessor represents specialized credential operations.
type CredentialAccessor interface {
	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string

	// Get returns a credential by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.Credential, error)

	// List returns all credentials.
	List(ctx context.Context) ([]*model.Credential, error)

	// Create creates a new credential.
	Create(ctx context.Context, credential *model.Credential) error

	// Update updates an existing credential.
	Update(ctx context.Context, credential *model.Credential) error

	// Delete removes a credential.
	Delete(ctx context.Context, id uuid.UUID) error

	// GetByName returns a credential by name.
	GetByName(ctx context.Context, name string) (*model.Credential, error)

	// ListByProvider returns credentials filtered by provider.
	ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Credential, error)

	// ListByStatus returns credentials filtered by status.
	ListByStatus(ctx context.Context, status model.CredentialStatus) ([]*model.Credential, error)

	// UpdateLastUsed updates the last used timestamp.
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error

	// GetActiveCredentials returns only active credentials.
	GetActiveCredentials(ctx context.Context) ([]*model.Credential, error)

	// RotateCredential updates credential rotation information.
	RotateCredential(ctx context.Context, id uuid.UUID, rotationInfo model.CredentialRotationInfo) error
}

// ReportAccessor represents specialized report operations.
type ReportAccessor interface {
	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string

	// Get returns a report by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.Report, error)

	// List returns all reports.
	List(ctx context.Context) ([]*model.Report, error)

	// Create creates a new report.
	Create(ctx context.Context, report *model.Report) error

	// Update updates an existing report.
	Update(ctx context.Context, report *model.Report) error

	// Delete removes a report.
	Delete(ctx context.Context, id uuid.UUID) error

	// GetByTargetID returns reports for a specific target.
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Report, error)

	// GetByScanID returns reports for a specific scan.
	GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Report, error)

	// ListByStatus returns reports filtered by status.
	ListByStatus(ctx context.Context, status model.ReportStatus) ([]*model.Report, error)

	// ListByType returns reports filtered by type.
	ListByType(ctx context.Context, reportType model.ReportType) ([]*model.Report, error)

	// UpdateStatus updates only the status of a report.
	UpdateStatus(ctx context.Context, id uuid.UUID, status model.ReportStatus) error

	// GetScheduledReports returns reports that are scheduled for generation.
	GetScheduledReports(ctx context.Context) ([]*model.Report, error)
}

// ReportScheduleAccessor represents specialized report schedule operations.
type ReportScheduleAccessor interface {
	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string

	// Get returns a report schedule by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.ReportSchedule, error)

	// List returns all report schedules.
	List(ctx context.Context) ([]*model.ReportSchedule, error)

	// Create creates a new report schedule.
	Create(ctx context.Context, schedule *model.ReportSchedule) error

	// Update updates an existing report schedule.
	Update(ctx context.Context, schedule *model.ReportSchedule) error

	// Delete removes a report schedule.
	Delete(ctx context.Context, id uuid.UUID) error

	// ListEnabled returns only enabled report schedules.
	ListEnabled(ctx context.Context) ([]*model.ReportSchedule, error)

	// GetDueSchedules returns schedules that are due to run.
	GetDueSchedules(ctx context.Context) ([]*model.ReportSchedule, error)

	// GetByTargetID returns schedules for a specific target.
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.ReportSchedule, error)

	// UpdateLastRun updates the last run timestamp and calculates next run.
	UpdateLastRun(ctx context.Context, id uuid.UUID, lastRun time.Time, nextRun *time.Time) error

	// UpdateNextRun updates only the next run timestamp.
	UpdateNextRun(ctx context.Context, id uuid.UUID, nextRun *time.Time) error

	// EnableSchedule enables a report schedule.
	EnableSchedule(ctx context.Context, id uuid.UUID) error

	// DisableSchedule disables a report schedule.
	DisableSchedule(ctx context.Context, id uuid.UUID) error
}

// PayloadAccessor represents specialized payload operations.
type PayloadAccessor interface {
	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string

	// Get returns a payload by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.Payload, error)

	// List returns all payloads.
	List(ctx context.Context) ([]*model.Payload, error)

	// Create creates a new payload.
	Create(ctx context.Context, payload *model.Payload) error

	// Update updates an existing payload.
	Update(ctx context.Context, payload *model.Payload) error

	// Delete removes a payload.
	Delete(ctx context.Context, id uuid.UUID) error

	// GetByName returns a payload by name.
	GetByName(ctx context.Context, name string) (*model.Payload, error)

	// ListByCategory returns payloads filtered by category.
	ListByCategory(ctx context.Context, category model.PayloadCategory) ([]*model.Payload, error)

	// ListByDomain returns payloads filtered by domain.
	ListByDomain(ctx context.Context, domain string) ([]*model.Payload, error)

	// ListEnabled returns only enabled payloads.
	ListEnabled(ctx context.Context) ([]*model.Payload, error)

	// GetVersions returns all versions of a payload.
	GetVersions(ctx context.Context, parentID uuid.UUID) ([]*model.Payload, error)

	// CreateVersion creates a new version of an existing payload.
	CreateVersion(ctx context.Context, originalID uuid.UUID, newPayload *model.Payload) error

	// UpdateUsageStats updates usage statistics for a payload.
	UpdateUsageStats(ctx context.Context, id uuid.UUID, successful bool) error

	// GetMostUsed returns the most frequently used payloads.
	GetMostUsed(ctx context.Context, limit int) ([]*model.Payload, error)
}

// PluginStatsAccessor represents specialized plugin stats operations.
type PluginStatsAccessor interface {
	// Init initializes the accessor with a factory.
	Init(Factory)

	// TableName returns the database table name.
	TableName() string

	// Get returns plugin stats by ID.
	Get(ctx context.Context, id uuid.UUID) (*model.PluginStats, error)

	// List returns all plugin stats.
	List(ctx context.Context) ([]*model.PluginStats, error)

	// Create creates new plugin stats.
	Create(ctx context.Context, stats *model.PluginStats) error

	// Update updates existing plugin stats.
	Update(ctx context.Context, stats *model.PluginStats) error

	// Delete removes plugin stats.
	Delete(ctx context.Context, id uuid.UUID) error

	// ListByPlugin returns stats for a specific plugin.
	ListByPlugin(ctx context.Context, pluginName string) ([]*model.PluginStats, error)

	// ListByMetric returns stats for a specific metric.
	ListByMetric(ctx context.Context, pluginName, metricName string) ([]*model.PluginStats, error)

	// ListByTimeRange returns stats within a time range.
	ListByTimeRange(ctx context.Context, start, end time.Time) ([]*model.PluginStats, error)

	// GetAggregatedStats returns aggregated statistics for a plugin metric.
	GetAggregatedStats(ctx context.Context, pluginName, metricName string, start, end time.Time) (map[string]float64, error)

	// GetTimeSeriesData returns time-series data for a plugin metric.
	GetTimeSeriesData(ctx context.Context, pluginName, metricName string, start, end time.Time, interval string) ([]*model.PluginStats, error)

	// GetTopPluginsByMetric returns plugins ranked by a specific metric.
	GetTopPluginsByMetric(ctx context.Context, metricName string, metricType model.PluginMetricType, limit int) (map[string]float64, error)

	// GetByScanID returns stats for a specific scan.
	GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.PluginStats, error)

	// GetByTargetID returns stats for a specific target.
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.PluginStats, error)

	// DeleteOldStats removes stats older than the specified time.
	DeleteOldStats(ctx context.Context, before time.Time) (int64, error)

	// RecordMetric is a convenience method to record a metric.
	RecordMetric(ctx context.Context, pluginName, pluginVersion, metricName string, metricType model.PluginMetricType, value float64, unit string, tags map[string]interface{}, targetID, scanID *uuid.UUID) error
}

// Transactor represents database transaction operations.
type Transactor interface {
	// WithTransaction executes a function within a database transaction.
	WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error
}

// Repository represents a complete data access layer with transaction support.
type Repository interface {
	Factory
	Transactor

	// Targets returns the target accessor.
	Targets() TargetAccessor

	// Scans returns the scan accessor.
	Scans() ScanAccessor

	// Findings returns the finding accessor.
	Findings() FindingAccessor

	// Credentials returns the credential accessor.
	Credentials() CredentialAccessor

	// Reports returns the report accessor.
	Reports() ReportAccessor

	// ReportSchedules returns the report schedule accessor.
	ReportSchedules() ReportScheduleAccessor

	// Payloads returns the payload accessor.
	Payloads() PayloadAccessor

	// PluginStats returns the plugin stats accessor.
	PluginStats() PluginStatsAccessor
}

// BaseAccessor provides common functionality for all accessors.
type BaseAccessor struct {
	factory Factory
	db      *sqlx.DB
	table   string
}

// Init initializes the accessor with a factory.
func (b *BaseAccessor) Init(f Factory, tableName string) {
	b.factory = f
	b.db = f.DB()
	b.table = tableName
}

// DB returns the database connection.
func (b *BaseAccessor) DB() *sqlx.DB {
	return b.db
}

// TableName returns the database table name.
func (b *BaseAccessor) TableName() string {
	return b.table
}

// Factory returns the factory instance.
func (b *BaseAccessor) Factory() Factory {
	return b.factory
}

// ExistsBy checks if a record exists by a specific field.
func (b *BaseAccessor) ExistsBy(ctx context.Context, field string, value interface{}) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM ` + b.table + ` WHERE ` + field + ` = ?)`

	var exists bool
	err := b.db.GetContext(ctx, &exists, query, value)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// CountBy returns count of records filtered by a specific field.
func (b *BaseAccessor) CountBy(ctx context.Context, field string, value interface{}) (int, error) {
	query := `SELECT COUNT(*) FROM ` + b.table + ` WHERE ` + field + ` = ?`

	var count int
	err := b.db.GetContext(ctx, &count, query, value)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// IsNotFound checks if an error represents a "not found" condition.
func IsNotFound(err error) bool {
	return err == sql.ErrNoRows
}