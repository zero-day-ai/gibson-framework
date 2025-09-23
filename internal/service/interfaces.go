// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package service

import (
	"context"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/google/uuid"
)

// CredentialService provides business logic for credential management
type CredentialService interface {
	// CRUD operations
	Create(ctx context.Context, req *model.CredentialCreateRequest) (*model.Credential, error)
	Get(ctx context.Context, id uuid.UUID) (*model.Credential, error)
	GetByName(ctx context.Context, name string) (*model.Credential, error)
	List(ctx context.Context) ([]*model.Credential, error)
	Update(ctx context.Context, id uuid.UUID, req *model.CredentialUpdateRequest) (*model.Credential, error)
	Delete(ctx context.Context, id uuid.UUID) error

	// Business operations
	ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Credential, error)
	ListByStatus(ctx context.Context, status model.CredentialStatus) ([]*model.Credential, error)
	GetActiveCredentials(ctx context.Context) ([]*model.Credential, error)

	// Security operations
	Validate(ctx context.Context, id uuid.UUID) (*model.CredentialValidationResult, error)
	Decrypt(ctx context.Context, id uuid.UUID) (string, error)
	Rotate(ctx context.Context, id uuid.UUID) error
	MarkAsUsed(ctx context.Context, id uuid.UUID) error

	// Export/Import
	Export(ctx context.Context, id uuid.UUID) (*model.CredentialExportData, error)
	ExportAll(ctx context.Context) ([]*model.CredentialExportData, error)
}

// ScanService provides business logic for scan management
type ScanService interface {
	// CRUD operations
	Create(ctx context.Context, targetID uuid.UUID, scanType model.ScanType, options map[string]interface{}) (*model.Scan, error)
	Get(ctx context.Context, id uuid.UUID) (*model.Scan, error)
	List(ctx context.Context) ([]*model.Scan, error)
	Update(ctx context.Context, scan *model.Scan) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Business operations
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Scan, error)
	ListByStatus(ctx context.Context, status model.ScanStatus) ([]*model.Scan, error)
	GetRunningScans(ctx context.Context) ([]*model.Scan, error)

	// Scan lifecycle
	Start(ctx context.Context, id uuid.UUID, startedBy string) error
	Stop(ctx context.Context, id uuid.UUID) error
	Cancel(ctx context.Context, id uuid.UUID) error
	UpdateProgress(ctx context.Context, id uuid.UUID, progress float64) error
	Complete(ctx context.Context, id uuid.UUID, statistics map[string]interface{}) error
	Fail(ctx context.Context, id uuid.UUID, errorMsg string) error

	// Scheduling
	Schedule(ctx context.Context, id uuid.UUID, scheduledFor time.Time) error
	GetScheduledScans(ctx context.Context) ([]*model.Scan, error)
}

// TargetService provides business logic for target management
type TargetService interface {
	// CRUD operations
	Create(ctx context.Context, target *model.Target) error
	Get(ctx context.Context, id uuid.UUID) (*model.Target, error)
	GetByName(ctx context.Context, name string) (*model.Target, error)
	List(ctx context.Context) ([]*model.Target, error)
	Update(ctx context.Context, target *model.Target) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByName(ctx context.Context, name string) error

	// Business operations
	ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Target, error)
	ListByStatus(ctx context.Context, status model.TargetStatus) ([]*model.Target, error)
	ListActiveTargets(ctx context.Context) ([]*model.Target, error)
	ExistsByName(ctx context.Context, name string) (bool, error)
	CountByProvider(ctx context.Context, provider model.Provider) (int, error)

	// Target lifecycle
	Activate(ctx context.Context, id uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID) error
	MarkError(ctx context.Context, id uuid.UUID, errorMsg string) error

	// Validation
	ValidateConfiguration(ctx context.Context, target *model.Target) error
	TestConnection(ctx context.Context, id uuid.UUID) error
}

// PluginService provides business logic for plugin management
type PluginService interface {
	// Plugin execution
	Execute(ctx context.Context, pluginName string, targetID uuid.UUID, scanID uuid.UUID, config map[string]interface{}) error

	// Plugin stats
	RecordMetric(ctx context.Context, pluginName, pluginVersion, metricName string, metricType model.PluginMetricType, value float64, unit string, tags map[string]interface{}, targetID, scanID *uuid.UUID) error
	GetStats(ctx context.Context, pluginName string) ([]*model.PluginStats, error)
	GetStatsByMetric(ctx context.Context, pluginName, metricName string) ([]*model.PluginStats, error)
	GetStatsByTimeRange(ctx context.Context, start, end time.Time) ([]*model.PluginStats, error)
	GetAggregatedStats(ctx context.Context, pluginName, metricName string, start, end time.Time) (map[string]float64, error)
	GetTimeSeriesData(ctx context.Context, pluginName, metricName string, start, end time.Time, interval string) ([]*model.PluginStats, error)
	GetTopPluginsByMetric(ctx context.Context, metricName string, metricType model.PluginMetricType, limit int) (map[string]float64, error)
	GetStatsByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.PluginStats, error)
	GetStatsByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.PluginStats, error)

	// Cleanup
	DeleteOldStats(ctx context.Context, before time.Time) (int64, error)
}

// PayloadService provides business logic for payload management
type PayloadService interface {
	// CRUD operations
	Create(ctx context.Context, payload *model.Payload) error
	Get(ctx context.Context, id uuid.UUID) (*model.Payload, error)
	GetByName(ctx context.Context, name string) (*model.Payload, error)
	List(ctx context.Context) ([]*model.Payload, error)
	Update(ctx context.Context, payload *model.Payload) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Business operations
	ListByCategory(ctx context.Context, category model.PayloadCategory) ([]*model.Payload, error)
	ListByDomain(ctx context.Context, domain string) ([]*model.Payload, error)
	ListEnabled(ctx context.Context) ([]*model.Payload, error)
	GetMostUsed(ctx context.Context, limit int) ([]*model.Payload, error)

	// Versioning
	GetVersions(ctx context.Context, parentID uuid.UUID) ([]*model.Payload, error)
	CreateVersion(ctx context.Context, originalID uuid.UUID, newPayload *model.Payload) error

	// Usage tracking
	UpdateUsageStats(ctx context.Context, id uuid.UUID, successful bool) error

	// Validation
	Validate(ctx context.Context, id uuid.UUID) (*model.Payload, error)
	ValidateContent(ctx context.Context, content string, payloadType model.PayloadType) error

	// Search and filtering
	Search(ctx context.Context, query string, category model.PayloadCategory, domain string, tags []string, limit, offset int) ([]*model.Payload, error)
	GetByTags(ctx context.Context, tags []string) ([]*model.Payload, error)
}

// ReportService provides business logic for report management
type ReportService interface {
	// CRUD operations
	Create(ctx context.Context, report *model.Report) error
	Get(ctx context.Context, id uuid.UUID) (*model.Report, error)
	List(ctx context.Context) ([]*model.Report, error)
	Update(ctx context.Context, report *model.Report) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Business operations
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Report, error)
	GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Report, error)
	ListByStatus(ctx context.Context, status model.ReportStatus) ([]*model.Report, error)
	ListByType(ctx context.Context, reportType model.ReportType) ([]*model.Report, error)
	GetScheduledReports(ctx context.Context) ([]*model.Report, error)

	// Report generation
	Generate(ctx context.Context, id uuid.UUID, generatedBy string) error
	GenerateFromScan(ctx context.Context, scanID uuid.UUID, reportType model.ReportType, format model.ReportFormat, config map[string]interface{}) (*model.Report, error)
	GenerateFromTarget(ctx context.Context, targetID uuid.UUID, reportType model.ReportType, format model.ReportFormat, config map[string]interface{}) (*model.Report, error)

	// Report lifecycle
	MarkCompleted(ctx context.Context, id uuid.UUID, outputPath string, fileSize int64) error
	MarkFailed(ctx context.Context, id uuid.UUID, errorMsg string) error

	// Scheduling
	Schedule(ctx context.Context, id uuid.UUID, scheduledFor time.Time) error
}

// FindingService provides business logic for finding management
type FindingService interface {
	// CRUD operations
	Create(ctx context.Context, finding *model.Finding) error
	Get(ctx context.Context, id uuid.UUID) (*model.Finding, error)
	List(ctx context.Context) ([]*model.Finding, error)
	Update(ctx context.Context, finding *model.Finding) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Business operations
	GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Finding, error)
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Finding, error)
	ListBySeverity(ctx context.Context, severity model.Severity) ([]*model.Finding, error)
	ListByStatus(ctx context.Context, status model.FindingStatus) ([]*model.Finding, error)
	GetHighSeverityFindings(ctx context.Context) ([]*model.Finding, error)
	CountBySeverity(ctx context.Context) (map[model.Severity]int, error)

	// Finding lifecycle
	Accept(ctx context.Context, id uuid.UUID, acceptedBy string, notes string) error
	Resolve(ctx context.Context, id uuid.UUID, resolvedBy string, notes string) error
	Suppress(ctx context.Context, id uuid.UUID, suppressedBy string, reason string) error
	Reopen(ctx context.Context, id uuid.UUID, reopenedBy string, reason string) error

	// Bulk operations
	BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status model.FindingStatus, updatedBy string) error
	BulkDelete(ctx context.Context, ids []uuid.UUID) error

	// Deduplication
	FindDuplicates(ctx context.Context, finding *model.Finding) ([]*model.Finding, error)
	MergeDuplicates(ctx context.Context, primaryID uuid.UUID, duplicateIDs []uuid.UUID) error
}

// ReportScheduleService provides business logic for report scheduling
type ReportScheduleService interface {
	// CRUD operations
	Create(ctx context.Context, schedule *model.ReportSchedule) error
	Get(ctx context.Context, id uuid.UUID) (*model.ReportSchedule, error)
	List(ctx context.Context) ([]*model.ReportSchedule, error)
	Update(ctx context.Context, schedule *model.ReportSchedule) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Business operations
	ListEnabled(ctx context.Context) ([]*model.ReportSchedule, error)
	GetDueSchedules(ctx context.Context) ([]*model.ReportSchedule, error)
	GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.ReportSchedule, error)

	// Schedule management
	Enable(ctx context.Context, id uuid.UUID) error
	Disable(ctx context.Context, id uuid.UUID) error
	UpdateLastRun(ctx context.Context, id uuid.UUID, lastRun time.Time, nextRun *time.Time) error
	UpdateNextRun(ctx context.Context, id uuid.UUID, nextRun *time.Time) error

	// Schedule execution
	ExecuteSchedule(ctx context.Context, id uuid.UUID) (*model.Report, error)
	CalculateNextRun(ctx context.Context, id uuid.UUID) (*time.Time, error)
}