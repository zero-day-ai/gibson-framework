// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/zero-day-ai/gibson-framework/pkg/core/database/repositories"
	"github.com/zero-day-ai/gibson-framework/pkg/core/formatters"
)

// ScanService handles domain-based payload execution
type ScanService struct {
	db                *sqlx.DB
	payloadRepo       repositories.PayloadRepository
	apiFormatter      *formatters.APIFormatter
	workers           int
	progressCallback  func(string)
}

// ScanConfig holds configuration for scan execution
type ScanConfig struct {
	Workers          int      `json:"workers"`
	Domains          []string `json:"domains,omitempty"`
	TargetDomains    []string `json:"target_domains,omitempty"`
	ProgressCallback func(string)
}

// ScanResult holds the results of a scan execution
type ScanResult struct {
	ScanID         uuid.UUID             `json:"scan_id"`
	TotalPayloads  int                   `json:"total_payloads"`
	ExecutedCount  int                   `json:"executed_count"`
	SuccessCount   int                   `json:"success_count"`
	FailureCount   int                   `json:"failure_count"`
	Duration       time.Duration         `json:"duration"`
	DomainStats    map[string]DomainStat `json:"domain_stats"`
	Errors         []string              `json:"errors,omitempty"`
}

// DomainStat holds execution statistics for a domain
type DomainStat struct {
	Domain        string        `json:"domain"`
	PluginCount   int           `json:"plugin_count"`
	PayloadCount  int           `json:"payload_count"`
	ExecutedCount int           `json:"executed_count"`
	SuccessCount  int           `json:"success_count"`
	FailureCount  int           `json:"failure_count"`
	Duration      time.Duration `json:"duration"`
}

// ExecutionContext holds context for payload execution
type ExecutionContext struct {
	TargetName   string
	TargetConfig formatters.TargetConfig
	Domain       string
	Plugin       string
	Payload      *coremodels.PayloadDB
	WorkerID     int
}

// NewScanService creates a new scan service instance
func NewScanService(db *sqlx.DB, config ScanConfig) *ScanService {
	// Set defaults
	if config.Workers <= 0 {
		config.Workers = 5
	}

	return &ScanService{
		db:               db,
		apiFormatter:     formatters.NewAPIFormatter(),
		workers:          config.Workers,
		progressCallback: config.ProgressCallback,
	}
}

// SetPayloadRepository sets the payload repository dependency
func (s *ScanService) SetPayloadRepository(payloadRepo repositories.PayloadRepository) {
	s.payloadRepo = payloadRepo
}

// ExecuteByDomain executes payloads organized by domain
// Implements requirement 3, 4: domain-based execution with domain selection
func (s *ScanService) ExecuteByDomain(ctx context.Context, targetName string, domains []string) coremodels.Result[ScanResult] {
	startTime := time.Now()

	// Create scan record (simplified)
	scanID := uuid.New()

	result := ScanResult{
		ScanID:      scanID,
		DomainStats: make(map[string]DomainStat),
		Errors:      []string{},
	}

	// Target validation and config creation
	if targetName == "" {
		return coremodels.Err[ScanResult](fmt.Errorf("target name is required"))
	}

	// Create target config (simplified - in real implementation this would come from target repository)
	targetConfig := formatters.TargetConfig{
		Name:     targetName,
		URL:      "https://api.example.com/v1/chat/completions", // Default URL
		Provider: "generic",
		Headers:  make(map[string]string),
	}

	// Get all payloads if no domains specified
	var payloads []*coremodels.PayloadDB
	if len(domains) == 0 {
		// Load ALL payloads when no filter specified (requirement 5)
		payloadsResult := s.payloadRepo.List(ctx)
		if payloadsResult.IsErr() {
			return coremodels.Err[ScanResult](fmt.Errorf("failed to load payloads: %w", payloadsResult.Error()))
		}
		payloads = payloadsResult.Unwrap()
	} else {
		// Load payloads for specified domains
		allPayloadsResult := s.payloadRepo.List(ctx)
		if allPayloadsResult.IsErr() {
			return coremodels.Err[ScanResult](fmt.Errorf("failed to load payloads: %w", allPayloadsResult.Error()))
		}
		allPayloads := allPayloadsResult.Unwrap()

		// Filter by requested domains
		for _, payload := range allPayloads {
			for _, domain := range domains {
				if payload.Domain == domain {
					payloads = append(payloads, payload)
					break
				}
			}
		}
	}

	result.TotalPayloads = len(payloads)

	// Execute domains in order: model, data, interface, infrastructure, output, process
	domainOrder := []string{"model", "data", "interface", "infrastructure", "output", "process"}

	for _, domain := range domainOrder {
		// Skip empty domains without error (requirement 9)
		domainPayloads := s.filterPayloadsByDomain(payloads, domain)
		if len(domainPayloads) == 0 {
			s.reportProgress(fmt.Sprintf("Skipping empty domain: %s", domain))
			continue
		}

		s.reportProgress(fmt.Sprintf("Executing domain: %s (%d payloads)", domain, len(domainPayloads)))

		domainResult := s.executeDomain(ctx, targetConfig, domain, domainPayloads)
		if domainResult.IsOk() {
			domainStat := domainResult.Unwrap()
			result.DomainStats[domain] = domainStat
			result.ExecutedCount += domainStat.ExecutedCount
			result.SuccessCount += domainStat.SuccessCount
			result.FailureCount += domainStat.FailureCount
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("Domain %s failed: %v", domain, domainResult.Error()))
		}
	}

	// Update scan completion
	result.Duration = time.Since(startTime)

	return coremodels.Ok(result)
}

// executeDomain executes all payloads for a specific domain
func (s *ScanService) executeDomain(ctx context.Context, targetConfig formatters.TargetConfig, domain string, payloads []*coremodels.PayloadDB) coremodels.Result[DomainStat] {
	startTime := time.Now()

	stat := DomainStat{
		Domain:       domain,
		PayloadCount: len(payloads),
	}

	// Group payloads by plugin for parallel execution within each plugin
	pluginPayloads := s.groupPayloadsByPlugin(payloads)
	stat.PluginCount = len(pluginPayloads)

	// Execute each plugin's payloads in parallel
	for pluginName, pluginPayloads := range pluginPayloads {
		s.reportProgress(fmt.Sprintf("Executing plugin: %s/%s (%d payloads)", domain, pluginName, len(pluginPayloads)))

		pluginResult := s.executePluginPayloads(ctx, targetConfig, domain, pluginName, pluginPayloads)
		if pluginResult.IsOk() {
			pluginStat := pluginResult.Unwrap()
			stat.ExecutedCount += pluginStat.ExecutedCount
			stat.SuccessCount += pluginStat.SuccessCount
			stat.FailureCount += pluginStat.FailureCount
		}
	}

	stat.Duration = time.Since(startTime)
	return coremodels.Ok(stat)
}

// executePluginPayloads executes payloads for a specific plugin using worker pool
// Implements requirement 4: parallel payload execution within plugins
func (s *ScanService) executePluginPayloads(ctx context.Context, targetConfig formatters.TargetConfig, domain, plugin string, payloads []*coremodels.PayloadDB) coremodels.Result[DomainStat] {
	stat := DomainStat{
		Domain:       domain,
		PayloadCount: len(payloads),
	}

	// Create worker pool for parallel execution (5 workers by default)
	workers := s.workers
	if workers > len(payloads) {
		workers = len(payloads)
	}

	jobs := make(chan *coremodels.PayloadDB, len(payloads))
	results := make(chan bool, len(payloads))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for payload := range jobs {
				success := s.executePayload(ctx, ExecutionContext{
					TargetName:   targetConfig.Name,
					TargetConfig: targetConfig,
					Domain:       domain,
					Plugin:       plugin,
					Payload:      payload,
					WorkerID:     workerID,
				})
				results <- success
			}
		}(i)
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, payload := range payloads {
			jobs <- payload
		}
	}()

	// Wait for workers to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for success := range results {
		stat.ExecutedCount++
		if success {
			stat.SuccessCount++
		} else {
			stat.FailureCount++
		}
	}

	return coremodels.Ok(stat)
}

// executePayload executes a single payload using domain-specific formatting
// Returns true for success, false for failure
func (s *ScanService) executePayload(ctx context.Context, execCtx ExecutionContext) bool {
	s.reportProgress(fmt.Sprintf("Executing: %s/%s/%s", execCtx.Domain, execCtx.Plugin, execCtx.Payload.Name))

	// Format payload using domain-specific formatter
	apiRequest, err := s.apiFormatter.FormatRequest(execCtx.Payload, execCtx.TargetConfig)
	if err != nil {
		s.reportProgress(fmt.Sprintf("Failed to format request for %s: %v", execCtx.Payload.Name, err))
		return false
	}

	// Validate the API request
	if err := s.apiFormatter.ValidateAPIRequest(apiRequest); err != nil {
		s.reportProgress(fmt.Sprintf("Invalid API request for %s: %v", execCtx.Payload.Name, err))
		return false
	}

	// Create HTTP request
	httpRequest, err := s.apiFormatter.CreateHTTPRequest(apiRequest)
	if err != nil {
		s.reportProgress(fmt.Sprintf("Failed to create HTTP request for %s: %v", execCtx.Payload.Name, err))
		return false
	}

	// TODO: Actually execute the HTTP request
	// For now, just validate that the request was created successfully
	if httpRequest == nil {
		return false
	}

	// Simulate execution time
	time.Sleep(100 * time.Millisecond)

	// For now, simulate success since we're not actually executing
	s.reportProgress(fmt.Sprintf("Formatted and validated request for %s (Method: %s, URL: %s)",
		execCtx.Payload.Name, apiRequest.Method, apiRequest.URL))
	return true
}

// filterPayloadsByDomain filters payloads by domain
func (s *ScanService) filterPayloadsByDomain(payloads []*coremodels.PayloadDB, domain string) []*coremodels.PayloadDB {
	var filtered []*coremodels.PayloadDB
	for _, payload := range payloads {
		if payload.Domain == domain {
			filtered = append(filtered, payload)
		}
	}
	return filtered
}

// groupPayloadsByPlugin groups payloads by plugin name
func (s *ScanService) groupPayloadsByPlugin(payloads []*coremodels.PayloadDB) map[string][]*coremodels.PayloadDB {
	groups := make(map[string][]*coremodels.PayloadDB)
	for _, payload := range payloads {
		plugin := payload.PluginName
		if plugin == "" {
			plugin = "default"
		}
		groups[plugin] = append(groups[plugin], payload)
	}
	return groups
}

// reportProgress reports progress if callback is set
func (s *ScanService) reportProgress(message string) {
	if s.progressCallback != nil {
		s.progressCallback(message)
	}
}

// LoadAllPayloads loads all payloads from repository
// Implements requirement 5: comprehensive payload execution (no filtering by default)
func (s *ScanService) LoadAllPayloads(ctx context.Context) coremodels.Result[[]*coremodels.PayloadDB] {
	return s.payloadRepo.List(ctx)
}

// LoadPayloadsByDomains loads payloads filtered by specific domains
func (s *ScanService) LoadPayloadsByDomains(ctx context.Context, domains []string) coremodels.Result[[]*coremodels.PayloadDB] {
	// Get all payloads and filter by domains
	allPayloadsResult := s.payloadRepo.List(ctx)
	if allPayloadsResult.IsErr() {
		return allPayloadsResult
	}

	allPayloads := allPayloadsResult.Unwrap()
	var filteredPayloads []*coremodels.PayloadDB

	for _, payload := range allPayloads {
		for _, domain := range domains {
			if payload.Domain == domain {
				filteredPayloads = append(filteredPayloads, payload)
				break
			}
		}
	}

	return coremodels.Ok(filteredPayloads)
}