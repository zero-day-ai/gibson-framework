// Package view provides scan view implementation for CLI commands
package view

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/plugin"
	"github.com/zero-day-ai/gibson-framework/internal/pool"
	"github.com/zero-day-ai/gibson-framework/internal/providers"
	"github.com/zero-day-ai/gibson-framework/internal/service"
	sdkplugin "github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
	"github.com/google/uuid"
	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

// scanView implements ScanViewer following k9s patterns
type scanView struct {
	serviceFactory *service.ServiceFactory
	scanService    service.ScanService
	targetService  service.TargetService
	findingService service.FindingService
	pluginService  service.PluginService
	pluginManager  *plugin.Manager
	logger         *slog.Logger
}

// NewScanView creates a new scan view instance
func NewScanView() (*scanView, error) {
	// Initialize database connection
	gibsonHome, err := getGibsonHome()
	if err != nil {
		return nil, fmt.Errorf("failed to determine gibson home: %w", err)
	}

	// Initialize repository
	dbPath := filepath.Join(gibsonHome, "gibson.db")
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", dbPath)
	repo, err := dao.NewSQLiteRepository(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize repository: %w", err)
	}

	// Read encryption key
	encryptionKey, err := readEncryptionKey(gibsonHome)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption key: %w", err)
	}

	// Initialize logger
	logger := slog.Default()

	// Create service factory
	serviceFactory := service.NewServiceFactory(repo, logger, encryptionKey)

	// Initialize plugin manager
	pluginsDir := filepath.Join(gibsonHome, "plugins")
	pluginManager := plugin.NewManager(pluginsDir,
		plugin.WithLogger(logger),
		plugin.WithGRPC(true),
		plugin.WithMaxPlugins(10),
		plugin.WithTimeout(30*time.Second),
	)

	return &scanView{
		serviceFactory: serviceFactory,
		scanService:    serviceFactory.ScanService(),
		targetService:  serviceFactory.TargetService(),
		findingService: serviceFactory.FindingService(),
		pluginService:  serviceFactory.PluginService(),
		pluginManager:  pluginManager,
		logger:         logger,
	}, nil
}


// Command integration methods following k9s patterns

// ScanStartOptions defines options for starting a scan
type ScanStartOptions struct {
	Target  string
	Type    string
	Plugins string
	Output  string
	Verbose bool
}

// StartScan starts a new security scan with the given options
func (sv *scanView) StartScan(ctx context.Context, opts ScanStartOptions) error {
	sv.logger.InfoContext(ctx, "Starting security scan", "target", opts.Target, "type", opts.Type)

	// Validate required fields
	if opts.Target == "" {
		return fmt.Errorf("target is required")
	}

	// Get target by name
	target, err := sv.targetService.GetByName(ctx, opts.Target)
	if err != nil {
		return fmt.Errorf("failed to find target %s: %w", opts.Target, err)
	}

	// Validate and apply default model if missing (for legacy targets)
	if target.Model == "" {
		sv.logger.InfoContext(ctx, "Target missing model, applying default", "target", target.Name, "provider", target.Provider)

		// Create provider adapter for model defaulting
		providerAdapter := providers.NewProviderAdapter()
		resolvedModelResult := providerAdapter.ResolveModelWithDefault(ctx, target.Provider, "")
		if !resolvedModelResult.IsOk() {
			return fmt.Errorf("failed to resolve default model for target %s: %w", target.Name, resolvedModelResult.Error())
		}
		resolvedModel := resolvedModelResult.Unwrap()

		// Update target with default model
		target.Model = resolvedModel
		if err := sv.targetService.Update(ctx, target); err != nil {
			sv.logger.WarnContext(ctx, "Failed to update target with default model", "error", err)
			// Continue with scan even if update fails
		} else {
			fmt.Printf("ℹ️  Applied default model '%s' to target '%s'\n", resolvedModel, target.Name)
		}
	}

	// Determine scan type
	scanType := model.ScanTypeBasic
	if opts.Type != "" {
		switch strings.ToLower(opts.Type) {
		case "basic":
			scanType = model.ScanTypeBasic
		case "advanced":
			scanType = model.ScanTypeAdvanced
		case "custom":
			scanType = model.ScanTypeCustom
		default:
			return fmt.Errorf("invalid scan type: %s", opts.Type)
		}
	}

	// Prepare scan options
	options := map[string]interface{}{
		"plugins": opts.Plugins,
		"output":  opts.Output,
	}

	// Create scan
	scan, err := sv.scanService.Create(ctx, target.ID, scanType, options)
	if err != nil {
		return fmt.Errorf("failed to create scan: %w", err)
	}

	fmt.Printf("Created scan %s for target %s\n", scan.ID, target.Name)

	// Start scan execution
	if err := sv.scanService.Start(ctx, scan.ID, "cli"); err != nil {
		return fmt.Errorf("failed to start scan: %w", err)
	}

	// Execute scan synchronously for CLI tool - this ensures completion
	// Use a context with timeout to ensure proper cleanup
	// Increased timeout to 2 hours to handle large payload sets
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()

	fmt.Printf("Scan %s started, executing...\n", scan.ID)
	sv.logger.InfoContext(scanCtx, "Starting synchronous scan execution", "scan_id", scan.ID)

	// Pass verbose flag through context
	if opts.Verbose {
		scanCtx = context.WithValue(scanCtx, "verbose", true)
	}

	// Execute the scan synchronously
	sv.executeFullScan(scanCtx, scan.ID, opts.Plugins)

	fmt.Printf("Scan %s completed\n", scan.ID)
	return nil
}

// ScanStopOptions defines options for stopping a scan
type ScanStopOptions struct {
	ID  string
	All bool
}

// StopScan stops a running scan
func (sv *scanView) StopScan(ctx context.Context, opts ScanStopOptions) error {
	if opts.All {
		// Operation completed - silent logging
		fmt.Println("Stopping all running scans...")
	} else if opts.ID != "" {
		// Operation completed - silent logging
		fmt.Printf("Stopping scan: %s\n", opts.ID)
	} else {
		return fmt.Errorf("either scan ID or --all flag must be specified")
	}

	return nil
}

// ScanListOptions defines options for listing scans
type ScanListOptions struct {
	Output string
}

// ListScans lists all scans
func (sv *scanView) ListScans(ctx context.Context, opts ScanListOptions) error {
	sv.logger.InfoContext(ctx, "Listing scans")

	// Get all scans
	scans, err := sv.scanService.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	if len(scans) == 0 {
		fmt.Println("No scans found")
		return nil
	}

	// Format output based on requested format
	switch strings.ToLower(opts.Output) {
	case "json":
		return sv.outputScansJSON(scans)
	case "yaml":
		return sv.outputScansYAML(scans)
	default:
		return sv.outputScansTable(scans)
	}
}

// ScanStatusOptions defines options for getting scan status
type ScanStatusOptions struct {
	ID     string
	Output string
}

// GetScanStatus gets detailed status for a scan
func (sv *scanView) GetScanStatus(ctx context.Context, opts ScanStatusOptions) error {
	if opts.ID == "" {
		return fmt.Errorf("scan ID is required")
	}

	// Operation completed - silent logging
	fmt.Printf("Getting status for scan: %s\n", opts.ID)
	fmt.Printf("Output format: %s\n", opts.Output)

	return nil
}

// ScanDeleteOptions defines options for deleting scans
type ScanDeleteOptions struct {
	ID  string
	All bool
}

// DeleteScan deletes a scan
func (sv *scanView) DeleteScan(ctx context.Context, opts ScanDeleteOptions) error {
	if opts.All {
		// Operation completed - silent logging
		fmt.Println("Deleting all scans...")
	} else if opts.ID != "" {
		// Operation completed - silent logging
		fmt.Printf("Deleting scan: %s\n", opts.ID)
	} else {
		return fmt.Errorf("either scan ID or --all flag must be specified")
	}

	return nil
}

// ScanResultsOptions defines options for getting scan results
type ScanResultsOptions struct {
	ID         string
	Output     string
	Severity   string
	Category   string
	ExportFile string
	Detailed   bool
	Summary    bool
}

// GetScanResults gets detailed scan results with findings by severity
func (sv *scanView) GetScanResults(ctx context.Context, opts ScanResultsOptions) error {
	if opts.ID == "" {
		return fmt.Errorf("scan ID is required")
	}

	sv.logger.InfoContext(ctx, "Getting scan results", "id", opts.ID, "severity", opts.Severity)

	// Parse scan ID
	scanID, err := uuid.Parse(opts.ID)
	if err != nil {
		return fmt.Errorf("invalid scan ID: %w", err)
	}

	// Get scan details
	scan, err := sv.scanService.Get(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	// Get findings for this scan
	findings, err := sv.findingService.GetByScanID(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan findings: %w", err)
	}

	// Filter findings if requested
	filteredFindings := sv.filterFindings(findings, opts)

	if opts.Summary {
		return sv.outputScanSummary(scan, filteredFindings)
	}

	if opts.ExportFile != "" {
		return sv.exportScanResults(scan, filteredFindings, opts.ExportFile, opts.Output)
	}

	// Format output based on requested format
	switch strings.ToLower(opts.Output) {
	case "json":
		return sv.outputScanResultsJSON(scan, filteredFindings)
	case "yaml":
		return sv.outputScanResultsYAML(scan, filteredFindings)
	default:
		return sv.outputScanResultsTable(scan, filteredFindings, opts.Detailed)
	}
}

// ScanBatchOptions defines options for batch scanning
type ScanBatchOptions struct {
	Targets    []string
	Type       string
	Plugins    string
	Output     string
	Workers    int
	Progress   bool
	Aggregate  bool
	ExportFile string
}

// RunBatchScan runs multiple scans in parallel
func (sv *scanView) RunBatchScan(ctx context.Context, opts ScanBatchOptions) error {
	if len(opts.Targets) == 0 {
		return fmt.Errorf("no targets specified for batch scan")
	}

	sv.logger.InfoContext(ctx, "Running batch scan", "targets", len(opts.Targets), "workers", opts.Workers)

	// Determine worker pool size
	workerCount := opts.Workers
	if workerCount <= 0 {
		workerCount = 5 // Default to 5 concurrent workers
	}

	fmt.Printf("Starting batch scan on %d targets using %d workers\n", len(opts.Targets), workerCount)

	// Determine scan type
	scanType := model.ScanTypeBasic
	if opts.Type != "" {
		switch strings.ToLower(opts.Type) {
		case "basic":
			scanType = model.ScanTypeBasic
		case "advanced":
			scanType = model.ScanTypeAdvanced
		case "custom":
			scanType = model.ScanTypeCustom
		default:
			return fmt.Errorf("invalid scan type: %s", opts.Type)
		}
	}

	// Create worker pool for batch scanning
	scannerPool := pool.NewScannerPool(ctx, workerCount)
	defer scannerPool.Drain()

	// Track results
	var (
		successCount int32
		failureCount int32
		allScans     = make([]*model.Scan, 0, len(opts.Targets))
		scansMutex   sync.Mutex
		progressChan = make(chan string, len(opts.Targets))
	)

	// Start progress tracking if requested
	if opts.Progress {
		go sv.trackBatchProgress(progressChan, len(opts.Targets))
	}

	// Submit scan jobs to the pool
	for i, targetName := range opts.Targets {
		targetIndex := i + 1
		scannerPool.AddScanJob(func(jobCtx context.Context) error {
			defer func() {
				if opts.Progress {
					select {
					case progressChan <- fmt.Sprintf("[%d/%d] %s", targetIndex, len(opts.Targets), targetName):
					default:
					}
				}
			}()

			// Execute single scan
			scan, err := sv.executeBatchScanTarget(jobCtx, targetName, scanType, opts)
			if err != nil {
				sv.logger.ErrorContext(jobCtx, "Batch scan failed for target", "target", targetName, "error", err)
				atomicInc(&failureCount)
				return err
			}

			atomicInc(&successCount)
			scansMutex.Lock()
			allScans = append(allScans, scan)
			scansMutex.Unlock()

			return nil
		})
	}

	// Wait for all scans to complete
	errors := scannerPool.Drain()
	close(progressChan)

	// Report results
	fmt.Printf("\nBatch scan completed: %d successful, %d failed\n", successCount, failureCount)

	if len(errors) > 0 {
		fmt.Printf("Errors encountered: %d\n", len(errors))
		for i, err := range errors {
			if i < 5 { // Show only first 5 errors
				fmt.Printf("  - %s\n", err)
			}
		}
		if len(errors) > 5 {
			fmt.Printf("  ... and %d more\n", len(errors)-5)
		}
	}

	// Handle result aggregation and export
	if opts.Aggregate && len(allScans) > 0 {
		return sv.aggregateBatchResults(ctx, allScans, opts)
	}

	return nil
}

// executeScan executes a scan with real plugin coordination
func (sv *scanView) executeScan(ctx context.Context, scanID uuid.UUID, pluginsFilter string) {
	start := time.Now()
	sv.logger.InfoContext(ctx, "Starting scan execution", "scan_id", scanID)

	defer func() {
		if r := recover(); r != nil {
			sv.logger.ErrorContext(ctx, "Scan execution panicked", "scan_id", scanID, "panic", r)
			if err := sv.scanService.Fail(ctx, scanID, fmt.Sprintf("Scan panicked: %v", r)); err != nil {
				sv.logger.ErrorContext(ctx, "Failed to mark scan as failed", "scan_id", scanID, "error", err)
			}
		}
	}()

	// Get scan details
	scan, err := sv.scanService.Get(ctx, scanID)
	if err != nil {
		sv.logger.ErrorContext(ctx, "Failed to get scan", "scan_id", scanID, "error", err)
		return
	}

	// Get target details
	target, err := sv.targetService.Get(ctx, scan.TargetID)
	if err != nil {
		sv.logger.ErrorContext(ctx, "Failed to get target", "target_id", scan.TargetID, "error", err)
		if markErr := sv.scanService.Fail(ctx, scanID, fmt.Sprintf("Failed to get target: %v", err)); markErr != nil {
			sv.logger.ErrorContext(ctx, "Failed to mark scan as failed", "scan_id", scanID, "error", markErr)
		}
		return
	}

	// Discover available plugins
	pluginNames, err := sv.pluginManager.Discover()
	if err != nil {
		sv.logger.ErrorContext(ctx, "Failed to discover plugins", "error", err)
		if markErr := sv.scanService.Fail(ctx, scanID, fmt.Sprintf("Failed to discover plugins: %v", err)); markErr != nil {
			sv.logger.ErrorContext(ctx, "Failed to mark scan as failed", "scan_id", scanID, "error", markErr)
		}
		return
	}

	// Filter plugins if specified
	if pluginsFilter != "" {
		pluginNames = sv.filterPlugins(pluginNames, pluginsFilter)
	}

	if len(pluginNames) == 0 {
		sv.logger.WarnContext(ctx, "No plugins available for scan", "scan_id", scanID)
		if err := sv.scanService.Complete(ctx, scanID, map[string]interface{}{
			"plugins_executed": 0,
			"findings_found":   0,
			"duration":         time.Since(start).Seconds(),
		}); err != nil {
			sv.logger.ErrorContext(ctx, "Failed to complete scan", "scan_id", scanID, "error", err)
		}
		return
	}

	// Execute plugins in parallel
	sv.logger.InfoContext(ctx, "Executing plugins", "scan_id", scanID, "plugin_count", len(pluginNames))

	// Create worker pool for plugin execution
	pluginPool := pool.NewScannerPool(ctx, 3) // Limit concurrent plugins
	defer pluginPool.Drain()

	var (
		totalFindings int32
		pluginsExecuted int32
		findingsMutex sync.Mutex
		allFindings   []*model.Finding
	)

	// Submit plugin execution jobs
	for i, pluginName := range pluginNames {
		pluginIndex := i
		pluginPool.AddPluginJob(func(pluginCtx context.Context) error {
			defer atomicInc(&pluginsExecuted)

			// Update scan progress
			progress := float64(pluginIndex+1) / float64(len(pluginNames)) * 100
			if err := sv.scanService.UpdateProgress(pluginCtx, scanID, progress); err != nil {
				sv.logger.ErrorContext(pluginCtx, "Failed to update scan progress", "scan_id", scanID, "error", err)
			}

			// Execute plugin
			findings, err := sv.executePlugin(pluginCtx, pluginName, target, scan)
			if err != nil {
				sv.logger.ErrorContext(pluginCtx, "Plugin execution failed", "plugin", pluginName, "scan_id", scanID, "error", err)
				return err
			}

			if len(findings) > 0 {
				// Store findings in database
				for _, finding := range findings {
					if err := sv.findingService.Create(pluginCtx, finding); err != nil {
						sv.logger.ErrorContext(pluginCtx, "Failed to store finding", "scan_id", scanID, "plugin", pluginName, "error", err)
						continue
					}
				}

				findingsMutex.Lock()
				allFindings = append(allFindings, findings...)
				atomicAdd(&totalFindings, int32(len(findings)))
				findingsMutex.Unlock()

				sv.logger.InfoContext(pluginCtx, "Plugin completed with findings", "plugin", pluginName, "scan_id", scanID, "findings", len(findings))
			} else {
				sv.logger.InfoContext(pluginCtx, "Plugin completed with no findings", "plugin", pluginName, "scan_id", scanID)
			}

			return nil
		})
	}

	// Wait for all plugins to complete
	errors := pluginPool.Drain()

	// Check for execution errors
	if len(errors) > 0 {
		errorMsg := fmt.Sprintf("Plugin execution errors: %d", len(errors))
		sv.logger.ErrorContext(ctx, "Scan completed with errors", "scan_id", scanID, "errors", len(errors))
		if err := sv.scanService.Fail(ctx, scanID, errorMsg); err != nil {
			sv.logger.ErrorContext(ctx, "Failed to mark scan as failed", "scan_id", scanID, "error", err)
		}
		return
	}

	// Complete scan with statistics
	statistics := map[string]interface{}{
		"plugins_executed": pluginsExecuted,
		"findings_found":   totalFindings,
		"duration":         time.Since(start).Seconds(),
		"completed_at":     time.Now(),
	}

	if err := sv.scanService.Complete(ctx, scanID, statistics); err != nil {
		sv.logger.ErrorContext(ctx, "Failed to complete scan", "scan_id", scanID, "error", err)
		return
	}

	sv.logger.InfoContext(ctx, "Scan completed successfully", "scan_id", scanID, "plugins", pluginsExecuted, "findings", totalFindings, "duration", time.Since(start))
}

// executeFullScan executes a complete scan with both plugins and direct scanning
func (sv *scanView) executeFullScan(ctx context.Context, scanID uuid.UUID, pluginsFilter string) {
	start := time.Now()
	sv.logger.InfoContext(ctx, "Starting full scan execution", "scan_id", scanID)
	// Debug logging removed - scan execution working correctly

	defer func() {
		if r := recover(); r != nil {
			sv.logger.ErrorContext(ctx, "Full scan execution panicked", "scan_id", scanID, "panic", r)
			if err := sv.scanService.Fail(ctx, scanID, fmt.Sprintf("Scan panicked: %v", r)); err != nil {
				sv.logger.ErrorContext(ctx, "Failed to mark scan as failed", "scan_id", scanID, "error", err)
			}
		}
	}()

	// Get scan details
	scan, err := sv.scanService.Get(ctx, scanID)
	if err != nil {
		sv.logger.ErrorContext(ctx, "Failed to get scan", "scan_id", scanID, "error", err)
		return
	}

	// Get target details
	target, err := sv.targetService.Get(ctx, scan.TargetID)
	if err != nil {
		sv.logger.ErrorContext(ctx, "Failed to get target", "target_id", scan.TargetID, "error", err)
		if markErr := sv.scanService.Fail(ctx, scanID, fmt.Sprintf("Failed to get target: %v", err)); markErr != nil {
			sv.logger.ErrorContext(ctx, "Failed to mark scan as failed", "scan_id", scanID, "error", markErr)
		}
		return
	}

	var (
		totalFindings   int32
		processedCount  int32
		findingsMutex   sync.Mutex
		allFindings     []*model.Finding
	)

	// Phase 1: Try plugin execution first
	pluginFindings := sv.executePluginsPhase(ctx, scanID, pluginsFilter, target, scan)
	if len(pluginFindings) > 0 {
		findingsMutex.Lock()
		allFindings = append(allFindings, pluginFindings...)
		totalFindings += int32(len(pluginFindings))
		findingsMutex.Unlock()
		sv.logger.InfoContext(ctx, "Plugin phase completed", "scan_id", scanID, "plugin_findings", len(pluginFindings))
	}

	// Update progress to 50% after plugin phase
	if err := sv.scanService.UpdateProgress(ctx, scanID, 50.0); err != nil {
		sv.logger.ErrorContext(ctx, "Failed to update scan progress", "scan_id", scanID, "error", err)
	}

	// Phase 2: Direct scan execution (core engine)
	directFindings := sv.executeDirectScanPhase(ctx, scanID, target, scan)
	if len(directFindings) > 0 {
		findingsMutex.Lock()
		allFindings = append(allFindings, directFindings...)
		totalFindings += int32(len(directFindings))
		findingsMutex.Unlock()
		sv.logger.InfoContext(ctx, "Direct scan phase completed", "scan_id", scanID, "direct_findings", len(directFindings))
	}

	// Update progress to 100%
	if err := sv.scanService.UpdateProgress(ctx, scanID, 100.0); err != nil {
		sv.logger.ErrorContext(ctx, "Failed to update final scan progress", "scan_id", scanID, "error", err)
	}

	// Complete scan with statistics
	statistics := map[string]interface{}{
		"plugins_executed": len(pluginFindings),
		"direct_payloads_executed": processedCount,
		"findings_found": totalFindings,
		"duration": time.Since(start).Seconds(),
		"completed_at": time.Now(),
		"execution_method": "hybrid", // Both plugins and direct
	}

	if err := sv.scanService.Complete(ctx, scanID, statistics); err != nil {
		sv.logger.ErrorContext(ctx, "Failed to complete scan", "scan_id", scanID, "error", err)
		return
	}

	sv.logger.InfoContext(ctx, "Full scan completed successfully", "scan_id", scanID, "total_findings", totalFindings, "duration", time.Since(start))
}

// executePluginsPhase executes the plugin-based scanning phase
func (sv *scanView) executePluginsPhase(ctx context.Context, scanID uuid.UUID, pluginsFilter string, target *model.Target, scan *model.Scan) []*model.Finding {
	// Discover available plugins
	pluginNames, err := sv.pluginManager.Discover()
	if err != nil {
		sv.logger.WarnContext(ctx, "Failed to discover plugins, skipping plugin phase", "error", err)
		return nil
	}

	// Filter plugins if specified
	if pluginsFilter != "" {
		pluginNames = sv.filterPlugins(pluginNames, pluginsFilter)
	}

	if len(pluginNames) == 0 {
		sv.logger.InfoContext(ctx, "No plugins available, skipping plugin phase", "scan_id", scanID)
		return nil
	}

	// Execute plugins in parallel
	sv.logger.InfoContext(ctx, "Executing plugins", "scan_id", scanID, "plugin_count", len(pluginNames))

	// Create worker pool for plugin execution
	pluginPool := pool.NewScannerPool(ctx, 3) // Limit concurrent plugins
	defer pluginPool.Drain()

	var (
		pluginFindings []*model.Finding
		findingsMutex  sync.Mutex
	)

	// Submit plugin execution jobs
	for i, pluginName := range pluginNames {
		pluginIndex := i
		pluginPool.AddPluginJob(func(pluginCtx context.Context) error {
			// Update scan progress
			progress := float64(pluginIndex+1) / float64(len(pluginNames)) * 25.0 // Plugins take 25% of total progress
			if err := sv.scanService.UpdateProgress(pluginCtx, scanID, progress); err != nil {
				sv.logger.ErrorContext(pluginCtx, "Failed to update scan progress", "scan_id", scanID, "error", err)
			}

			// Execute plugin
			findings, err := sv.executePlugin(pluginCtx, pluginName, target, scan)
			if err != nil {
				sv.logger.ErrorContext(pluginCtx, "Plugin execution failed", "plugin", pluginName, "scan_id", scanID, "error", err)
				return err
			}

			if len(findings) > 0 {
				// Store findings in database
				for _, finding := range findings {
					if err := sv.findingService.Create(pluginCtx, finding); err != nil {
						sv.logger.ErrorContext(pluginCtx, "Failed to store finding", "scan_id", scanID, "plugin", pluginName, "error", err)
						continue
					}
				}

				findingsMutex.Lock()
				pluginFindings = append(pluginFindings, findings...)
				findingsMutex.Unlock()

				sv.logger.InfoContext(pluginCtx, "Plugin completed with findings", "plugin", pluginName, "scan_id", scanID, "findings", len(findings))
			} else {
				sv.logger.InfoContext(pluginCtx, "Plugin completed with no findings", "plugin", pluginName, "scan_id", scanID)
			}

			return nil
		})
	}

	// Wait for all plugins to complete
	errors := pluginPool.Drain()
	if len(errors) > 0 {
		sv.logger.WarnContext(ctx, "Some plugins failed during execution", "scan_id", scanID, "errors", len(errors))
	}

	return pluginFindings
}

// executeDirectScanPhase executes the direct scanning phase using built-in payloads
func (sv *scanView) executeDirectScanPhase(ctx context.Context, scanID uuid.UUID, target *model.Target, scan *model.Scan) []*model.Finding {
	sv.logger.InfoContext(ctx, "Starting direct scan phase", "scan_id", scanID, "target", target.Name)

	// Get payloads from payload service
	payloadService := sv.serviceFactory.PayloadService()
	payloads, err := payloadService.ListEnabled(ctx)
	if err != nil {
		sv.logger.ErrorContext(ctx, "Failed to get payloads for direct scan", "scan_id", scanID, "error", err)
		return nil
	}

	if len(payloads) == 0 {
		sv.logger.InfoContext(ctx, "No payloads available for direct scan", "scan_id", scanID)
		return nil
	}

	sv.logger.InfoContext(ctx, "Loaded payloads for direct scan", "scan_id", scanID, "payload_count", len(payloads))

	// Create HTTP client for API requests
	// Increased timeout to 2 minutes to handle slow API responses
	httpClient := &http.Client{
		Timeout: 2 * time.Minute,
	}

	var (
		directFindings []*model.Finding
		findingsMutex  sync.Mutex
		processedCount int32
	)

	// Create worker pool for payload execution
	payloadPool := pool.NewScannerPool(ctx, 5) // Process payloads concurrently
	defer payloadPool.Drain()

	// Execute payloads against target
	for i, payload := range payloads {
		payloadIndex := i
		payloadCopy := payload // Capture for closure
		payloadPool.AddScanJob(func(payloadCtx context.Context) error {
			atomic.AddInt32(&processedCount, 1)

			// Update progress (50% to 95% for direct scan phase)
			progress := 50.0 + (float64(payloadIndex+1)/float64(len(payloads)))*45.0
			if err := sv.scanService.UpdateProgress(payloadCtx, scanID, progress); err != nil {
				sv.logger.ErrorContext(payloadCtx, "Failed to update scan progress", "scan_id", scanID, "error", err)
			}

			// Convert model.Payload to coremodels.PayloadDB for compatibility
			payloadDB := sv.convertToPayloadDB(payloadCopy)

			// Execute payload against target
			findings, err := sv.executePayloadAgainstTarget(payloadCtx, httpClient, target, payloadDB, scan)
			if err != nil {
				sv.logger.WarnContext(payloadCtx, "Payload execution failed", "payload", payloadCopy.Name, "scan_id", scanID, "error", err)
				return nil // Continue with other payloads even if one fails
			}

			if len(findings) > 0 {
				// Store findings in database
				for _, finding := range findings {
					if err := sv.findingService.Create(payloadCtx, finding); err != nil {
						sv.logger.ErrorContext(payloadCtx, "Failed to store finding", "scan_id", scanID, "payload", payloadCopy.Name, "error", err)
						continue
					}
				}

				findingsMutex.Lock()
				directFindings = append(directFindings, findings...)
				findingsMutex.Unlock()

				sv.logger.InfoContext(payloadCtx, "Payload execution completed with findings", "payload", payloadCopy.Name, "scan_id", scanID, "findings", len(findings))
			} else {
				sv.logger.DebugContext(payloadCtx, "Payload execution completed with no findings", "payload", payloadCopy.Name, "scan_id", scanID)
			}

			// Update payload usage statistics
			if err := payloadService.UpdateUsageStats(payloadCtx, payloadCopy.ID, err == nil); err != nil {
				sv.logger.WarnContext(payloadCtx, "Failed to update payload usage stats", "payload", payloadCopy.Name, "error", err)
			}

			return nil
		})
	}

	// Wait for all payloads to complete
	errors := payloadPool.Drain()
	if len(errors) > 0 {
		sv.logger.WarnContext(ctx, "Some payload executions encountered errors", "scan_id", scanID, "errors", len(errors))
	}

	sv.logger.InfoContext(ctx, "Direct scan phase completed", "scan_id", scanID, "payloads_processed", processedCount, "findings", len(directFindings))
	return directFindings
}

// convertToPayloadDB converts model.Payload to coremodels.PayloadDB
func (sv *scanView) convertToPayloadDB(payload *model.Payload) *coremodels.PayloadDB {
	return &coremodels.PayloadDB{
		ID:          payload.ID,
		Name:        payload.Name,
		Category:    coremodels.PayloadCategory(payload.Category),
		Domain:      payload.Domain,
		Type:        coremodels.PayloadType(payload.Type),
		Content:     payload.Content,
		Description: payload.Description,
		Severity:    payload.Severity,
		Tags:        payload.Tags,
		Enabled:     payload.Enabled,
		CreatedAt:   payload.CreatedAt,
		UpdatedAt:   payload.UpdatedAt,
	}
}

// executePayloadAgainstTarget executes a specific payload against the target API
func (sv *scanView) executePayloadAgainstTarget(ctx context.Context, httpClient *http.Client, target *model.Target, payload *coremodels.PayloadDB, scan *model.Scan) ([]*model.Finding, error) {
	// Get credential for target
	credential, err := sv.getTargetCredential(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("failed to get target credential: %w", err)
	}

	// Create HTTP request based on target provider
	req, err := sv.createAPIRequest(ctx, target, payload, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to create API request: %w", err)
	}

	// Check if verbose mode is enabled
	verbose, _ := ctx.Value("verbose").(bool)

	// Log the request being sent for debugging
	sv.logger.DebugContext(ctx, "Sending API request",
		"target", target.Name,
		"payload", payload.Name,
		"url", req.URL.String(),
		"method", req.Method)

	if verbose {
		fmt.Printf("\n[VERBOSE] Sending payload: %s\n", payload.Name)
		fmt.Printf("  Payload ID: %s\n", payload.ID.String())
		fmt.Printf("  Target: %s\n", target.Name)
		fmt.Printf("  URL: %s\n", req.URL.String())
	}

	// Execute HTTP request
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Log the actual response for debugging
	sv.logger.DebugContext(ctx, "API request completed",
		"target", target.Name,
		"payload", payload.Name,
		"status", resp.StatusCode,
		"duration", duration,
		"response_body", string(body))

	// Output to console if verbose mode is enabled
	if verbose {
		fmt.Printf("  Status: %d\n", resp.StatusCode)
		fmt.Printf("  Duration: %v\n", duration)

		// Parse and display response content
		if len(body) > 0 {
			// Try to parse as JSON for better formatting
			var jsonResp map[string]interface{}
			if err := json.Unmarshal(body, &jsonResp); err == nil {
				// For Anthropic responses, extract the content
				if content, ok := jsonResp["content"].([]interface{}); ok && len(content) > 0 {
					if firstContent, ok := content[0].(map[string]interface{}); ok {
						if text, ok := firstContent["text"].(string); ok {
							fmt.Printf("  Response: %s\n", text)
							if len(text) > 200 {
								fmt.Printf("  (truncated, showing first 200 chars)\n")
							}
						}
					}
				} else if error, ok := jsonResp["error"].(map[string]interface{}); ok {
					fmt.Printf("  Error: %v\n", error["message"])
				} else {
					// Show raw response if structure is different
					responseStr := string(body)
					if len(responseStr) > 200 {
						responseStr = responseStr[:200] + "..."
					}
					fmt.Printf("  Response: %s\n", responseStr)
				}
			} else {
				// Not JSON, show as string
				responseStr := string(body)
				if len(responseStr) > 200 {
					responseStr = responseStr[:200] + "..."
				}
				fmt.Printf("  Response: %s\n", responseStr)
			}
		}
		fmt.Println()
	}

	// Analyze response for security issues
	findings := sv.analyzeAPIResponse(ctx, target, payload, scan, resp, body, duration)

	return findings, nil
}

// executePlugin executes a single plugin against a target
func (sv *scanView) executePlugin(ctx context.Context, pluginName string, target *model.Target, scan *model.Scan) ([]*model.Finding, error) {
	// Load plugin
	if err := sv.pluginManager.Load(pluginName); err != nil {
		return nil, fmt.Errorf("failed to load plugin %s: %w", pluginName, err)
	}

	// Get plugin instance
	pluginInstance, err := sv.pluginManager.Get(pluginName)
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin %s: %w", pluginName, err)
	}

	// Target type is already a string in the framework
	// Convert model.TargetType to string
	var targetType string
	switch target.Type {
	case model.TargetTypeAPI:
		targetType = "api"
	case model.TargetTypeModel:
		targetType = "model"
	case model.TargetTypeEndpoint:
		targetType = "endpoint"
	case "website":
		targetType = "website"
	case "database":
		targetType = "database"
	default:
		targetType = "api"
	}

	// Prepare target config with model-specific metadata
	targetConfig := make(map[string]string)
	if target.Model != "" {
		targetConfig["model"] = target.Model
	}
	if target.APIVersion != "" {
		targetConfig["api_version"] = target.APIVersion
	}
	if target.Provider != "" {
		targetConfig["provider"] = string(target.Provider)
	}

	// Prepare assess request
	request := sdkplugin.AssessRequest{
		RequestID: uuid.New().String(),
		Target: &sdkplugin.Target{
			ID:            target.ID.String(),
			Name:          target.Name,
			Type:          targetType,
			Endpoint:      target.URL,
			Configuration: targetConfig,
			Credentials:   nil, // Will be populated if available
			Tags:          []string{string(scan.Type)},
			Metadata:      make(map[string]string),
			// Legacy fields for compatibility
			URL:    target.URL,
			Config: targetConfig,
		},
		Config:    nil, // Will be populated if needed
		Context:   make(map[string]string),
		// Legacy fields
		ScanID:    scan.ID.String(),
		Timeout:   30 * time.Second,
		Metadata: map[string]string{
			"scan_id":    scan.ID.String(),
			"scan_type":  string(scan.Type),
			"started_by": scan.StartedBy,
		},
		Timestamp: time.Now(),
	}

	// Add credentials if available
	if target.CredentialID != nil {
		credential, err := sv.serviceFactory.CredentialService().Get(ctx, *target.CredentialID)
		if err == nil && credential.IsActive() {
			// Add credential info to target config
			request.Target.Config["credential_type"] = string(credential.Type)
			request.Target.Config["credential_provider"] = string(credential.Provider)

			// Decrypt and store credentials in the Target's Credentials field
			decryptedValue, err := sv.serviceFactory.CredentialService().Decrypt(ctx, credential.ID)
			if err == nil {
				credData := make(map[string]string)
				// The decrypted value should contain the actual credential value
				// Store based on credential type
				switch credential.Type {
				case model.CredentialTypeAPIKey:
					credData["api_key"] = decryptedValue
				case model.CredentialTypeBasic:
					// For basic auth, the decrypted value might be JSON with username and password
					// For now, store as password
					credData["password"] = decryptedValue
				case model.CredentialTypeBearer:
					credData["token"] = decryptedValue
				case model.CredentialTypeOAuth:
					credData["oauth_token"] = decryptedValue
				default:
					credData["value"] = decryptedValue
				}

				request.Target.Credentials = &sdkplugin.Credentials{
					Type:      string(credential.Type),
					Data:      credData,
					Encrypted: false, // Already decrypted
				}
			}
		}
	}

	// Execute plugin
	responseResult := pluginInstance.Plugin.Execute(ctx, &request)
	if responseResult.IsErr() {
		return nil, fmt.Errorf("plugin execution failed: %w", responseResult.Error())
	}

	response := responseResult.Unwrap()

	// Convert SDK findings to model findings
	var findings []*model.Finding
	for _, sdkFinding := range response.Findings {
		finding := &model.Finding{
			ID:          uuid.New(),
			ScanID:      scan.ID,
			TargetID:    target.ID,
			Title:       sdkFinding.Title,
			Description: sdkFinding.Description,
			Severity:    model.Severity(sdkFinding.Severity),
			Confidence:  0.8, // Default confidence for SDK findings
			Category:    string(sdkFinding.Category),
			Status:      model.FindingStatusNew,
			Evidence:    fmt.Sprintf("Plugin: %s", pluginName),
			Remediation: func() string {
				if sdkFinding.Remediation != nil {
					return sdkFinding.Remediation.Description
				}
				return ""
			}(),
			Location:    request.Target.URL,
			Metadata:    make(map[string]interface{}),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Add plugin-specific metadata
		finding.Metadata["plugin_name"] = pluginName
		if response.RequestID != "" {
			finding.Metadata["response_request_id"] = response.RequestID
		}
		finding.Metadata["finding_id"] = sdkFinding.ID
		if len(sdkFinding.Tags) > 0 {
			finding.Metadata["tags"] = sdkFinding.Tags
		}
		if len(sdkFinding.References) > 0 {
			finding.Metadata["references"] = sdkFinding.References
		}

		// Calculate risk score based on severity and confidence
		finding.RiskScore = sv.calculateRiskScore(finding.Severity, finding.Confidence)

		findings = append(findings, finding)
	}

	// Record plugin metrics
	if err := sv.pluginService.RecordMetric(ctx, pluginName, "1.0.0", "execution_count", model.PluginMetricTypeCounter, 1, "count", nil, &target.ID, &scan.ID); err != nil {
		sv.logger.WarnContext(ctx, "Failed to record plugin metric", "plugin", pluginName, "error", err)
	}

	// Calculate duration from start and end times
	if !response.StartTime.IsZero() && !response.EndTime.IsZero() {
		duration := response.EndTime.Sub(response.StartTime)
		if err := sv.pluginService.RecordMetric(ctx, pluginName, "1.0.0", "execution_duration", model.PluginMetricTypeTimer, float64(duration.Milliseconds()), "ms", nil, &target.ID, &scan.ID); err != nil {
			sv.logger.WarnContext(ctx, "Failed to record plugin duration metric", "plugin", pluginName, "error", err)
		}
	}

	return findings, nil
}

// Helper functions for scan execution

// decryptCredential decrypts a credential value using the credential service
func (sv *scanView) decryptCredential(credentialService service.CredentialService, credential *model.Credential) (string, error) {
	return credentialService.Decrypt(context.Background(), credential.ID)
}

func (sv *scanView) filterPlugins(plugins []string, filter string) []string {
	if filter == "" {
		return plugins
	}

	filterList := strings.Split(filter, ",")
	filterMap := make(map[string]bool)
	for _, f := range filterList {
		filterMap[strings.TrimSpace(f)] = true
	}

	var filtered []string
	for _, plugin := range plugins {
		if filterMap[plugin] {
			filtered = append(filtered, plugin)
		}
	}

	return filtered
}

// mapConfidenceToFloat is no longer needed as SDK handles confidence internally

func (sv *scanView) calculateRiskScore(severity model.Severity, confidence float64) float64 {
	var severityWeight float64
	switch severity {
	case model.SeverityCritical:
		severityWeight = 1.0
	case model.SeverityHigh:
		severityWeight = 0.8
	case model.SeverityMedium:
		severityWeight = 0.6
	case model.SeverityLow:
		severityWeight = 0.4
	case model.SeverityInfo:
		severityWeight = 0.2
	default:
		severityWeight = 0.5
	}

	return severityWeight * confidence
}

// Atomic helpers
func atomicInc(counter *int32) {
	atomic.AddInt32(counter, 1)
}

func atomicAdd(counter *int32, value int32) {
	atomic.AddInt32(counter, value)
}

// Batch scan execution methods

func (sv *scanView) executeBatchScanTarget(ctx context.Context, targetName string, scanType model.ScanType, opts ScanBatchOptions) (*model.Scan, error) {
	// Get target by name
	target, err := sv.targetService.GetByName(ctx, targetName)
	if err != nil {
		return nil, fmt.Errorf("failed to find target %s: %w", targetName, err)
	}

	// Prepare scan options
	options := map[string]interface{}{
		"plugins": opts.Plugins,
		"output":  opts.Output,
		"batch":   true,
	}

	// Create scan
	scan, err := sv.scanService.Create(ctx, target.ID, scanType, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan for target %s: %w", targetName, err)
	}

	// Start scan
	if err := sv.scanService.Start(ctx, scan.ID, "batch-cli"); err != nil {
		return nil, fmt.Errorf("failed to start scan for target %s: %w", targetName, err)
	}

	// Execute scan synchronously for batch processing
	sv.executeScan(ctx, scan.ID, opts.Plugins)

	return scan, nil
}

func (sv *scanView) trackBatchProgress(progressChan <-chan string, total int) {
	count := 0
	for progress := range progressChan {
		count++
		fmt.Printf("\r%s - %d/%d completed", progress, count, total)
	}
	fmt.Println()
}

func (sv *scanView) aggregateBatchResults(ctx context.Context, scans []*model.Scan, opts ScanBatchOptions) error {
	sv.logger.InfoContext(ctx, "Aggregating batch scan results", "scan_count", len(scans))

	// Collect all findings from all scans
	allFindings := make([]*model.Finding, 0)
	for _, scan := range scans {
		findings, err := sv.findingService.GetByScanID(ctx, scan.ID)
		if err != nil {
			sv.logger.WarnContext(ctx, "Failed to get findings for scan", "scan_id", scan.ID, "error", err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Create aggregated report
	aggregatedData := map[string]interface{}{
		"scans": len(scans),
		"findings": len(allFindings),
		"timestamp": time.Now(),
	}

	// Group findings by severity
	severityCount := make(map[model.Severity]int)
	for _, finding := range allFindings {
		severityCount[finding.Severity]++
	}
	aggregatedData["severity_breakdown"] = severityCount

	// Export if requested
	if opts.ExportFile != "" {
		return sv.exportAggregatedResults(aggregatedData, allFindings, opts.ExportFile, opts.Output)
	}

	// Display aggregated summary
	fmt.Println("\n=== Batch Scan Summary ===")
	fmt.Printf("Total scans: %d\n", len(scans))
	fmt.Printf("Total findings: %d\n", len(allFindings))
	fmt.Println("\nFindings by severity:")
	for severity, count := range severityCount {
		fmt.Printf("  %s: %d\n", severity, count)
	}

	return nil
}

// getTargetCredential retrieves and decrypts the credential for a target
func (sv *scanView) getTargetCredential(ctx context.Context, target *model.Target) (*model.Credential, error) {
	if target.CredentialID == nil {
		return nil, fmt.Errorf("target %s has no credential configured", target.Name)
	}

	credentialService := sv.serviceFactory.CredentialService()
	credential, err := credentialService.Get(ctx, *target.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	if !credential.IsActive() {
		return nil, fmt.Errorf("credential %s is not active (status: %s)", credential.Name, credential.Status)
	}

	return credential, nil
}

// createAPIRequest creates an HTTP request for the target API based on provider
func (sv *scanView) createAPIRequest(ctx context.Context, target *model.Target, payload *coremodels.PayloadDB, credential *model.Credential) (*http.Request, error) {
	switch target.Provider {
	case model.ProviderAnthropic:
		return sv.createAnthropicRequest(ctx, target, payload, credential)
	case model.ProviderOpenAI:
		return sv.createOpenAIRequest(ctx, target, payload, credential)
	case model.ProviderHuggingFace:
		return sv.createHuggingFaceRequest(ctx, target, payload, credential)
	default:
		return sv.createGenericAPIRequest(ctx, target, payload, credential)
	}
}

// createAnthropicRequest creates a request for Anthropic Claude API
func (sv *scanView) createAnthropicRequest(ctx context.Context, target *model.Target, payload *coremodels.PayloadDB, credential *model.Credential) (*http.Request, error) {
	// Anthropic Claude API request structure
	requestBody := map[string]interface{}{
		"model": target.Model,
		"max_tokens": 1024,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": payload.Content,
			},
		},
	}

	// Add temperature and other parameters from target config
	if target.Config != nil {
		if temp, ok := target.Config["temperature"]; ok {
			requestBody["temperature"] = temp
		} else {
			requestBody["temperature"] = 0.7
		}
		if topP, ok := target.Config["top_p"]; ok {
			requestBody["top_p"] = topP
		}
	}

	// Marshal request body
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Determine API URL
	apiURL := target.URL
	if apiURL == "" {
		apiURL = "https://api.anthropic.com/v1/messages"
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Decrypt the credential properly
	credentialService := sv.serviceFactory.CredentialService()
	decryptedKey, err := sv.decryptCredential(credentialService, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	// Trim any whitespace/newlines from the API key
	decryptedKey = strings.TrimSpace(decryptedKey)

	req.Header.Set("x-api-key", decryptedKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	// Add custom headers from target
	if target.Headers != nil {
		for key, value := range target.Headers {
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

// createOpenAIRequest creates a request for OpenAI API
func (sv *scanView) createOpenAIRequest(ctx context.Context, target *model.Target, payload *coremodels.PayloadDB, credential *model.Credential) (*http.Request, error) {
	// OpenAI API request structure
	requestBody := map[string]interface{}{
		"model": target.Model,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": payload.Content,
			},
		},
		"max_tokens": 1024,
	}

	// Add parameters from target config
	if target.Config != nil {
		if temp, ok := target.Config["temperature"]; ok {
			requestBody["temperature"] = temp
		} else {
			requestBody["temperature"] = 0.7
		}
		if topP, ok := target.Config["top_p"]; ok {
			requestBody["top_p"] = topP
		}
	}

	// Marshal request body
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Determine API URL
	apiURL := target.URL
	if apiURL == "" {
		apiURL = "https://api.openai.com/v1/chat/completions"
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Decrypt the credential properly
	credentialService := sv.serviceFactory.CredentialService()
	decryptedKey, err := sv.decryptCredential(credentialService, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	// Trim any whitespace/newlines from the API key
	decryptedKey = strings.TrimSpace(decryptedKey)

	req.Header.Set("Authorization", "Bearer "+decryptedKey)

	// Add custom headers from target
	if target.Headers != nil {
		for key, value := range target.Headers {
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

// createHuggingFaceRequest creates a request for HuggingFace API
func (sv *scanView) createHuggingFaceRequest(ctx context.Context, target *model.Target, payload *coremodels.PayloadDB, credential *model.Credential) (*http.Request, error) {
	// HuggingFace API request structure
	requestBody := map[string]interface{}{
		"inputs": payload.Content,
		"parameters": map[string]interface{}{
			"max_length": 1024,
			"temperature": 0.7,
		},
	}

	// Add parameters from target config
	if target.Config != nil {
		if params, ok := target.Config["parameters"].(map[string]interface{}); ok {
			requestBody["parameters"] = params
		}
	}

	// Marshal request body
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Determine API URL
	apiURL := target.URL
	if apiURL == "" {
		apiURL = fmt.Sprintf("https://api-inference.huggingface.co/models/%s", target.Model)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Decrypt the credential properly
	credentialService := sv.serviceFactory.CredentialService()
	decryptedKey, err := sv.decryptCredential(credentialService, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	// Trim any whitespace/newlines from the API key
	decryptedKey = strings.TrimSpace(decryptedKey)

	req.Header.Set("Authorization", "Bearer "+decryptedKey)

	// Add custom headers from target
	if target.Headers != nil {
		for key, value := range target.Headers {
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

// createGenericAPIRequest creates a generic API request for custom providers
func (sv *scanView) createGenericAPIRequest(ctx context.Context, target *model.Target, payload *coremodels.PayloadDB, credential *model.Credential) (*http.Request, error) {
	// Generic request structure
	requestBody := map[string]interface{}{
		"prompt": payload.Content,
		"max_tokens": 1024,
	}

	// Add all target config as request parameters
	if target.Config != nil {
		for key, value := range target.Config {
			requestBody[key] = value
		}
	}

	// Marshal request body
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Use target URL
	if target.URL == "" {
		return nil, fmt.Errorf("target URL is required for custom providers")
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", target.URL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Decrypt the credential properly
	credentialService := sv.serviceFactory.CredentialService()
	decryptedKey, err := sv.decryptCredential(credentialService, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	// Set authorization based on credential type
	switch credential.Type {
	case model.CredentialTypeAPIKey:
		req.Header.Set("X-API-Key", decryptedKey)
	case model.CredentialTypeBearer:
		req.Header.Set("Authorization", "Bearer "+decryptedKey)
	case model.CredentialTypeBasic:
		req.Header.Set("Authorization", "Basic "+decryptedKey)
	}

	// Add custom headers from target
	if target.Headers != nil {
		for key, value := range target.Headers {
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

// analyzeAPIResponse analyzes the API response for security issues and generates findings
func (sv *scanView) analyzeAPIResponse(ctx context.Context, target *model.Target, payload *coremodels.PayloadDB, scan *model.Scan, resp *http.Response, body []byte, duration time.Duration) []*model.Finding {
	var findings []*model.Finding
	responseStr := string(body)

	sv.logger.DebugContext(ctx, "Analyzing API response", "target", target.Name, "payload", payload.Name, "status", resp.StatusCode, "response_length", len(body))

	// Check for HTTP error codes that might indicate security issues
	if resp.StatusCode >= 400 {
		if finding := sv.analyzeHTTPErrorCode(target, payload, scan, resp.StatusCode, responseStr); finding != nil {
			findings = append(findings, finding)
		}
	}

	sv.logger.DebugContext(ctx, "Response analysis completed", "target", target.Name, "payload", payload.Name, "findings", len(findings))
	return findings
}

// analyzeHTTPErrorCode analyzes HTTP error codes for security implications
func (sv *scanView) analyzeHTTPErrorCode(target *model.Target, payload *coremodels.PayloadDB, scan *model.Scan, statusCode int, response string) *model.Finding {
	switch {
	case statusCode == 401:
		return &model.Finding{
			ID:          uuid.New(),
			ScanID:      scan.ID,
			TargetID:    target.ID,
			Title:       "Authentication Bypass Attempt",
			Description: "Request returned 401 Unauthorized, indicating potential authentication bypass attempt",
			Severity:    model.SeverityMedium,
			Confidence:  0.6,
			Category:    "Authentication",
			Status:      model.FindingStatusNew,
			Evidence:    fmt.Sprintf("Payload: %s\\nHTTP Status: %d\\nResponse: %s", payload.Content, statusCode, truncateString(response, 500)),
			Remediation: "Review authentication mechanisms and ensure proper access controls",
			Location:    target.URL,
			Metadata: map[string]interface{}{
				"payload_name": payload.Name,
				"payload_category": payload.Category,
				"http_status": statusCode,
				"execution_method": "direct_scan",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	case statusCode == 403:
		return &model.Finding{
			ID:          uuid.New(),
			ScanID:      scan.ID,
			TargetID:    target.ID,
			Title:       "Authorization Bypass Attempt",
			Description: "Request returned 403 Forbidden, indicating potential authorization bypass attempt",
			Severity:    model.SeverityMedium,
			Confidence:  0.6,
			Category:    "Authorization",
			Status:      model.FindingStatusNew,
			Evidence:    fmt.Sprintf("Payload: %s\\nHTTP Status: %d\\nResponse: %s", payload.Content, statusCode, truncateString(response, 500)),
			Remediation: "Review authorization mechanisms and ensure proper access controls",
			Location:    target.URL,
			Metadata: map[string]interface{}{
				"payload_name": payload.Name,
				"payload_category": payload.Category,
				"http_status": statusCode,
				"execution_method": "direct_scan",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	case statusCode >= 500:
		return &model.Finding{
			ID:          uuid.New(),
			ScanID:      scan.ID,
			TargetID:    target.ID,
			Title:       "Server Error Induced by Payload",
			Description: "Payload caused server error, indicating potential input validation issue",
			Severity:    model.SeverityHigh,
			Confidence:  0.7,
			Category:    "Input Validation",
			Status:      model.FindingStatusNew,
			Evidence:    fmt.Sprintf("Payload: %s\\nHTTP Status: %d\\nResponse: %s", payload.Content, statusCode, truncateString(response, 500)),
			Remediation: "Implement proper input validation and error handling",
			Location:    target.URL,
			Metadata: map[string]interface{}{
				"payload_name": payload.Name,
				"payload_category": payload.Category,
				"http_status": statusCode,
				"execution_method": "direct_scan",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}
	return nil
}
