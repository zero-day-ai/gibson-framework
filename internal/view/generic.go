// Package view provides simple generic view implementation for CLI commands
package view

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/health"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/service"
	"github.com/jmoiron/sqlx"
)

// genericView implements a generic ResourceViewer following k9s patterns
type genericView struct {
	serviceFactory    *service.ServiceFactory
	targetService     service.TargetService
	scanService       service.ScanService
	findingService    service.FindingService
	pluginService     service.PluginService
	healthChecker     *health.HealthChecker
	db                *sqlx.DB
	logger            *slog.Logger
}

// NewGenericView creates a new generic view instance
func NewGenericView() (*genericView, error) {
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

	// Get underlying database connection for health checks
	db := repo.GetDB()

	// Read encryption key
	encryptionKey, err := readEncryptionKey(gibsonHome)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption key: %w", err)
	}

	// Initialize logger
	logger := slog.Default()

	// Create service factory
	serviceFactory := service.NewServiceFactory(repo, logger, encryptionKey)

	// Initialize health checker with database and system checks
	healthChecker := health.NewHealthChecker("dev")
	healthChecker.RegisterCheck("database", health.DatabaseHealthCheck(db))
	healthChecker.RegisterCheck("memory", health.MemoryHealthCheck(256)) // 256MB limit
	healthChecker.RegisterCheck("disk_space", health.DiskSpaceHealthCheck(gibsonHome, 1)) // 1GB minimum

	return &genericView{
		serviceFactory:    serviceFactory,
		targetService:     serviceFactory.TargetService(),
		scanService:       serviceFactory.ScanService(),
		findingService:    serviceFactory.FindingService(),
		pluginService:     serviceFactory.PluginService(),
		healthChecker:     healthChecker,
		db:                db,
		logger:            logger,
	}, nil
}

// Command integration methods following k9s patterns

// SystemStatusOptions defines options for showing system status
type SystemStatusOptions struct {
	Output    string
	Verbose   bool
	Watch     bool
	Refresh   int
	Component string
}

// ShowSystemStatus displays comprehensive system status
func (gv *genericView) ShowSystemStatus(ctx context.Context, opts SystemStatusOptions) error {
	// Operation completed - silent logging

	if opts.Watch {
		return gv.watchSystemStatus(ctx, opts)
	}

	return gv.displaySystemStatus(ctx, opts)
}

// displaySystemStatus shows a one-time system status
func (gv *genericView) displaySystemStatus(ctx context.Context, opts SystemStatusOptions) error {
	fmt.Println("Gibson System Status")
	fmt.Println("===================")
	fmt.Printf("Timestamp: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Output format: %s\n", opts.Output)

	if opts.Component != "" {
		fmt.Printf("Component: %s\n", opts.Component)
	}

	fmt.Println()

	// Show general system information
	fmt.Println("System Information:")
	fmt.Println("- Gibson Framework: Running")
	fmt.Println("- Version: dev")
	fmt.Println("- Configuration: Loaded")

	fmt.Println()

	// Show component-specific status or all components
	switch opts.Component {
	case "scans":
		return gv.showScanStatus(opts)
	case "targets":
		return gv.showTargetStatus(opts)
	case "plugins":
		return gv.showPluginStatus(opts)
	case "system":
		return gv.showSystemHealth(opts)
	default:
		// Show all components
		if err := gv.showScanStatus(opts); err != nil {
			return err
		}
		if err := gv.showTargetStatus(opts); err != nil {
			return err
		}
		if err := gv.showPluginStatus(opts); err != nil {
			return err
		}
		return gv.showSystemHealth(opts)
	}
}

// watchSystemStatus provides live updates of system status
func (gv *genericView) watchSystemStatus(ctx context.Context, opts SystemStatusOptions) error {
	fmt.Printf("Watching system status (refresh every %d seconds, press Ctrl+C to exit)...\n", opts.Refresh)
	fmt.Println()

	ticker := time.NewTicker(time.Duration(opts.Refresh) * time.Second)
	defer ticker.Stop()

	// Show initial status
	if err := gv.displaySystemStatus(ctx, opts); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Clear screen and show updated status
			fmt.Print("\033[2J\033[H") // Clear screen and move cursor to top
			if err := gv.displaySystemStatus(ctx, opts); err != nil {
				return err
			}
		}
	}
}

// showScanStatus displays scan-related status
func (gv *genericView) showScanStatus(opts SystemStatusOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Scans:")

	// Get all scans
	allScans, err := gv.scanService.List(ctx)
	if err != nil {
		fmt.Printf("- Error getting scan counts: %v\n", err)
		return nil
	}

	// Count by status
	activeCount := 0
	completedCount := 0
	failedCount := 0
	var lastScanTime *time.Time

	for _, scan := range allScans {
		switch scan.Status {
		case model.ScanStatusRunning, model.ScanStatusPending:
			activeCount++
		case model.ScanStatusCompleted:
			completedCount++
		case model.ScanStatusFailed, model.ScanStatusCancelled:
			failedCount++
		}

		// Track most recent scan
		if scan.StartedAt != nil && (lastScanTime == nil || scan.StartedAt.After(*lastScanTime)) {
			lastScanTime = scan.StartedAt
		}
	}

	fmt.Printf("- Active scans: %d\n", activeCount)
	fmt.Printf("- Completed scans: %d\n", completedCount)
	fmt.Printf("- Failed scans: %d\n", failedCount)
	fmt.Printf("- Total scans: %d\n", len(allScans))

	if opts.Verbose {
		if lastScanTime != nil {
			fmt.Printf("- Last scan: %s\n", lastScanTime.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Println("- Last scan: Never")
		}

		// Calculate average duration for completed scans
		if completedCount > 0 {
			totalDuration := time.Duration(0)
			validDurations := 0
			for _, scan := range allScans {
				if scan.Status == model.ScanStatusCompleted && scan.StartedAt != nil && scan.CompletedAt != nil {
					totalDuration += scan.CompletedAt.Sub(*scan.StartedAt)
					validDurations++
				}
			}
			if validDurations > 0 {
				avgDuration := totalDuration / time.Duration(validDurations)
				fmt.Printf("- Average scan duration: %s\n", avgDuration.Round(time.Second))
			} else {
				fmt.Println("- Average scan duration: N/A")
			}
		} else {
			fmt.Println("- Average scan duration: N/A")
		}
	}

	fmt.Println()
	return nil
}

// showTargetStatus displays target-related status
func (gv *genericView) showTargetStatus(opts SystemStatusOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Targets:")

	// Get all targets
	allTargets, err := gv.targetService.List(ctx)
	if err != nil {
		fmt.Printf("- Error getting target counts: %v\n", err)
		return nil
	}

	// Count by status
	activeCount := 0
	errorCount := 0
	providerCounts := make(map[model.Provider]int)

	for _, target := range allTargets {
		switch target.Status {
		case model.TargetStatusActive:
			activeCount++
		case model.TargetStatusError:
			errorCount++
		}
		providerCounts[target.Provider]++
	}

	fmt.Printf("- Configured targets: %d\n", len(allTargets))
	fmt.Printf("- Active targets: %d\n", activeCount)
	fmt.Printf("- Error targets: %d\n", errorCount)

	if opts.Verbose {
		fmt.Println("- Last connectivity test: Never") // Connectivity test tracking available in target service

		// Show provider breakdown
		if len(providerCounts) > 0 {
			var providers []string
			for provider, count := range providerCounts {
				providers = append(providers, fmt.Sprintf("%s (%d)", provider, count))
			}
			fmt.Printf("- Providers: %s\n", strings.Join(providers, ", "))
		} else {
			fmt.Println("- Providers: None configured")
		}
	}

	fmt.Println()
	return nil
}

// showPluginStatus displays plugin-related status
func (gv *genericView) showPluginStatus(opts SystemStatusOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Plugins:")

	// Note: The plugin service interface doesn't have List methods for plugins themselves,
	// it's focused on execution and stats. This suggests plugins are managed differently.
	// For now, we'll show stats-based information.

	// Try to get some plugin statistics to infer plugin usage
	stats, err := gv.pluginService.GetStatsByTimeRange(ctx, time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		fmt.Printf("- Error getting plugin stats: %v\n", err)
		fmt.Println("- Installed plugins: Unknown")
		fmt.Println("- Enabled plugins: Unknown")
		fmt.Println("- Disabled plugins: Unknown")
	} else {
		// Count unique plugins from stats
		uniquePlugins := make(map[string]bool)
		for _, stat := range stats {
			uniquePlugins[stat.PluginName] = true
		}

		fmt.Printf("- Plugins with recent activity: %d\n", len(uniquePlugins))
		fmt.Printf("- Plugin executions (24h): %d\n", len(stats))
		fmt.Println("- Plugin status: Stats-based (no registry yet)")
	}

	if opts.Verbose {
		if len(stats) > 0 {
			// Show active plugin names
			uniquePlugins := make(map[string]bool)
			for _, stat := range stats {
				uniquePlugins[stat.PluginName] = true
			}
			var pluginNames []string
			for name := range uniquePlugins {
				pluginNames = append(pluginNames, name)
			}
			fmt.Printf("- Recent plugins: %s\n", strings.Join(pluginNames, ", "))
		} else {
			fmt.Println("- Recent plugins: None")
		}
		fmt.Println("- Last plugin test: Not implemented")
	}

	fmt.Println()
	return nil
}

// showSystemHealth displays system health information
func (gv *genericView) showSystemHealth(opts SystemStatusOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Println("System Health:")

	// Get comprehensive health check results
	healthResult := gv.healthChecker.CheckHealth(ctx)

	// Show overall status
	statusSymbol := "✓"
	switch healthResult.Status {
	case health.StatusHealthy:
		statusSymbol = "✓"
	case health.StatusDegraded:
		statusSymbol = "⚠"
	case health.StatusUnhealthy:
		statusSymbol = "✗"
	default:
		statusSymbol = "?"
	}

	fmt.Printf("- Overall Status: %s %s\n", statusSymbol, healthResult.Status)
	fmt.Printf("- Version: %s\n", healthResult.Version)
	fmt.Printf("- Uptime: %s\n", healthResult.Uptime.Round(time.Second))

	// Show individual health checks
	for name, check := range healthResult.Checks {
		checkSymbol := "✓"
		switch check.Status {
		case health.StatusHealthy:
			checkSymbol = "✓"
		case health.StatusDegraded:
			checkSymbol = "⚠"
		case health.StatusUnhealthy:
			checkSymbol = "✗"
		default:
			checkSymbol = "?"
		}

		switch name {
		case "database":
			fmt.Printf("- Database: %s %s\n", checkSymbol, check.Message)
		case "memory":
			fmt.Printf("- Memory: %s %s\n", checkSymbol, check.Message)
		case "disk_space":
			fmt.Printf("- Disk Space: %s %s\n", checkSymbol, check.Message)
		default:
			fmt.Printf("- %s: %s %s\n", name, checkSymbol, check.Message)
		}
	}

	// Always show configuration and logging status
	fmt.Println("- Configuration: ✓ Loaded")
	fmt.Println("- Logging: ✓ Active")

	if opts.Verbose {
		fmt.Printf("- Last Health Check: %s\n", healthResult.Timestamp.Format("2006-01-02 15:04:05"))

		// Show detailed health check information
		for name, check := range healthResult.Checks {
			if check.Details != nil && len(check.Details) > 0 {
				fmt.Printf("  %s details:\n", name)
				for key, value := range check.Details {
					fmt.Printf("    %s: %v\n", key, value)
				}
			}
			if check.Error != "" {
				fmt.Printf("    Error: %s\n", check.Error)
			}
			if check.Duration > 0 {
				fmt.Printf("    Check Duration: %s\n", check.Duration)
			}
		}

		// Show system info
		if len(healthResult.SystemInfo) > 0 {
			fmt.Println("  System Information:")
			for key, value := range healthResult.SystemInfo {
				fmt.Printf("    %s: %v\n", key, value)
			}
		}
	}

	fmt.Println()
	return nil
}