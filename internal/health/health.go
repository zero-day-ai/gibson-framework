// Package health provides health checking functionality
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/metrics"
	"github.com/jmoiron/sqlx"
)

// Status represents the health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// Check represents a health check
type Check struct {
	Name        string                 `json:"name"`
	Status      Status                 `json:"status"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Duration    time.Duration          `json:"duration"`
	LastChecked time.Time              `json:"last_checked"`
	Error       string                 `json:"error,omitempty"`
}

// HealthResult represents the overall health result
type HealthResult struct {
	Status      Status             `json:"status"`
	Timestamp   time.Time          `json:"timestamp"`
	Uptime      time.Duration      `json:"uptime"`
	Version     string             `json:"version"`
	Checks      map[string]*Check  `json:"checks"`
	SystemInfo  map[string]interface{} `json:"system_info"`
	Metrics     []metrics.Metric   `json:"metrics,omitempty"`
}

// CheckFunc represents a health check function
type CheckFunc func(ctx context.Context) *Check

// HealthChecker manages health checks
type HealthChecker struct {
	checks    map[string]CheckFunc
	mutex     sync.RWMutex
	startTime time.Time
	version   string
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(version string) *HealthChecker {
	return &HealthChecker{
		checks:    make(map[string]CheckFunc),
		startTime: time.Now(),
		version:   version,
	}
}

// RegisterCheck registers a health check
func (hc *HealthChecker) RegisterCheck(name string, checkFunc CheckFunc) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.checks[name] = checkFunc
}

// RemoveCheck removes a health check
func (hc *HealthChecker) RemoveCheck(name string) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	delete(hc.checks, name)
}

// CheckHealth performs all health checks
func (hc *HealthChecker) CheckHealth(ctx context.Context) *HealthResult {
	hc.mutex.RLock()
	checks := make(map[string]CheckFunc)
	for name, checkFunc := range hc.checks {
		checks[name] = checkFunc
	}
	hc.mutex.RUnlock()

	result := &HealthResult{
		Timestamp:  time.Now(),
		Uptime:     time.Since(hc.startTime),
		Version:    hc.version,
		Checks:     make(map[string]*Check),
		SystemInfo: getSystemInfo(),
		Metrics:    metrics.GetSystemMetrics(),
	}

	overallStatus := StatusHealthy

	// Run checks concurrently
	checkResults := make(chan struct {
		name  string
		check *Check
	}, len(checks))

	for name, checkFunc := range checks {
		go func(name string, checkFunc CheckFunc) {
			start := time.Now()
			check := checkFunc(ctx)
			check.Duration = time.Since(start)
			check.LastChecked = time.Now()
			checkResults <- struct {
				name  string
				check *Check
			}{name, check}
		}(name, checkFunc)
	}

	// Collect results
	for i := 0; i < len(checks); i++ {
		select {
		case checkResult := <-checkResults:
			result.Checks[checkResult.name] = checkResult.check

			// Determine overall status
			switch checkResult.check.Status {
			case StatusUnhealthy:
				overallStatus = StatusUnhealthy
			case StatusDegraded:
				if overallStatus == StatusHealthy {
					overallStatus = StatusDegraded
				}
			}
		case <-time.After(30 * time.Second):
			// Timeout for health checks
			overallStatus = StatusUnhealthy
		}
	}

	result.Status = overallStatus
	return result
}

// Database health check
func DatabaseHealthCheck(db *sqlx.DB) CheckFunc {
	return func(ctx context.Context) *Check {
		check := &Check{
			Name: "database",
		}

		if db == nil {
			check.Status = StatusUnhealthy
			check.Message = "Database connection is nil"
			return check
		}

		// Test connection
		if err := db.PingContext(ctx); err != nil {
			check.Status = StatusUnhealthy
			check.Message = "Database ping failed"
			check.Error = err.Error()
			return check
		}

		// Test a simple query
		var result int
		if err := db.GetContext(ctx, &result, "SELECT 1"); err != nil {
			check.Status = StatusUnhealthy
			check.Message = "Database query failed"
			check.Error = err.Error()
			return check
		}

		// Get database stats
		stats := db.Stats()
		check.Status = StatusHealthy
		check.Message = "Database is healthy"
		check.Details = map[string]interface{}{
			"open_connections":     stats.OpenConnections,
			"in_use":              stats.InUse,
			"idle":                stats.Idle,
			"wait_count":          stats.WaitCount,
			"wait_duration":       stats.WaitDuration.String(),
			"max_idle_closed":     stats.MaxIdleClosed,
			"max_idle_time_closed": stats.MaxIdleTimeClosed,
			"max_lifetime_closed": stats.MaxLifetimeClosed,
		}

		return check
	}
}

// Memory health check
func MemoryHealthCheck(maxMemoryMB uint64) CheckFunc {
	return func(ctx context.Context) *Check {
		check := &Check{
			Name: "memory",
		}

		systemMetrics := metrics.GetSystemMetrics()
		var allocBytes float64

		for _, metric := range systemMetrics {
			if metric.Name == "system_memory_alloc_bytes" {
				allocBytes = metric.Value
				break
			}
		}

		allocMB := allocBytes / (1024 * 1024)
		maxBytes := float64(maxMemoryMB * 1024 * 1024)

		check.Details = map[string]interface{}{
			"allocated_mb":    allocMB,
			"allocated_bytes": allocBytes,
			"max_mb":         maxMemoryMB,
			"usage_percent":  (allocBytes / maxBytes) * 100,
		}

		if allocBytes > maxBytes {
			check.Status = StatusUnhealthy
			check.Message = fmt.Sprintf("Memory usage too high: %.2f MB (max: %d MB)", allocMB, maxMemoryMB)
		} else if allocBytes > maxBytes*0.8 {
			check.Status = StatusDegraded
			check.Message = fmt.Sprintf("Memory usage high: %.2f MB (max: %d MB)", allocMB, maxMemoryMB)
		} else {
			check.Status = StatusHealthy
			check.Message = fmt.Sprintf("Memory usage normal: %.2f MB", allocMB)
		}

		return check
	}
}

// Disk space health check
func DiskSpaceHealthCheck(path string, minFreeGB uint64) CheckFunc {
	return func(ctx context.Context) *Check {
		check := &Check{
			Name: "disk_space",
		}

		// Resolve path - default to Gibson home directory if empty
		checkPath := path
		if checkPath == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				check.Status = StatusUnhealthy
				check.Message = "Failed to get user home directory"
				check.Error = err.Error()
				return check
			}
			checkPath = filepath.Join(homeDir, ".gibson")
		}

		// Create directory if it doesn't exist for proper checking
		if err := os.MkdirAll(checkPath, 0755); err != nil {
			check.Status = StatusUnhealthy
			check.Message = "Failed to access Gibson directory"
			check.Error = err.Error()
			return check
		}

		// Get filesystem statistics using syscall.Statfs
		var stat syscall.Statfs_t
		if err := syscall.Statfs(checkPath, &stat); err != nil {
			check.Status = StatusUnhealthy
			check.Message = "Failed to get filesystem statistics"
			check.Error = err.Error()
			return check
		}

		// Calculate disk usage metrics
		blockSize := uint64(stat.Bsize)
		totalBytes := stat.Blocks * blockSize
		availableBytes := stat.Bavail * blockSize
		usedBytes := totalBytes - availableBytes

		// Calculate percentages
		usedPercent := float64(usedBytes) / float64(totalBytes) * 100
		freePercent := float64(availableBytes) / float64(totalBytes) * 100

		// Format bytes for human-readable messages
		totalFormatted := formatBytes(totalBytes)
		usedFormatted := formatBytes(usedBytes)
		availableFormatted := formatBytes(availableBytes)

		// Set detailed metrics
		check.Details = map[string]interface{}{
			"path":            checkPath,
			"total_bytes":     totalBytes,
			"used_bytes":      usedBytes,
			"available_bytes": availableBytes,
			"used_percent":    usedPercent,
			"free_percent":    freePercent,
			"block_size":      blockSize,
			"min_free_gb":     minFreeGB,
			"total_formatted": totalFormatted,
			"used_formatted":  usedFormatted,
			"free_formatted":  availableFormatted,
		}

		// Determine health status based on usage thresholds
		if usedPercent >= 90.0 {
			check.Status = StatusUnhealthy
			check.Message = fmt.Sprintf("Disk space critically low: %.1f%% used (%s of %s available)",
				usedPercent, availableFormatted, totalFormatted)
		} else if usedPercent >= 80.0 {
			check.Status = StatusDegraded
			check.Message = fmt.Sprintf("Disk space warning: %.1f%% used (%s of %s available)",
				usedPercent, availableFormatted, totalFormatted)
		} else {
			check.Status = StatusHealthy
			check.Message = fmt.Sprintf("Disk space healthy: %.1f%% used (%s of %s available)",
				usedPercent, availableFormatted, totalFormatted)
		}

		// Additional check against minimum free GB requirement
		if minFreeGB > 0 {
			availableGB := availableBytes / (1024 * 1024 * 1024)
			if availableGB < minFreeGB {
				if check.Status == StatusHealthy {
					check.Status = StatusDegraded
				}
				check.Message += fmt.Sprintf(" (below minimum %dGB threshold)", minFreeGB)
			}
		}

		return check
	}
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// HTTP endpoint health check
func HTTPEndpointHealthCheck(name, url string, timeout time.Duration) CheckFunc {
	return func(ctx context.Context) *Check {
		check := &Check{
			Name: name,
		}

		client := &http.Client{
			Timeout: timeout,
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			check.Status = StatusUnhealthy
			check.Message = "Failed to create request"
			check.Error = err.Error()
			return check
		}

		resp, err := client.Do(req)
		if err != nil {
			check.Status = StatusUnhealthy
			check.Message = "Request failed"
			check.Error = err.Error()
			return check
		}
		defer resp.Body.Close()

		check.Details = map[string]interface{}{
			"url":         url,
			"status_code": resp.StatusCode,
			"headers":     resp.Header,
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			check.Status = StatusHealthy
			check.Message = "Endpoint is healthy"
		} else if resp.StatusCode >= 500 {
			check.Status = StatusUnhealthy
			check.Message = "Endpoint returned server error"
		} else {
			check.Status = StatusDegraded
			check.Message = "Endpoint returned non-2xx status"
		}

		return check
	}
}

// Plugin health check
func PluginHealthCheck(name string, healthFunc func(ctx context.Context) error) CheckFunc {
	return func(ctx context.Context) *Check {
		check := &Check{
			Name: name,
		}

		if err := healthFunc(ctx); err != nil {
			check.Status = StatusUnhealthy
			check.Message = "Plugin health check failed"
			check.Error = err.Error()
		} else {
			check.Status = StatusHealthy
			check.Message = "Plugin is healthy"
		}

		return check
	}
}

// Helper function to get system information
func getSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"go_version":      "go1.21", // This would be runtime.Version() in production
		"num_cpu":         "unknown", // This would be runtime.NumCPU() in production
		"arch":           "unknown", // This would be runtime.GOARCH in production
		"os":             "unknown", // This would be runtime.GOOS in production
	}
}

// HTTP handler for health checks
func (hc *HealthChecker) HTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		result := hc.CheckHealth(ctx)

		w.Header().Set("Content-Type", "application/json")

		// Set HTTP status based on health
		switch result.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still 200 but with warnings
		case StatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}

		if err := json.NewEncoder(w).Encode(result); err != nil {
			http.Error(w, "Failed to encode health check result", http.StatusInternalServerError)
		}
	}
}

// Periodic health checker
type PeriodicHealthChecker struct {
	*HealthChecker
	interval time.Duration
	callback func(*HealthResult)
}

func NewPeriodicHealthChecker(version string, interval time.Duration, callback func(*HealthResult)) *PeriodicHealthChecker {
	return &PeriodicHealthChecker{
		HealthChecker: NewHealthChecker(version),
		interval:      interval,
		callback:      callback,
	}
}

func (phc *PeriodicHealthChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(phc.interval)
	defer ticker.Stop()

	// Initial check
	if phc.callback != nil {
		result := phc.CheckHealth(ctx)
		phc.callback(result)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if phc.callback != nil {
				result := phc.CheckHealth(ctx)
				phc.callback(result)
			}
		}
	}
}

// Global health checker
var defaultHealthChecker = NewHealthChecker("dev")

func RegisterCheck(name string, checkFunc CheckFunc) {
	defaultHealthChecker.RegisterCheck(name, checkFunc)
}

func CheckHealth(ctx context.Context) *HealthResult {
	return defaultHealthChecker.CheckHealth(ctx)
}

func HTTPHandler() http.HandlerFunc {
	return defaultHealthChecker.HTTPHandler()
}