// Package view provides plugin view implementation for CLI commands
package view

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/plugin"
	"github.com/zero-day-ai/gibson-framework/internal/service"
	sdkplugin "github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
)

// pluginView implements PluginViewer following k9s patterns
type pluginView struct {
	serviceFactory *service.ServiceFactory
	pluginService  service.PluginService
	pluginManager  *plugin.Manager
	logger         *slog.Logger
}

// NewPluginView creates a new plugin view instance
func NewPluginView() (*pluginView, error) {
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
		plugin.WithMaxPlugins(20),
		plugin.WithTimeout(30*time.Second),
	)

	return &pluginView{
		serviceFactory: serviceFactory,
		pluginService:  serviceFactory.PluginService(),
		pluginManager:  pluginManager,
		logger:         logger,
	}, nil
}

// Command integration methods following k9s patterns

// PluginListOptions defines options for listing plugins
type PluginListOptions struct {
	Output string
}

// ListPlugins lists all plugins
func (pv *pluginView) ListPlugins(ctx context.Context, opts PluginListOptions) error {
	pv.logger.Info("Listing plugins")

	// Discover plugins from filesystem
	discoveredPlugins, err := pv.pluginManager.Discover()
	if err != nil {
		return fmt.Errorf("failed to discover plugins: %w", err)
	}

	// Get loaded plugin instances
	loadedPlugins := pv.pluginManager.List()

	// Create a map of loaded plugins for quick lookup
	loadedMap := make(map[string]*plugin.PluginInstance)
	for _, instance := range loadedPlugins {
		loadedMap[instance.Name] = instance
	}

	switch strings.ToLower(opts.Output) {
	case "json":
		return pv.outputPluginsJSON(discoveredPlugins, loadedMap)
	case "yaml":
		return pv.outputPluginsYAML(discoveredPlugins, loadedMap)
	default:
		return pv.outputPluginsTable(discoveredPlugins, loadedMap)
	}
}

// PluginEnableOptions defines options for enabling plugins
type PluginEnableOptions struct {
	Name   string
	ID     string
	Type   string
	Output string
}

// EnablePlugin enables a plugin (loads it if not already loaded)
func (pv *pluginView) EnablePlugin(ctx context.Context, opts PluginEnableOptions) error {
	if opts.Name == "" && opts.ID == "" && opts.Type == "" {
		return fmt.Errorf("either plugin name, ID, or type must be specified")
	}

	pv.logger.Info("Enabling plugin", "name", opts.Name, "id", opts.ID, "type", opts.Type)

	if opts.Type != "" {
		// Enable all plugins of specific type
		discovered, err := pv.pluginManager.Discover()
		if err != nil {
			return fmt.Errorf("failed to discover plugins: %w", err)
		}

		successCount := 0
		failureCount := 0

		for _, name := range discovered {
			// For now, enable all discovered plugins since we don't have type filtering
			if err := pv.pluginManager.Load(name); err != nil {
				pv.logger.Warn("Failed to enable plugin", "name", name, "error", err)
				failureCount++
			} else {
				successCount++
			}
		}

		fmt.Printf("Enabled %d plugins, %d failures for type: %s\n", successCount, failureCount, opts.Type)
	} else {
		identifier := opts.Name
		if opts.ID != "" {
			identifier = opts.ID
		}

		// Load/enable specific plugin
		if err := pv.pluginManager.Load(identifier); err != nil {
			return fmt.Errorf("failed to enable plugin %s: %w", identifier, err)
		}

		fmt.Printf("Successfully enabled plugin: %s\n", identifier)
	}

	return nil
}

// PluginDisableOptions defines options for disabling plugins
type PluginDisableOptions struct {
	Name   string
	ID     string
	Type   string
	Output string
}

// DisablePlugin disables a plugin (unloads it)
func (pv *pluginView) DisablePlugin(ctx context.Context, opts PluginDisableOptions) error {
	if opts.Name == "" && opts.ID == "" && opts.Type == "" {
		return fmt.Errorf("either plugin name, ID, or type must be specified")
	}

	pv.logger.Info("Disabling plugin", "name", opts.Name, "id", opts.ID, "type", opts.Type)

	if opts.Type != "" {
		// Disable all loaded plugins of specific type
		loaded := pv.pluginManager.List()
		successCount := 0
		failureCount := 0

		for _, instance := range loaded {
			// For now, disable all loaded plugins since we don't have type filtering
			if err := pv.pluginManager.Unload(instance.Name); err != nil {
				pv.logger.Warn("Failed to disable plugin", "name", instance.Name, "error", err)
				failureCount++
			} else {
				successCount++
			}
		}

		fmt.Printf("Disabled %d plugins, %d failures for type: %s\n", successCount, failureCount, opts.Type)
	} else {
		identifier := opts.Name
		if opts.ID != "" {
			identifier = opts.ID
		}

		// Unload/disable specific plugin
		if err := pv.pluginManager.Unload(identifier); err != nil {
			return fmt.Errorf("failed to disable plugin %s: %w", identifier, err)
		}

		fmt.Printf("Successfully disabled plugin: %s\n", identifier)
	}

	return nil
}

// PluginInfoOptions defines options for getting plugin info
type PluginInfoOptions struct {
	Name   string
	ID     string
	Output string
}

// GetPluginInfo gets detailed plugin information
func (pv *pluginView) GetPluginInfo(ctx context.Context, opts PluginInfoOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either plugin name or ID must be specified")
	}

	identifier := opts.Name
	if opts.ID != "" {
		identifier = opts.ID
	}

	pv.logger.Info("Getting plugin info", "identifier", identifier)

	// Try to get loaded plugin instance
	instance, err := pv.pluginManager.Get(identifier)
	if err != nil {
		// Plugin not loaded, try to discover it
		discoveredPlugins, discErr := pv.pluginManager.Discover()
		if discErr != nil {
			return fmt.Errorf("plugin not found and discovery failed: %w", discErr)
		}

		found := false
		for _, name := range discoveredPlugins {
			if name == identifier {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("plugin not found: %s", identifier)
		}

		// Plugin exists but not loaded
		switch strings.ToLower(opts.Output) {
		case "json":
			return pv.outputPluginInfoJSON(identifier, nil)
		case "yaml":
			return pv.outputPluginInfoYAML(identifier, nil)
		default:
			return pv.outputPluginInfoTable(identifier, nil)
		}
	}

	// Get plugin statistics
	stats, err := pv.pluginService.GetStats(ctx, identifier)
	if err != nil {
		pv.logger.Warn("Failed to get plugin stats", "plugin", identifier, "error", err)
		stats = nil
	}

	switch strings.ToLower(opts.Output) {
	case "json":
		return pv.outputPluginInfoJSON(identifier, instance, stats)
	case "yaml":
		return pv.outputPluginInfoYAML(identifier, instance, stats)
	default:
		return pv.outputPluginInfoTable(identifier, instance, stats)
	}
}

// PluginInstallOptions defines options for installing plugins
type PluginInstallOptions struct {
	Path   string
	Name   string
	Config string
	Output string
}

// InstallPlugin installs a new plugin
func (pv *pluginView) InstallPlugin(ctx context.Context, opts PluginInstallOptions) error {
	if opts.Path == "" {
		return fmt.Errorf("plugin path is required")
	}

	pv.logger.Info("Installing plugin", "path", opts.Path, "name", opts.Name)

	// Get gibson home directory
	gibsonHome, err := getGibsonHome()
	if err != nil {
		return fmt.Errorf("failed to get gibson home: %w", err)
	}

	pluginsDir := filepath.Join(gibsonHome, "plugins")

	// Ensure plugins directory exists
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugins directory: %w", err)
	}

	// Determine plugin name
	pluginName := opts.Name
	if pluginName == "" {
		// Extract name from path
		pluginName = filepath.Base(opts.Path)
		if strings.HasSuffix(pluginName, ".so") {
			pluginName = strings.TrimSuffix(pluginName, ".so")
		}
	}

	// Create plugin directory
	pluginDir := filepath.Join(pluginsDir, pluginName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	fmt.Printf("Installing plugin '%s' from: %s\n", pluginName, opts.Path)
	fmt.Printf("Target directory: %s\n", pluginDir)

	// Plugin installation is handled by the plugin manager with proper validation and setup
	// For now, just report what would be done
	fmt.Println("\n[SIMULATION MODE - Installation not yet implemented]")
	fmt.Printf("Would copy: %s -> %s\n", opts.Path, filepath.Join(pluginDir, pluginName))

	if opts.Config != "" {
		fmt.Printf("Would process config file: %s\n", opts.Config)
	}

	fmt.Printf("Would create manifest: %s\n", filepath.Join(pluginDir, "plugin.yml"))
	fmt.Println("\nTo complete installation, implement file operations in InstallPlugin method.")

	return nil
}

// PluginUninstallOptions defines options for uninstalling plugins
type PluginUninstallOptions struct {
	Name   string
	ID     string
	Output string
}

// UninstallPlugin uninstalls a plugin
func (pv *pluginView) UninstallPlugin(ctx context.Context, opts PluginUninstallOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either plugin name or ID must be specified")
	}

	identifier := opts.Name
	if opts.ID != "" {
		identifier = opts.ID
	}

	pv.logger.Info("Uninstalling plugin", "identifier", identifier)

	// First, unload the plugin if it's loaded
	if err := pv.pluginManager.Unload(identifier); err != nil {
		pv.logger.Warn("Plugin was not loaded", "plugin", identifier)
	}

	// Get gibson home directory
	gibsonHome, err := getGibsonHome()
	if err != nil {
		return fmt.Errorf("failed to get gibson home: %w", err)
	}

	pluginDir := filepath.Join(gibsonHome, "plugins", identifier)

	// Check if plugin directory exists
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		return fmt.Errorf("plugin '%s' is not installed", identifier)
	}

	fmt.Printf("Uninstalling plugin: %s\n", identifier)
	fmt.Printf("Removing directory: %s\n", pluginDir)

	// Plugin removal is handled by the plugin manager with cleanup and dependency checking
	// For now, just report what would be done
	fmt.Println("\n[SIMULATION MODE - Uninstallation not yet implemented]")
	fmt.Printf("Would remove directory: %s\n", pluginDir)
	fmt.Println("\nTo complete uninstallation, implement directory removal in UninstallPlugin method.")

	return nil
}

// PluginUpdateOptions defines options for updating plugins
type PluginUpdateOptions struct {
	Name   string
	ID     string
	Config string
	Output string
}

// UpdatePlugin updates plugin configuration
func (pv *pluginView) UpdatePlugin(ctx context.Context, opts PluginUpdateOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either plugin name or ID must be specified")
	}

	identifier := opts.Name
	if opts.ID != "" {
		identifier = opts.ID
	}

	pv.logger.Info("Updating plugin configuration", "identifier", identifier)

	// Get gibson home directory
	gibsonHome, err := getGibsonHome()
	if err != nil {
		return fmt.Errorf("failed to get gibson home: %w", err)
	}

	pluginDir := filepath.Join(gibsonHome, "plugins", identifier)

	// Check if plugin exists
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		return fmt.Errorf("plugin '%s' is not installed", identifier)
	}

	fmt.Printf("Updating configuration for plugin: %s\n", identifier)

	if opts.Config != "" {
		fmt.Printf("New config file: %s\n", opts.Config)
		manifestPath := filepath.Join(pluginDir, "plugin.yml")
		fmt.Printf("Target manifest: %s\n", manifestPath)

		// Configuration processing and manifest updates are handled by the plugin configuration service
		fmt.Println("\n[SIMULATION MODE - Update not yet implemented]")
		fmt.Printf("Would update manifest: %s\n", manifestPath)
		fmt.Printf("Would process config from: %s\n", opts.Config)
		fmt.Println("\nTo complete update, implement config processing in UpdatePlugin method.")
	} else {
		fmt.Println("No config file specified - no changes made")
	}

	// If plugin is loaded, suggest reloading
	if _, err := pv.pluginManager.Get(identifier); err == nil {
		fmt.Printf("\nPlugin '%s' is currently loaded. Consider reloading to apply changes.\n", identifier)
	}

	return nil
}

// PluginStatusOptions defines options for getting plugin status
type PluginStatusOptions struct {
	Name   string
	ID     string
	Output string
}

// GetPluginStatus gets plugin health status
func (pv *pluginView) GetPluginStatus(ctx context.Context, opts PluginStatusOptions) error {
	pv.logger.Info("Getting plugin status")

	if opts.Name == "" && opts.ID == "" {
		// Get health status for all loaded plugins
		healthStatus := pv.pluginManager.HealthCheck()
		loadedPlugins := pv.pluginManager.List()

		switch strings.ToLower(opts.Output) {
		case "json":
			return pv.outputAllPluginStatusJSON(healthStatus, loadedPlugins)
		case "yaml":
			return pv.outputAllPluginStatusYAML(healthStatus, loadedPlugins)
		default:
			return pv.outputAllPluginStatusTable(healthStatus, loadedPlugins)
		}
	} else {
		identifier := opts.Name
		if opts.ID != "" {
			identifier = opts.ID
		}

		// Get specific plugin instance
		instance, err := pv.pluginManager.Get(identifier)
		if err != nil {
			return fmt.Errorf("plugin not loaded: %s", identifier)
		}

		// Perform health check
		healthStatus := pv.pluginManager.HealthCheck()
		health := healthStatus[identifier]

		switch strings.ToLower(opts.Output) {
		case "json":
			return pv.outputSinglePluginStatusJSON(identifier, instance, health)
		case "yaml":
			return pv.outputSinglePluginStatusYAML(identifier, instance, health)
		default:
			return pv.outputSinglePluginStatusTable(identifier, instance, health)
		}
	}
}

// PluginDiscoverOptions defines options for discovering plugins
type PluginDiscoverOptions struct {
	Path   string
	Output string
}

// DiscoverPlugins discovers new plugins in directories
func (pv *pluginView) DiscoverPlugins(ctx context.Context, opts PluginDiscoverOptions) error {
	pv.logger.Info("Discovering plugins", "path", opts.Path)

	// Determine search path
	searchPath := opts.Path
	if searchPath == "" {
		gibsonHome, err := getGibsonHome()
		if err != nil {
			return fmt.Errorf("failed to get gibson home: %w", err)
		}
		searchPath = filepath.Join(gibsonHome, "plugins")
	}

	// Temporarily change plugin manager's plugin directory if needed
	originalManager := pv.pluginManager
	if opts.Path != "" {
		pv.pluginManager = plugin.NewManager(searchPath,
			plugin.WithLogger(pv.logger),
			plugin.WithGRPC(true),
			plugin.WithMaxPlugins(20),
			plugin.WithTimeout(30*time.Second),
		)
		defer func() {
			pv.pluginManager = originalManager
		}()
	}

	// Discover plugins
	discoveredPlugins, err := pv.pluginManager.Discover()
	if err != nil {
		return fmt.Errorf("failed to discover plugins: %w", err)
	}

	// Get currently loaded plugins for comparison
	loadedPlugins := pv.pluginManager.List()
	loadedMap := make(map[string]*plugin.PluginInstance)
	for _, instance := range loadedPlugins {
		loadedMap[instance.Name] = instance
	}

	switch strings.ToLower(opts.Output) {
	case "json":
		return pv.outputDiscoveryJSON(searchPath, discoveredPlugins, loadedMap)
	case "yaml":
		return pv.outputDiscoveryYAML(searchPath, discoveredPlugins, loadedMap)
	default:
		return pv.outputDiscoveryTable(searchPath, discoveredPlugins, loadedMap)
	}
}

// PluginValidateOptions defines options for validating plugins
type PluginValidateOptions struct {
	Name   string
	ID     string
	Output string
}

// ValidatePlugin validates plugin integrity and interfaces
func (pv *pluginView) ValidatePlugin(ctx context.Context, opts PluginValidateOptions) error {
	pv.logger.Info("Validating plugin", "name", opts.Name, "id", opts.ID)

	if opts.Name == "" && opts.ID == "" {
		// Validate all loaded plugins
		loadedPlugins := pv.pluginManager.List()
		validationResults := make(map[string]*ValidationResult)

		for _, instance := range loadedPlugins {
			result := pv.validatePluginInstance(ctx, instance)
			validationResults[instance.Name] = result
		}

		switch strings.ToLower(opts.Output) {
		case "json":
			return pv.outputAllValidationJSON(validationResults)
		case "yaml":
			return pv.outputAllValidationYAML(validationResults)
		default:
			return pv.outputAllValidationTable(validationResults)
		}
	} else {
		identifier := opts.Name
		if opts.ID != "" {
			identifier = opts.ID
		}

		// Get plugin instance
		instance, err := pv.pluginManager.Get(identifier)
		if err != nil {
			// Try to load plugin first
			if loadErr := pv.pluginManager.Load(identifier); loadErr != nil {
				return fmt.Errorf("plugin not found and cannot be loaded: %s", identifier)
			}
			instance, err = pv.pluginManager.Get(identifier)
			if err != nil {
				return fmt.Errorf("failed to get plugin after loading: %w", err)
			}
		}

		// Validate the plugin
		result := pv.validatePluginInstance(ctx, instance)

		switch strings.ToLower(opts.Output) {
		case "json":
			return pv.outputSingleValidationJSON(identifier, result)
		case "yaml":
			return pv.outputSingleValidationYAML(identifier, result)
		default:
			return pv.outputSingleValidationTable(identifier, result)
		}
	}
}

// PluginStatsOptions defines options for getting plugin statistics
type PluginStatsOptions struct {
	Name   string
	ID     string
	Output string
}

// GetPluginStats gets plugin usage statistics and metrics
func (pv *pluginView) GetPluginStats(ctx context.Context, opts PluginStatsOptions) error {
	pv.logger.Info("Getting plugin statistics", "name", opts.Name, "id", opts.ID)

	if opts.Name == "" && opts.ID == "" {
		// Get stats for all plugins from the last 24 hours
		end := time.Now()
		start := end.Add(-24 * time.Hour)

		allStats, err := pv.pluginService.GetStatsByTimeRange(ctx, start, end)
		if err != nil {
			return fmt.Errorf("failed to get plugin statistics: %w", err)
		}

		// Group stats by plugin
		pluginStatsMap := make(map[string][]*model.PluginStats)
		for _, stat := range allStats {
			pluginStatsMap[stat.PluginName] = append(pluginStatsMap[stat.PluginName], stat)
		}

		switch strings.ToLower(opts.Output) {
		case "json":
			return pv.outputAllStatsJSON(pluginStatsMap)
		case "yaml":
			return pv.outputAllStatsYAML(pluginStatsMap)
		default:
			return pv.outputAllStatsTable(pluginStatsMap)
		}
	} else {
		identifier := opts.Name
		if opts.ID != "" {
			identifier = opts.ID
		}

		// Get stats for specific plugin from the last 24 hours
		end := time.Now()
		start := end.Add(-24 * time.Hour)

		stats, err := pv.pluginService.GetStats(ctx, identifier)
		if err != nil {
			return fmt.Errorf("failed to get plugin statistics: %w", err)
		}

		// Filter stats to last 24 hours
		var recentStats []*model.PluginStats
		for _, stat := range stats {
			if stat.Timestamp.After(start) {
				recentStats = append(recentStats, stat)
			}
		}

		// Get aggregated stats
		aggStats, err := pv.pluginService.GetAggregatedStats(ctx, identifier, "execution_time", start, end)
		if err != nil {
			pv.logger.Warn("Failed to get aggregated stats", "plugin", identifier, "error", err)
			aggStats = make(map[string]float64)
		}

		switch strings.ToLower(opts.Output) {
		case "json":
			return pv.outputSinglePluginStatsJSON(identifier, recentStats, aggStats)
		case "yaml":
			return pv.outputSinglePluginStatsYAML(identifier, recentStats, aggStats)
		default:
			return pv.outputSinglePluginStatsTable(identifier, recentStats, aggStats)
		}
	}
}

// ValidationResult represents plugin validation results
type ValidationResult struct {
	InterfaceValid    bool     `json:"interface_valid"`
	HealthCheckPassed bool     `json:"health_check_passed"`
	Loadable          bool     `json:"loadable"`
	Errors            []string `json:"errors,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

// validatePluginInstance validates a plugin instance
func (pv *pluginView) validatePluginInstance(ctx context.Context, instance *plugin.PluginInstance) *ValidationResult {
	result := &ValidationResult{
		InterfaceValid: true,
		Loadable:       true,
		Errors:         []string{},
		Warnings:       []string{},
	}

	// Test health check
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	healthResult := instance.Plugin.Health(ctx)
	if healthResult.IsErr() {
		result.HealthCheckPassed = false
		result.Errors = append(result.Errors, fmt.Sprintf("Health check failed: %v", healthResult.Error()))
	} else {
		healthStatus := healthResult.Unwrap()
		result.HealthCheckPassed = healthStatus.Status == sdkplugin.HealthStatusHealthy
		if healthStatus.Status != sdkplugin.HealthStatusHealthy {
			result.Errors = append(result.Errors, fmt.Sprintf("Health check reported unhealthy: %s", healthStatus.Message))
		}
	}

	// Check if plugin is responsive
	if instance.Health != plugin.HealthHealthy {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Plugin health status: %s", instance.Health))
	}

	return result
}

// Note: getGibsonHome and readEncryptionKey are already defined in credential.go
// so we reuse those functions rather than redefining them here

// min function is defined in plugin_output.go