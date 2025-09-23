// Package view provides plugin output formatting methods
package view

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/gibson-sec/gibson-framework-2/internal/plugin"
)

// Output methods for different formats

// outputPluginsTable outputs plugins in table format
func (pv *pluginView) outputPluginsTable(discovered []string, loaded map[string]*plugin.PluginInstance) error {
	fmt.Println("\nPlugin Status:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-20s %-10s %-15s %-20s %-10s\n", "Name", "Status", "Version", "Last Used", "Use Count")
	fmt.Println(strings.Repeat("-", 80))

	if len(discovered) == 0 {
		fmt.Println("No plugins found.")
		return nil
	}

	for _, name := range discovered {
		if instance, exists := loaded[name]; exists {
			lastUsed := "Never"
			if !instance.LastUsed.IsZero() {
				lastUsed = instance.LastUsed.Format("2006-01-02 15:04")
			}
			fmt.Printf("%-20s %-10s %-15s %-20s %-10d\n",
				name,
				string(instance.Health),
				instance.Config.Version,
				lastUsed,
				instance.UseCount)
		} else {
			fmt.Printf("%-20s %-10s %-15s %-20s %-10s\n",
				name,
				"unloaded",
				"unknown",
				"N/A",
				"0")
		}
	}

	fmt.Printf("\nTotal discovered: %d, Loaded: %d\n", len(discovered), len(loaded))
	return nil
}

// outputPluginsJSON outputs plugins in JSON format
func (pv *pluginView) outputPluginsJSON(discovered []string, loaded map[string]*plugin.PluginInstance) error {
	type PluginInfo struct {
		Name      string    `json:"name"`
		Status    string    `json:"status"`
		Version   string    `json:"version,omitempty"`
		LastUsed  *time.Time `json:"last_used,omitempty"`
		UseCount  int64     `json:"use_count"`
		Health    string    `json:"health,omitempty"`
	}

	type PluginList struct {
		Plugins []PluginInfo `json:"plugins"`
		Total   int          `json:"total"`
		Loaded  int          `json:"loaded"`
	}

	var plugins []PluginInfo
	for _, name := range discovered {
		if instance, exists := loaded[name]; exists {
			plugins = append(plugins, PluginInfo{
				Name:     name,
				Status:   "loaded",
				Version:  instance.Config.Version,
				LastUsed: &instance.LastUsed,
				UseCount: instance.UseCount,
				Health:   string(instance.Health),
			})
		} else {
			plugins = append(plugins, PluginInfo{
				Name:     name,
				Status:   "unloaded",
				UseCount: 0,
			})
		}
	}

	result := PluginList{
		Plugins: plugins,
		Total:   len(discovered),
		Loaded:  len(loaded),
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// outputPluginsYAML outputs plugins in YAML format
func (pv *pluginView) outputPluginsYAML(discovered []string, loaded map[string]*plugin.PluginInstance) error {
	fmt.Println("plugins:")
	for _, name := range discovered {
		if instance, exists := loaded[name]; exists {
			fmt.Printf("  - name: %s\n", name)
			fmt.Printf("    status: loaded\n")
			fmt.Printf("    version: %s\n", instance.Config.Version)
			fmt.Printf("    health: %s\n", instance.Health)
			fmt.Printf("    use_count: %d\n", instance.UseCount)
			if !instance.LastUsed.IsZero() {
				fmt.Printf("    last_used: %s\n", instance.LastUsed.Format(time.RFC3339))
			}
		} else {
			fmt.Printf("  - name: %s\n", name)
			fmt.Printf("    status: unloaded\n")
			fmt.Printf("    use_count: 0\n")
		}
	}
	fmt.Printf("total: %d\n", len(discovered))
	fmt.Printf("loaded: %d\n", len(loaded))
	return nil
}

// outputPluginInfoTable outputs detailed plugin info in table format
func (pv *pluginView) outputPluginInfoTable(name string, instance *plugin.PluginInstance, stats ...[]*model.PluginStats) error {
	fmt.Printf("Plugin Information: %s\n", name)
	fmt.Println(strings.Repeat("=", 50))

	if instance == nil {
		fmt.Println("Status: Not loaded")
		fmt.Println("Path: Available but not loaded")
		return nil
	}

	fmt.Printf("Status: %s\n", instance.Health)
	fmt.Printf("Version: %s\n", instance.Config.Version)
	fmt.Printf("Description: %s\n", instance.Config.Description)
	fmt.Printf("Author: %s\n", instance.Config.Author)
	fmt.Printf("Path: %s\n", instance.Path)
	fmt.Printf("Use Count: %d\n", instance.UseCount)
	if !instance.LastUsed.IsZero() {
		fmt.Printf("Last Used: %s\n", instance.LastUsed.Format(time.RFC3339))
	}

	if len(stats) > 0 && len(stats[0]) > 0 {
		fmt.Println("\nRecent Statistics:")
		fmt.Printf("Total Metrics: %d\n", len(stats[0]))
	}

	return nil
}

// outputPluginInfoJSON outputs detailed plugin info in JSON format
func (pv *pluginView) outputPluginInfoJSON(name string, instance *plugin.PluginInstance, stats ...[]*model.PluginStats) error {
	type PluginDetail struct {
		Name        string                 `json:"name"`
		Status      string                 `json:"status"`
		Version     string                 `json:"version,omitempty"`
		Description string                 `json:"description,omitempty"`
		Author      string                 `json:"author,omitempty"`
		Path        string                 `json:"path,omitempty"`
		UseCount    int64                  `json:"use_count"`
		LastUsed    *time.Time             `json:"last_used,omitempty"`
		Health      string                 `json:"health,omitempty"`
		Config      map[string]interface{} `json:"config,omitempty"`
		StatsCount  int                    `json:"stats_count,omitempty"`
	}

	detail := PluginDetail{
		Name:   name,
		Status: "unloaded",
	}

	if instance != nil {
		detail.Status = "loaded"
		detail.Version = instance.Config.Version
		detail.Description = instance.Config.Description
		detail.Author = instance.Config.Author
		detail.Path = instance.Path
		detail.UseCount = instance.UseCount
		detail.LastUsed = &instance.LastUsed
		detail.Health = string(instance.Health)
		detail.Config = instance.Config.Config
		if len(stats) > 0 {
			detail.StatsCount = len(stats[0])
		}
	}

	data, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// outputPluginInfoYAML outputs detailed plugin info in YAML format
func (pv *pluginView) outputPluginInfoYAML(name string, instance *plugin.PluginInstance, stats ...[]*model.PluginStats) error {
	fmt.Printf("name: %s\n", name)
	if instance == nil {
		fmt.Println("status: unloaded")
		return nil
	}

	fmt.Println("status: loaded")
	fmt.Printf("version: %s\n", instance.Config.Version)
	fmt.Printf("description: %s\n", instance.Config.Description)
	fmt.Printf("author: %s\n", instance.Config.Author)
	fmt.Printf("path: %s\n", instance.Path)
	fmt.Printf("use_count: %d\n", instance.UseCount)
	fmt.Printf("health: %s\n", instance.Health)
	if !instance.LastUsed.IsZero() {
		fmt.Printf("last_used: %s\n", instance.LastUsed.Format(time.RFC3339))
	}
	if len(stats) > 0 {
		fmt.Printf("stats_count: %d\n", len(stats[0]))
	}

	return nil
}

// outputAllPluginStatusTable outputs status of all plugins in table format
func (pv *pluginView) outputAllPluginStatusTable(healthStatus map[string]plugin.HealthStatus, loaded []*plugin.PluginInstance) error {
	fmt.Println("\nPlugin Health Status:")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("%-20s %-12s %-15s %-20s\n", "Plugin", "Health", "Use Count", "Last Used")
	fmt.Println(strings.Repeat("-", 70))

	for _, instance := range loaded {
		health := healthStatus[instance.Name]
		lastUsed := "Never"
		if !instance.LastUsed.IsZero() {
			lastUsed = instance.LastUsed.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-20s %-12s %-15d %-20s\n",
			instance.Name,
			health,
			instance.UseCount,
			lastUsed)
	}

	return nil
}

// outputAllPluginStatusJSON outputs status of all plugins in JSON format
func (pv *pluginView) outputAllPluginStatusJSON(healthStatus map[string]plugin.HealthStatus, loaded []*plugin.PluginInstance) error {
	type StatusInfo struct {
		Name      string    `json:"name"`
		Health    string    `json:"health"`
		UseCount  int64     `json:"use_count"`
		LastUsed  *time.Time `json:"last_used,omitempty"`
	}

	type StatusList struct {
		Plugins []StatusInfo `json:"plugins"`
		Total   int          `json:"total"`
	}

	var plugins []StatusInfo
	for _, instance := range loaded {
		health := healthStatus[instance.Name]
		plugins = append(plugins, StatusInfo{
			Name:     instance.Name,
			Health:   string(health),
			UseCount: instance.UseCount,
			LastUsed: &instance.LastUsed,
		})
	}

	result := StatusList{
		Plugins: plugins,
		Total:   len(plugins),
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// outputAllPluginStatusYAML outputs status of all plugins in YAML format
func (pv *pluginView) outputAllPluginStatusYAML(healthStatus map[string]plugin.HealthStatus, loaded []*plugin.PluginInstance) error {
	fmt.Println("plugins:")
	for _, instance := range loaded {
		health := healthStatus[instance.Name]
		fmt.Printf("  - name: %s\n", instance.Name)
		fmt.Printf("    health: %s\n", health)
		fmt.Printf("    use_count: %d\n", instance.UseCount)
		if !instance.LastUsed.IsZero() {
			fmt.Printf("    last_used: %s\n", instance.LastUsed.Format(time.RFC3339))
		}
	}
	fmt.Printf("total: %d\n", len(loaded))
	return nil
}

// Single plugin status output methods
func (pv *pluginView) outputSinglePluginStatusTable(name string, instance *plugin.PluginInstance, health plugin.HealthStatus) error {
	fmt.Printf("Plugin Status: %s\n", name)
	fmt.Println(strings.Repeat("=", 40))
	fmt.Printf("Health: %s\n", health)
	fmt.Printf("Use Count: %d\n", instance.UseCount)
	if !instance.LastUsed.IsZero() {
		fmt.Printf("Last Used: %s\n", instance.LastUsed.Format(time.RFC3339))
	}
	fmt.Printf("Uptime: %s\n", time.Since(instance.LastUsed).Round(time.Second))
	return nil
}

func (pv *pluginView) outputSinglePluginStatusJSON(name string, instance *plugin.PluginInstance, health plugin.HealthStatus) error {
	type SingleStatus struct {
		Name     string    `json:"name"`
		Health   string    `json:"health"`
		UseCount int64     `json:"use_count"`
		LastUsed *time.Time `json:"last_used,omitempty"`
	}

	status := SingleStatus{
		Name:     name,
		Health:   string(health),
		UseCount: instance.UseCount,
		LastUsed: &instance.LastUsed,
	}

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (pv *pluginView) outputSinglePluginStatusYAML(name string, instance *plugin.PluginInstance, health plugin.HealthStatus) error {
	fmt.Printf("name: %s\n", name)
	fmt.Printf("health: %s\n", health)
	fmt.Printf("use_count: %d\n", instance.UseCount)
	if !instance.LastUsed.IsZero() {
		fmt.Printf("last_used: %s\n", instance.LastUsed.Format(time.RFC3339))
	}
	return nil
}

// Discovery output methods
func (pv *pluginView) outputDiscoveryTable(searchPath string, discovered []string, loaded map[string]*plugin.PluginInstance) error {
	fmt.Printf("Plugin Discovery Results\n")
	fmt.Printf("Search Path: %s\n", searchPath)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%-25s %-15s %-15s\n", "Plugin Name", "Status", "Action")
	fmt.Println(strings.Repeat("-", 60))

	newCount := 0
	updatedCount := 0

	for _, name := range discovered {
		if _, exists := loaded[name]; exists {
			fmt.Printf("%-25s %-15s %-15s\n", name, "Loaded", "Already Available")
			updatedCount++
		} else {
			fmt.Printf("%-25s %-15s %-15s\n", name, "Available", "New")
			newCount++
		}
	}

	fmt.Printf("\nSummary: %d new plugins, %d already available\n", newCount, updatedCount)
	return nil
}

func (pv *pluginView) outputDiscoveryJSON(searchPath string, discovered []string, loaded map[string]*plugin.PluginInstance) error {
	type DiscoveryResult struct {
		SearchPath string   `json:"search_path"`
		Plugins    []string `json:"discovered_plugins"`
		NewCount   int      `json:"new_count"`
		LoadedCount int     `json:"loaded_count"`
		Total      int      `json:"total"`
	}

	newCount := 0
	for _, name := range discovered {
		if _, exists := loaded[name]; !exists {
			newCount++
		}
	}

	result := DiscoveryResult{
		SearchPath:  searchPath,
		Plugins:     discovered,
		NewCount:    newCount,
		LoadedCount: len(discovered) - newCount,
		Total:       len(discovered),
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (pv *pluginView) outputDiscoveryYAML(searchPath string, discovered []string, loaded map[string]*plugin.PluginInstance) error {
	fmt.Printf("search_path: %s\n", searchPath)
	fmt.Println("discovered_plugins:")
	for _, name := range discovered {
		status := "new"
		if _, exists := loaded[name]; exists {
			status = "loaded"
		}
		fmt.Printf("  - name: %s\n", name)
		fmt.Printf("    status: %s\n", status)
	}
	fmt.Printf("total: %d\n", len(discovered))
	return nil
}

// Validation output methods
func (pv *pluginView) outputAllValidationTable(results map[string]*ValidationResult) error {
	fmt.Println("Plugin Validation Results:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-20s %-12s %-12s %-12s %-20s\n", "Plugin", "Interface", "Health", "Loadable", "Status")
	fmt.Println(strings.Repeat("-", 80))

	passedCount := 0
	warningCount := 0
	failedCount := 0

	for name, result := range results {
		interfaceStatus := "FAIL"
		if result.InterfaceValid {
			interfaceStatus = "OK"
		}

		healthStatus := "FAIL"
		if result.HealthCheckPassed {
			healthStatus = "OK"
		}

		loadableStatus := "FAIL"
		if result.Loadable {
			loadableStatus = "OK"
		}

		overallStatus := "PASSED"
		if len(result.Errors) > 0 {
			overallStatus = "FAILED"
			failedCount++
		} else if len(result.Warnings) > 0 {
			overallStatus = "WARNING"
			warningCount++
		} else {
			passedCount++
		}

		fmt.Printf("%-20s %-12s %-12s %-12s %-20s\n",
			name, interfaceStatus, healthStatus, loadableStatus, overallStatus)
	}

	fmt.Printf("\nValidation Summary: %d passed, %d warnings, %d failed\n",
		passedCount, warningCount, failedCount)
	return nil
}

func (pv *pluginView) outputAllValidationJSON(results map[string]*ValidationResult) error {
	type ValidationSummary struct {
		Results map[string]*ValidationResult `json:"results"`
		Summary struct {
			Passed   int `json:"passed"`
			Warnings int `json:"warnings"`
			Failed   int `json:"failed"`
		} `json:"summary"`
	}

	summary := ValidationSummary{Results: results}
	for _, result := range results {
		if len(result.Errors) > 0 {
			summary.Summary.Failed++
		} else if len(result.Warnings) > 0 {
			summary.Summary.Warnings++
		} else {
			summary.Summary.Passed++
		}
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (pv *pluginView) outputAllValidationYAML(results map[string]*ValidationResult) error {
	fmt.Println("results:")
	for name, result := range results {
		fmt.Printf("  %s:\n", name)
		fmt.Printf("    interface_valid: %v\n", result.InterfaceValid)
		fmt.Printf("    health_check_passed: %v\n", result.HealthCheckPassed)
		fmt.Printf("    loadable: %v\n", result.Loadable)
		if len(result.Errors) > 0 {
			fmt.Println("    errors:")
			for _, err := range result.Errors {
				fmt.Printf("      - %s\n", err)
			}
		}
		if len(result.Warnings) > 0 {
			fmt.Println("    warnings:")
			for _, warn := range result.Warnings {
				fmt.Printf("      - %s\n", warn)
			}
		}
	}
	return nil
}

// Single validation output methods
func (pv *pluginView) outputSingleValidationTable(name string, result *ValidationResult) error {
	fmt.Printf("Validation Results for: %s\n", name)
	fmt.Println(strings.Repeat("=", 50))

	if result.InterfaceValid {
		fmt.Println("Interface Validation: ✓ PASSED")
	} else {
		fmt.Println("Interface Validation: ✗ FAILED")
	}

	if result.HealthCheckPassed {
		fmt.Println("Health Check: ✓ PASSED")
	} else {
		fmt.Println("Health Check: ✗ FAILED")
	}

	if result.Loadable {
		fmt.Println("Loadable: ✓ PASSED")
	} else {
		fmt.Println("Loadable: ✗ FAILED")
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range result.Errors {
			fmt.Printf("  - %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, warn := range result.Warnings {
			fmt.Printf("  - %s\n", warn)
		}
	}

	return nil
}

func (pv *pluginView) outputSingleValidationJSON(name string, result *ValidationResult) error {
	type SingleValidation struct {
		Plugin string            `json:"plugin"`
		Result *ValidationResult `json:"result"`
	}

	validation := SingleValidation{
		Plugin: name,
		Result: result,
	}

	data, err := json.MarshalIndent(validation, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (pv *pluginView) outputSingleValidationYAML(name string, result *ValidationResult) error {
	fmt.Printf("plugin: %s\n", name)
	fmt.Printf("interface_valid: %v\n", result.InterfaceValid)
	fmt.Printf("health_check_passed: %v\n", result.HealthCheckPassed)
	fmt.Printf("loadable: %v\n", result.Loadable)
	if len(result.Errors) > 0 {
		fmt.Println("errors:")
		for _, err := range result.Errors {
			fmt.Printf("  - %s\n", err)
		}
	}
	if len(result.Warnings) > 0 {
		fmt.Println("warnings:")
		for _, warn := range result.Warnings {
			fmt.Printf("  - %s\n", warn)
		}
	}
	return nil
}

// Stats output methods
func (pv *pluginView) outputAllStatsTable(pluginStatsMap map[string][]*model.PluginStats) error {
	fmt.Println("Plugin Usage Statistics (Last 24h):")
	fmt.Println(strings.Repeat("-", 90))
	fmt.Printf("%-20s %-12s %-15s %-15s %-15s\n", "Plugin", "Executions", "Success Rate", "Avg Duration", "Findings")
	fmt.Println(strings.Repeat("-", 90))

	totalExecutions := 0
	totalSuccesses := 0

	for pluginName, stats := range pluginStatsMap {
		if len(stats) == 0 {
			continue
		}

		executions := 0
		successes := 0
		totalDuration := 0.0
		findings := 0

		for _, stat := range stats {
			if stat.MetricName == "execution_count" {
				executions = int(stat.Value)
			} else if stat.MetricName == "success_count" {
				successes = int(stat.Value)
			} else if stat.MetricName == "execution_time" {
				totalDuration += stat.Value
			} else if stat.MetricName == "findings_count" {
				findings = int(stat.Value)
			}
		}

		successRate := 0.0
		if executions > 0 {
			successRate = float64(successes) / float64(executions) * 100
		}

		avgDuration := 0.0
		if executions > 0 {
			avgDuration = totalDuration / float64(executions)
		}

		fmt.Printf("%-20s %-12d %-15.1f%% %-15.0fms %-15d\n",
			pluginName, executions, successRate, avgDuration, findings)

		totalExecutions += executions
		totalSuccesses += successes
	}

	overallSuccessRate := 0.0
	if totalExecutions > 0 {
		overallSuccessRate = float64(totalSuccesses) / float64(totalExecutions) * 100
	}

	fmt.Printf("\nTotal Executions: %d | Overall Success Rate: %.1f%%\n",
		totalExecutions, overallSuccessRate)
	return nil
}

func (pv *pluginView) outputAllStatsJSON(pluginStatsMap map[string][]*model.PluginStats) error {
	type StatsResult struct {
		Plugins map[string][]*model.PluginStats `json:"plugins"`
		Summary struct {
			TotalPlugins int `json:"total_plugins"`
			TimeRange    string `json:"time_range"`
		} `json:"summary"`
	}

	result := StatsResult{
		Plugins: pluginStatsMap,
	}
	result.Summary.TotalPlugins = len(pluginStatsMap)
	result.Summary.TimeRange = "Last 24 hours"

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (pv *pluginView) outputAllStatsYAML(pluginStatsMap map[string][]*model.PluginStats) error {
	fmt.Println("plugins:")
	for pluginName, stats := range pluginStatsMap {
		fmt.Printf("  %s:\n", pluginName)
		fmt.Printf("    stats_count: %d\n", len(stats))
		if len(stats) > 0 {
			fmt.Println("    metrics:")
			for _, stat := range stats[:min(5, len(stats))] { // Show first 5 stats
				fmt.Printf("      - metric: %s\n", stat.MetricName)
				fmt.Printf("        value: %f\n", stat.Value)
				fmt.Printf("        timestamp: %s\n", stat.Timestamp.Format(time.RFC3339))
			}
		}
	}
	fmt.Printf("total_plugins: %d\n", len(pluginStatsMap))
	return nil
}

// Single plugin stats output methods
func (pv *pluginView) outputSinglePluginStatsTable(name string, stats []*model.PluginStats, aggStats map[string]float64) error {
	fmt.Printf("Statistics for plugin: %s (Last 24h)\n", name)
	fmt.Println(strings.Repeat("=", 50))

	if len(stats) == 0 {
		fmt.Println("No statistics available for this plugin.")
		return nil
	}

	// Calculate basic stats
	executions := 0
	successes := 0
	findings := 0

	for _, stat := range stats {
		switch stat.MetricName {
		case "execution_count":
			executions += int(stat.Value)
		case "success_count":
			successes += int(stat.Value)
		case "findings_count":
			findings += int(stat.Value)
		}
	}

	successRate := 0.0
	if executions > 0 {
		successRate = float64(successes) / float64(executions) * 100
	}

	fmt.Printf("Execution Count: %d\n", executions)
	fmt.Printf("Success Rate: %.1f%%\n", successRate)
	fmt.Printf("Failure Rate: %.1f%%\n", 100-successRate)
	fmt.Printf("Total Findings: %d\n", findings)

	if avg, ok := aggStats["avg"]; ok {
		fmt.Printf("Average Duration: %.0fms\n", avg)
	}
	if min, ok := aggStats["min"]; ok {
		fmt.Printf("Min Duration: %.0fms\n", min)
	}
	if max, ok := aggStats["max"]; ok {
		fmt.Printf("Max Duration: %.0fms\n", max)
	}

	fmt.Printf("\nTotal Metrics Recorded: %d\n", len(stats))
	return nil
}

func (pv *pluginView) outputSinglePluginStatsJSON(name string, stats []*model.PluginStats, aggStats map[string]float64) error {
	type SinglePluginStats struct {
		Plugin    string                 `json:"plugin"`
		Stats     []*model.PluginStats   `json:"stats"`
		Aggregated map[string]float64    `json:"aggregated"`
		Summary   map[string]interface{} `json:"summary"`
	}

	// Calculate summary
	summary := make(map[string]interface{})
	executions := 0
	successes := 0
	for _, stat := range stats {
		switch stat.MetricName {
		case "execution_count":
			executions += int(stat.Value)
		case "success_count":
			successes += int(stat.Value)
		}
	}

	summary["executions"] = executions
	summary["successes"] = successes
	if executions > 0 {
		summary["success_rate"] = float64(successes) / float64(executions) * 100
	} else {
		summary["success_rate"] = 0.0
	}
	summary["total_metrics"] = len(stats)

	result := SinglePluginStats{
		Plugin:    name,
		Stats:     stats,
		Aggregated: aggStats,
		Summary:   summary,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func (pv *pluginView) outputSinglePluginStatsYAML(name string, stats []*model.PluginStats, aggStats map[string]float64) error {
	fmt.Printf("plugin: %s\n", name)
	fmt.Printf("total_metrics: %d\n", len(stats))
	fmt.Println("aggregated:")
	for key, value := range aggStats {
		fmt.Printf("  %s: %f\n", key, value)
	}
	fmt.Println("recent_stats:")
	for i, stat := range stats {
		if i >= 10 { // Limit to first 10 stats in YAML
			break
		}
		fmt.Printf("  - metric: %s\n", stat.MetricName)
		fmt.Printf("    value: %f\n", stat.Value)
		fmt.Printf("    timestamp: %s\n", stat.Timestamp.Format(time.RFC3339))
	}
	return nil
}
// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
