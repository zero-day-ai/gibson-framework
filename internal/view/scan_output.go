// Package view provides output formatting methods for scan view
package view

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"gopkg.in/yaml.v2"
)

// Output formatting methods for scans

func (sv *scanView) outputScansJSON(scans []*model.Scan) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(scans)
}

func (sv *scanView) outputScansYAML(scans []*model.Scan) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer encoder.Close()
	return encoder.Encode(scans)
}

func (sv *scanView) outputScansTable(scans []*model.Scan) error {
	// Simple table output for scans
	fmt.Printf("%-36s %-20s %-12s %-10s %-8s %-20s\n",
		"ID", "TARGET", "TYPE", "STATUS", "PROGRESS", "CREATED")
	fmt.Println(strings.Repeat("-", 110))

	for _, scan := range scans {
		progress := fmt.Sprintf("%.1f%%", scan.Progress)
		created := scan.CreatedAt.Format("2006-01-02 15:04:05")

		fmt.Printf("%-36s %-20s %-12s %-10s %-8s %-20s\n",
			scan.ID.String(),
			scan.Name,
			string(scan.Type),
			string(scan.Status),
			progress,
			created,
		)
	}

	fmt.Printf("\nTotal: %d scans\n", len(scans))
	return nil
}

// Output formatting methods for scan results

func (sv *scanView) outputScanResultsJSON(scan *model.Scan, findings []*model.Finding) error {
	result := map[string]interface{}{
		"scan":     scan,
		"findings": findings,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (sv *scanView) outputScanResultsYAML(scan *model.Scan, findings []*model.Finding) error {
	result := map[string]interface{}{
		"scan":     scan,
		"findings": findings,
	}

	encoder := yaml.NewEncoder(os.Stdout)
	defer encoder.Close()
	return encoder.Encode(result)
}

func (sv *scanView) outputScanResultsTable(scan *model.Scan, findings []*model.Finding, detailed bool) error {
	// Display scan summary
	fmt.Printf("=== Scan Results ===\n")
	fmt.Printf("Scan ID: %s\n", scan.ID)
	fmt.Printf("Target: %s\n", scan.Name)
	fmt.Printf("Type: %s\n", scan.Type)
	fmt.Printf("Status: %s\n", scan.Status)
	fmt.Printf("Progress: %.1f%%\n", scan.Progress)

	if scan.StartedAt != nil {
		fmt.Printf("Started: %s\n", scan.StartedAt.Format("2006-01-02 15:04:05"))
	}
	if scan.CompletedAt != nil {
		fmt.Printf("Completed: %s\n", scan.CompletedAt.Format("2006-01-02 15:04:05"))
		duration := scan.CompletedAt.Sub(*scan.StartedAt)
		fmt.Printf("Duration: %s\n", duration.String())
	}

	if scan.Error != "" {
		fmt.Printf("Error: %s\n", scan.Error)
	}

	fmt.Printf("\n=== Findings ===\n")

	if len(findings) == 0 {
		fmt.Println("No findings detected.")
		return nil
	}

	// Group findings by severity for summary
	severityCount := make(map[model.Severity]int)
	for _, finding := range findings {
		severityCount[finding.Severity]++
	}

	fmt.Printf("Total findings: %d\n", len(findings))
	fmt.Println("\nSeverity breakdown:")
	for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if count, exists := severityCount[severity]; exists && count > 0 {
			fmt.Printf("  %s: %d\n", severity, count)
		}
	}

	if !detailed {
		return nil
	}

	// Detailed findings table
	fmt.Printf("\n%-36s %-10s %-20s %-50s\n", "ID", "SEVERITY", "CATEGORY", "TITLE")
	fmt.Println(strings.Repeat("-", 120))

	for _, finding := range findings {
		title := finding.Title
		if len(title) > 47 {
			title = title[:47] + "..."
		}

		fmt.Printf("%-36s %-10s %-20s %-50s\n",
			finding.ID.String(),
			string(finding.Severity),
			finding.Category,
			title,
		)
	}

	return nil
}

func (sv *scanView) outputScanSummary(scan *model.Scan, findings []*model.Finding) error {
	fmt.Printf("=== Scan Summary ===\n")
	fmt.Printf("Scan: %s (%s)\n", scan.Name, scan.ID)
	fmt.Printf("Status: %s\n", scan.Status)

	if scan.StartedAt != nil && scan.CompletedAt != nil {
		duration := scan.CompletedAt.Sub(*scan.StartedAt)
		fmt.Printf("Duration: %s\n", duration.String())
	}

	// Statistics from scan
	if len(scan.Statistics) > 0 {
		fmt.Printf("\nExecution Statistics:\n")
		if pluginCount, ok := scan.Statistics["plugins_executed"]; ok {
			fmt.Printf("  Plugins executed: %v\n", pluginCount)
		}
		if duration, ok := scan.Statistics["duration"]; ok {
			fmt.Printf("  Execution time: %.2fs\n", duration)
		}
	}

	fmt.Printf("\nFindings Summary:\n")
	fmt.Printf("  Total findings: %d\n", len(findings))

	// Group by severity
	severityCount := make(map[model.Severity]int)
	for _, finding := range findings {
		severityCount[finding.Severity]++
	}

	for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if count, exists := severityCount[severity]; exists && count > 0 {
			fmt.Printf("  %s: %d\n", severity, count)
		}
	}

	return nil
}

// Helper methods for filtering and exporting

func (sv *scanView) filterFindings(findings []*model.Finding, opts ScanResultsOptions) []*model.Finding {
	var filtered []*model.Finding

	for _, finding := range findings {
		// Filter by severity
		if opts.Severity != "" && strings.ToLower(string(finding.Severity)) != strings.ToLower(opts.Severity) {
			continue
		}

		// Filter by category
		if opts.Category != "" && strings.ToLower(finding.Category) != strings.ToLower(opts.Category) {
			continue
		}

		filtered = append(filtered, finding)
	}

	return filtered
}

func (sv *scanView) exportScanResults(scan *model.Scan, findings []*model.Finding, filename, format string) error {
	data := map[string]interface{}{
		"scan":      scan,
		"findings":  findings,
		"exported":  time.Now(),
		"total":     len(findings),
	}

	var content []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		content, err = json.MarshalIndent(data, "", "  ")
	case "yaml":
		content, err = yaml.Marshal(data)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := os.WriteFile(filename, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Scan results exported to: %s\n", filename)
	return nil
}

func (sv *scanView) exportAggregatedResults(data map[string]interface{}, findings []*model.Finding, filename, format string) error {
	exportData := map[string]interface{}{
		"summary":  data,
		"findings": findings,
		"exported": time.Now(),
	}

	var content []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		content, err = json.MarshalIndent(exportData, "", "  ")
	case "yaml":
		content, err = yaml.Marshal(exportData)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := os.WriteFile(filename, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Aggregated results exported to: %s\n", filename)
	return nil
}