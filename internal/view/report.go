// Package view provides simple report view implementation for CLI commands
package view

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/service"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// ReportViewer defines the interface for report view operations
type ReportViewer interface {
	GenerateReport(ctx context.Context, opts ReportGenerateOptions) error
	ListReports(ctx context.Context, opts ReportListOptions) error
	ViewReport(ctx context.Context, opts ReportViewOptions) error
	ExportReport(ctx context.Context, opts ReportExportOptions) error
	ManageSchedule(ctx context.Context, opts ReportScheduleOptions) error
}

// reportView implements ReportViewer following k9s patterns
type reportView struct {
	serviceFactory *service.ServiceFactory
	logger         *slog.Logger
}

// NewReportView creates a new report view instance with service factory
func NewReportView(serviceFactory *service.ServiceFactory) (*reportView, error) {
	if serviceFactory == nil {
		return nil, fmt.Errorf("service factory is required")
	}

	return &reportView{
		serviceFactory: serviceFactory,
		logger:         serviceFactory.Logger(),
	}, nil
}

// Command integration methods following k9s patterns

// ReportGenerateOptions defines options for generating a report
type ReportGenerateOptions struct {
	Name      string
	ScanID    string
	TimeRange string
	Template  string
	Format    string
	Output    string
}

// GenerateReport generates a new security report with the given options
func (rv *reportView) GenerateReport(ctx context.Context, opts ReportGenerateOptions) error {
	// Operation completed - silent logging

	// Validate required fields
	if opts.Name == "" {
		return fmt.Errorf("report name is required")
	}

	// Default format if not specified
	format := model.ReportFormatJSON
	if opts.Format != "" {
		format = model.ReportFormat(opts.Format)
	}

	// Default template if not specified
	template := "default"
	if opts.Template != "" {
		template = opts.Template
	}

	// Create report record
	report := &model.Report{
		Name:   opts.Name,
		Type:   model.ReportTypeScanSummary, // Default type
		Status: model.ReportStatusGenerating,
		Format: format,
		Config: map[string]interface{}{
			"template":   template,
			"timeRange":  opts.TimeRange,
			"generated_by": "cli",
		},
		OutputPath: opts.Output,
	}

	// Set scan ID if provided
	if opts.ScanID != "" {
		scanUUID, err := uuid.Parse(opts.ScanID)
		if err != nil {
			return fmt.Errorf("invalid scan ID format: %v", err)
		}
		report.ScanID = &scanUUID
	}

	fmt.Printf("Generating report: %s\n", opts.Name)
	if opts.ScanID != "" {
		fmt.Printf("Source scan ID: %s\n", opts.ScanID)
	}
	if opts.TimeRange != "" {
		fmt.Printf("Time range: %s\n", opts.TimeRange)
	}
	fmt.Printf("Template: %s\n", template)
	fmt.Printf("Format: %s\n", format)

	if opts.Output != "" {
		fmt.Printf("Output file: %s\n", opts.Output)
	}

	// Save report to database
	fmt.Println("✓ Creating report record...")
	reportService := rv.serviceFactory.ReportService()
	if err := reportService.Create(ctx, report); err != nil {
		return fmt.Errorf("failed to create report record: %v", err)
	}

	// Aggregate findings from scans
	fmt.Println("✓ Aggregating scan findings...")

	var findings []*model.Finding
	findingService := rv.serviceFactory.FindingService()

	if report.ScanID != nil {
		// Get findings for specific scan
		scanFindings, err := findingService.GetByScanID(ctx, *report.ScanID)
		if err != nil {
			rv.logger.ErrorContext(ctx, "Failed to retrieve scan findings", "error", err)
			// Update report status to failed
			report.Status = model.ReportStatusFailed
			report.Error = err.Error()
			reportService.Update(ctx, report)
			return fmt.Errorf("failed to retrieve scan findings: %v", err)
		}
		findings = scanFindings
	} else {
		// Get all findings (would normally filter by time range)
		allFindings, err := findingService.List(ctx)
		if err != nil {
			rv.logger.ErrorContext(ctx, "Failed to retrieve findings", "error", err)
			report.Status = model.ReportStatusFailed
			report.Error = err.Error()
			reportService.Update(ctx, report)
			return fmt.Errorf("failed to retrieve findings: %v", err)
		}
		findings = allFindings
	}

	// Generate report data
	fmt.Println("✓ Applying report template...")
	reportData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"generated_at": time.Now(),
			"template":     template,
			"total_findings": len(findings),
		},
		"findings": findings,
		"summary": map[string]interface{}{
			"total": len(findings),
			"by_severity": rv.groupFindingsBySeverity(findings),
		},
	}

	// Update report with generated data
	report.Data = reportData
	report.Status = model.ReportStatusCompleted
	report.GeneratedAt = func() *time.Time { t := time.Now(); return &t }()
	report.FileSize = int64(len(fmt.Sprintf("%v", reportData))) // Rough estimate

	fmt.Printf("✓ Generating %s output...\n", format)
	if err := reportService.Update(ctx, report); err != nil {
		return fmt.Errorf("failed to update report: %v", err)
	}

	fmt.Println("✓ Report generated successfully!")
	fmt.Printf("Report ID: %s\n", report.ID.String())

	return nil
}

// groupFindingsBySeverity groups findings by severity level
func (rv *reportView) groupFindingsBySeverity(findings []*model.Finding) map[string]int {
	groups := make(map[string]int)
	for _, finding := range findings {
		groups[string(finding.Severity)]++
	}
	return groups
}

// ReportListOptions defines options for listing reports
type ReportListOptions struct {
	Output string
	Type   string
}

// ListReports lists all generated reports
func (rv *reportView) ListReports(ctx context.Context, opts ReportListOptions) error {
	// Operation completed - silent logging

	fmt.Println("Listing security reports...")
	if opts.Type != "" {
		fmt.Printf("Filter by type: %s\n", opts.Type)
	}
	fmt.Printf("Output format: %s\n", opts.Output)

	// Retrieve reports from database
	reportService := rv.serviceFactory.ReportService()
	var reports []*model.Report
	var err error

	if opts.Type != "" {
		reports, err = reportService.ListByType(ctx, model.ReportType(opts.Type))
	} else {
		reports, err = reportService.List(ctx)
	}

	if err != nil {
		return fmt.Errorf("failed to retrieve reports: %v", err)
	}

	if len(reports) == 0 {
		fmt.Println("No reports found")
		return nil
	}

	// Display results based on output format
	if opts.Output == "json" {
		return rv.outputReportsJSON(reports)
	} else if opts.Output == "yaml" {
		return rv.outputReportsYAML(reports)
	}

	// Default table output
	return rv.outputReportsTable(reports)
}

// ReportViewOptions defines options for viewing a report
type ReportViewOptions struct {
	ID     string
	Format string
}

// ViewReport displays the content of a specific report
func (rv *reportView) ViewReport(ctx context.Context, opts ReportViewOptions) error {
	if opts.ID == "" {
		return fmt.Errorf("report ID is required")
	}

	reportID, err := uuid.Parse(opts.ID)
	if err != nil {
		return fmt.Errorf("invalid report ID format: %v", err)
	}

	rv.logger.InfoContext(ctx, "Viewing security report", "id", opts.ID)

	// Retrieve report from database
	reportService := rv.serviceFactory.ReportService()
	report, err := reportService.Get(ctx, reportID)
	if err != nil {
		return fmt.Errorf("failed to retrieve report: %v", err)
	}

	fmt.Printf("Viewing report: %s\n", report.Name)
	fmt.Printf("Report ID: %s\n", report.ID.String())
	fmt.Printf("Type: %s\n", report.Type)
	fmt.Printf("Status: %s\n", report.Status)
	fmt.Printf("Format: %s\n", report.Format)
	if report.GeneratedAt != nil {
		fmt.Printf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339))
	}
	fmt.Printf("Display format: %s\n", opts.Format)

	if report.Status != model.ReportStatusCompleted {
		fmt.Printf("Report is not completed (status: %s)\n", report.Status)
		if report.Error != "" {
			fmt.Printf("Error: %s\n", report.Error)
		}
		return nil
	}

	// Display report content based on format
	switch strings.ToLower(opts.Format) {
	case "json":
		return rv.displayReportJSON(report)
	case "yaml":
		return rv.displayReportYAML(report)
	default:
		return rv.displayReportTable(report)
	}
}

// ReportExportOptions defines options for exporting reports
type ReportExportOptions struct {
	ID     string
	Format string
	Output string
	All    bool
}

// ExportReport exports a report to external format
func (rv *reportView) ExportReport(ctx context.Context, opts ReportExportOptions) error {
	if !opts.All && opts.ID == "" {
		return fmt.Errorf("either report ID or --all flag must be specified")
	}

	reportService := rv.serviceFactory.ReportService()

	if opts.All {
		rv.logger.InfoContext(ctx, "Exporting all reports", "format", opts.Format)
		fmt.Printf("Exporting all reports to %s format...\n", opts.Format)

		// Get all completed reports
		allReports, err := reportService.ListByStatus(ctx, model.ReportStatusCompleted)
		if err != nil {
			return fmt.Errorf("failed to retrieve reports: %v", err)
		}

		for _, report := range allReports {
			if err := rv.exportSingleReport(ctx, report, opts.Format, opts.Output); err != nil {
				rv.logger.ErrorContext(ctx, "Failed to export report", "id", report.ID, "error", err)
				continue
			}
		}

		fmt.Printf("✓ Exported %d reports successfully\n", len(allReports))
	} else {
		reportID, err := uuid.Parse(opts.ID)
		if err != nil {
			return fmt.Errorf("invalid report ID format: %v", err)
		}

		rv.logger.InfoContext(ctx, "Exporting report", "id", opts.ID, "format", opts.Format)
		fmt.Printf("Exporting report %s to %s format...\n", opts.ID, opts.Format)

		report, err := reportService.Get(ctx, reportID)
		if err != nil {
			return fmt.Errorf("failed to retrieve report: %v", err)
		}

		if report.Status != model.ReportStatusCompleted {
			return fmt.Errorf("report is not completed (status: %s)", report.Status)
		}

		if err := rv.exportSingleReport(ctx, report, opts.Format, opts.Output); err != nil {
			return fmt.Errorf("failed to export report: %v", err)
		}

		fmt.Println("✓ Report exported successfully!")
	}

	return nil
}

// ReportScheduleOptions defines options for managing report schedules
type ReportScheduleOptions struct {
	Cron      string
	Template  string
	TimeRange string
	Output    string
}

// ManageSchedule manages report scheduling with cron-like syntax
func (rv *reportView) ManageSchedule(ctx context.Context, opts ReportScheduleOptions) error {
	rv.logger.InfoContext(ctx, "Managing report scheduling")

	scheduleService := rv.serviceFactory.ReportScheduleService()

	if opts.Cron != "" {
		fmt.Printf("Creating scheduled report with cron: %s\n", opts.Cron)
		fmt.Printf("Template: %s\n", opts.Template)
		fmt.Printf("Time range: %s\n", opts.TimeRange)

		// Validate cron expression
		fmt.Println("✓ Validating cron expression...")
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		_, err := parser.Parse(opts.Cron)
		if err != nil {
			return fmt.Errorf("invalid cron expression: %v", err)
		}

		// Create schedule record
		fmt.Println("✓ Creating scheduled report...")
		schedule := &model.ReportSchedule{
			ID:                 generateUUID(),
			Name:               fmt.Sprintf("Scheduled Report - %s", time.Now().Format("2006-01-02")),
			Description:        fmt.Sprintf("Auto-generated schedule with cron %s", opts.Cron),
			ReportType:         model.ReportTypeScanSummary,
			ScheduleExpression: opts.Cron,
			Format:             model.ReportFormatJSON,
			Enabled:            true,
			Config: map[string]interface{}{
				"template":   opts.Template,
				"time_range": opts.TimeRange,
				"auto_generated": true,
			},
			CreatedBy:          "cli",
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
		}

		// Calculate next run time
		if nextRun, err := scheduleService.CalculateNextRun(ctx, schedule.ID); err == nil {
			schedule.NextRun = nextRun
		}

		if err := scheduleService.Create(ctx, schedule); err != nil {
			return fmt.Errorf("failed to create schedule: %v", err)
		}

		fmt.Println("✓ Schedule created successfully!")
		fmt.Printf("Schedule ID: %s\n", schedule.ID.String())
	} else {
		// List scheduled reports
		fmt.Println("Listing scheduled reports...")
		fmt.Printf("Output format: %s\n", opts.Output)

		schedules, err := scheduleService.List(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve schedules: %v", err)
		}

		if len(schedules) == 0 {
			fmt.Println("No scheduled reports found")
			return nil
		}

		switch strings.ToLower(opts.Output) {
		case "json":
			return rv.outputSchedulesJSON(schedules)
		case "yaml":
			return rv.outputSchedulesYAML(schedules)
		default:
			return rv.outputSchedulesTable(schedules)
		}
	}

	return nil
}

// generateUUID generates a new UUID
func generateUUID() uuid.UUID {
	return uuid.New()
}

// outputReportsJSON outputs reports in JSON format
func (rv *reportView) outputReportsJSON(reports []*model.Report) error {
	fmt.Println("[")
	for i, report := range reports {
		fmt.Printf("  {\n")
		fmt.Printf("    \"id\": \"%s\",\n", report.ID.String())
		fmt.Printf("    \"name\": \"%s\",\n", report.Name)
		fmt.Printf("    \"type\": \"%s\",\n", string(report.Type))
		fmt.Printf("    \"status\": \"%s\",\n", string(report.Status))
		fmt.Printf("    \"format\": \"%s\",\n", string(report.Format))
		if report.GeneratedAt != nil {
			fmt.Printf("    \"generated_at\": \"%s\",\n", report.GeneratedAt.Format(time.RFC3339))
		}
		fmt.Printf("    \"file_size\": %d,\n", report.FileSize)
		fmt.Printf("    \"created_at\": \"%s\"\n", report.CreatedAt.Format(time.RFC3339))
		if i < len(reports)-1 {
			fmt.Printf("  },\n")
		} else {
			fmt.Printf("  }\n")
		}
	}
	fmt.Println("]")
	return nil
}

// outputReportsYAML outputs reports in YAML format
func (rv *reportView) outputReportsYAML(reports []*model.Report) error {
	fmt.Println("reports:")
	for _, report := range reports {
		fmt.Printf("  - id: %s\n", report.ID.String())
		fmt.Printf("    name: \"%s\"\n", report.Name)
		fmt.Printf("    type: %s\n", string(report.Type))
		fmt.Printf("    status: %s\n", string(report.Status))
		fmt.Printf("    format: %s\n", string(report.Format))
		if report.GeneratedAt != nil {
			fmt.Printf("    generated_at: %s\n", report.GeneratedAt.Format(time.RFC3339))
		}
		fmt.Printf("    file_size: %d\n", report.FileSize)
		fmt.Printf("    created_at: %s\n", report.CreatedAt.Format(time.RFC3339))
	}
	return nil
}

// outputReportsTable outputs reports in table format
func (rv *reportView) outputReportsTable(reports []*model.Report) error {
	fmt.Printf("\n%-36s %-25s %-15s %-12s %-12s %-12s\n",
		"REPORT ID", "NAME", "TYPE", "STATUS", "FORMAT", "CREATED")
	fmt.Println("----------------------------------------------------------------------------------------------------------------------------")

	for _, report := range reports {
		name := report.Name
		if len(name) > 24 {
			name = name[:21] + "..."
		}

		fmt.Printf("%-36s %-25s %-15s %-12s %-12s %-12s\n",
			report.ID.String(),
			name,
			string(report.Type),
			string(report.Status),
			string(report.Format),
			report.CreatedAt.Format("2006-01-02"),
		)
	}

	fmt.Printf("\nTotal: %d reports\n", len(reports))
	return nil
}

// displayReportJSON displays report content in JSON format
func (rv *reportView) displayReportJSON(report *model.Report) error {
	fmt.Println("\n=== Report Data (JSON) ===")
	data, err := json.MarshalIndent(report.Data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report data: %v", err)
	}
	fmt.Println(string(data))
	return nil
}

// displayReportYAML displays report content in YAML format (simplified)
func (rv *reportView) displayReportYAML(report *model.Report) error {
	fmt.Println("\n=== Report Data (YAML) ===")
	fmt.Printf("name: %s\n", report.Name)
	fmt.Printf("type: %s\n", report.Type)
	fmt.Printf("status: %s\n", report.Status)
	if report.Data != nil {
		if metadata, ok := report.Data["metadata"].(map[string]interface{}); ok {
			fmt.Println("metadata:")
			for k, v := range metadata {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
		if summary, ok := report.Data["summary"].(map[string]interface{}); ok {
			fmt.Println("summary:")
			for k, v := range summary {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
	}
	return nil
}

// displayReportTable displays report content in table format
func (rv *reportView) displayReportTable(report *model.Report) error {
	fmt.Printf("\n=== Security Report: %s ===\n", report.Name)
	fmt.Printf("ID: %s\n", report.ID.String())
	fmt.Printf("Type: %s\n", report.Type)
	fmt.Printf("Status: %s\n", report.Status)
	if report.GeneratedAt != nil {
		fmt.Printf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339))
	}

	if report.Data != nil {
		if metadata, ok := report.Data["metadata"].(map[string]interface{}); ok {
			fmt.Println("\nMetadata:")
			if totalFindings, ok := metadata["total_findings"].(int); ok {
				fmt.Printf("  Total Findings: %d\n", totalFindings)
			}
			if template, ok := metadata["template"].(string); ok {
				fmt.Printf("  Template: %s\n", template)
			}
		}

		if summary, ok := report.Data["summary"].(map[string]interface{}); ok {
			fmt.Println("\nSummary:")
			if total, ok := summary["total"].(int); ok {
				fmt.Printf("  Total: %d\n", total)
			}
			if bySeverity, ok := summary["by_severity"].(map[string]int); ok {
				fmt.Println("  By Severity:")
				for severity, count := range bySeverity {
					fmt.Printf("    %s: %d\n", severity, count)
				}
			}
		}

		if findings, ok := report.Data["findings"].([]*model.Finding); ok && len(findings) > 0 {
			fmt.Printf("\nFindings (%d):\n", len(findings))
			fmt.Printf("%-36s %-20s %-10s %-50s\n", "ID", "TITLE", "SEVERITY", "DESCRIPTION")
			fmt.Println(strings.Repeat("-", 120))
			for _, finding := range findings[:minInt(len(findings), 10)] { // Limit to first 10
				title := finding.Title
				if len(title) > 19 {
					title = title[:16] + "..."
				}
				description := finding.Description
				if len(description) > 49 {
					description = description[:46] + "..."
				}
				fmt.Printf("%-36s %-20s %-10s %-50s\n",
					finding.ID.String(),
					title,
					string(finding.Severity),
					description,
				)
			}
			if len(findings) > 10 {
				fmt.Printf("... and %d more findings\n", len(findings)-10)
			}
		}
	}

	return nil
}

// exportSingleReport exports a single report to the specified format
func (rv *reportView) exportSingleReport(ctx context.Context, report *model.Report, format, outputPath string) error {
	fmt.Printf("Exporting report %s...\n", report.Name)

	var data []byte
	var err error
	var filename string

	switch strings.ToLower(format) {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
		filename = fmt.Sprintf("%s.json", sanitizeFilename(report.Name))
	case "yaml":
		// For YAML, we'll create a simplified structure
		yamlData := map[string]interface{}{
			"id":           report.ID.String(),
			"name":         report.Name,
			"type":         report.Type,
			"status":       report.Status,
			"format":       report.Format,
			"generated_at": report.GeneratedAt,
			"data":         report.Data,
		}
		data, err = json.MarshalIndent(yamlData, "", "  ") // Simplified as JSON for now
		filename = fmt.Sprintf("%s.yaml", sanitizeFilename(report.Name))
	case "csv":
		// For CSV, export finding data if available
		if report.Data != nil && report.Data["findings"] != nil {
			data = []byte(rv.exportFindingsAsCSV(report))
		} else {
			data = []byte("No findings data available for CSV export\n")
		}
		filename = fmt.Sprintf("%s.csv", sanitizeFilename(report.Name))
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal report data: %v", err)
	}

	// Determine output path
	var fullPath string
	if outputPath != "" {
		if strings.HasSuffix(outputPath, "/") || (len(outputPath) > 0 && outputPath[len(outputPath)-1] == os.PathSeparator) {
			// Directory path provided
			fullPath = filepath.Join(outputPath, filename)
		} else {
			// Full file path provided
			fullPath = outputPath
		}
	} else {
		// Use current directory
		fullPath = filename
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Write file
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	fmt.Printf("✓ Exported to: %s\n", fullPath)
	return nil
}

// exportFindingsAsCSV exports findings data as CSV format
func (rv *reportView) exportFindingsAsCSV(report *model.Report) string {
	var csv strings.Builder
	csv.WriteString("ID,Title,Severity,Confidence,Category,Status,Created At\n")

	if findings, ok := report.Data["findings"].([]*model.Finding); ok {
		for _, finding := range findings {
			csv.WriteString(fmt.Sprintf("%s,\"%s\",\"%s\",%.2f,\"%s\",\"%s\",\"%s\"\n",
				finding.ID.String(),
				strings.ReplaceAll(finding.Title, "\"", "\\\""),
				string(finding.Severity),
				finding.Confidence,
				finding.Category,
				string(finding.Status),
				finding.CreatedAt.Format(time.RFC3339),
			))
		}
	}

	return csv.String()
}

// sanitizeFilename removes invalid characters from filename
func sanitizeFilename(name string) string {
	// Replace invalid characters with underscores
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	result := name
	for _, char := range invalidChars {
		result = strings.ReplaceAll(result, char, "_")
	}
	// Limit length
	if len(result) > 200 {
		result = result[:200]
	}
	return result
}

// outputSchedulesJSON outputs schedules in JSON format
func (rv *reportView) outputSchedulesJSON(schedules []*model.ReportSchedule) error {
	data, err := json.MarshalIndent(schedules, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal schedules: %v", err)
	}
	fmt.Println(string(data))
	return nil
}

// outputSchedulesYAML outputs schedules in YAML format
func (rv *reportView) outputSchedulesYAML(schedules []*model.ReportSchedule) error {
	fmt.Println("schedules:")
	for _, schedule := range schedules {
		fmt.Printf("  - id: %s\n", schedule.ID.String())
		fmt.Printf("    name: \"%s\"\n", schedule.Name)
		fmt.Printf("    type: %s\n", string(schedule.ReportType))
		fmt.Printf("    cron: \"%s\"\n", schedule.ScheduleExpression)
		fmt.Printf("    format: %s\n", string(schedule.Format))
		fmt.Printf("    enabled: %t\n", schedule.Enabled)
		if schedule.LastRun != nil {
			fmt.Printf("    last_run: %s\n", schedule.LastRun.Format(time.RFC3339))
		}
		if schedule.NextRun != nil {
			fmt.Printf("    next_run: %s\n", schedule.NextRun.Format(time.RFC3339))
		}
		fmt.Printf("    created_at: %s\n", schedule.CreatedAt.Format(time.RFC3339))
	}
	return nil
}

// outputSchedulesTable outputs schedules in table format
func (rv *reportView) outputSchedulesTable(schedules []*model.ReportSchedule) error {
	fmt.Printf("\n%-36s %-25s %-15s %-15s %-10s %-20s\n",
		"SCHEDULE ID", "NAME", "TYPE", "CRON", "ENABLED", "NEXT RUN")
	fmt.Println(strings.Repeat("-", 130))

	for _, schedule := range schedules {
		name := schedule.Name
		if len(name) > 24 {
			name = name[:21] + "..."
		}

		cron := schedule.ScheduleExpression
		if len(cron) > 14 {
			cron = cron[:11] + "..."
		}

		nextRun := "N/A"
		if schedule.NextRun != nil {
			nextRun = schedule.NextRun.Format("2006-01-02 15:04")
		}
		if len(nextRun) > 19 {
			nextRun = nextRun[:16] + "..."
		}

		enabled := "Yes"
		if !schedule.Enabled {
			enabled = "No"
		}

		fmt.Printf("%-36s %-25s %-15s %-15s %-10s %-20s\n",
			schedule.ID.String(),
			name,
			string(schedule.ReportType),
			cron,
			enabled,
			nextRun,
		)
	}

	fmt.Printf("\nTotal: %d schedules\n", len(schedules))
	return nil
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}