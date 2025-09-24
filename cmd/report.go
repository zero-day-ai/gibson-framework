// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/service"
	"github.com/zero-day-ai/gibson-framework/internal/view"
	"github.com/spf13/cobra"
)

var (
	// Generate flags
	reportGenNameFlag       *string
	reportGenScanIDFlag     *string
	reportGenTimeRangeFlag  *string
	reportGenTemplateFlag   *string
	reportGenFormatFlag     *string
	reportGenOutputFlag     *string

	// List flags
	reportListOutputFlag    *string
	reportListTypeFlag      *string

	// View flags
	reportViewIDFlag        *string
	reportViewFormatFlag    *string

	// Export flags
	reportExportIDFlag      *string
	reportExportFormatFlag  *string
	reportExportOutputFlag  *string
	reportExportAllFlag     *bool

	// Schedule flags
	reportScheduleCronFlag     *string
	reportScheduleTemplateFlag *string
	reportScheduleTimeRangeFlag *string
	reportScheduleOutputFlag   *string
)

// reportCmd creates the report command following k9s patterns
func reportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "report",
		Aliases: []string{"r"},
		Short:   "Manage security reports",
		Long:    "Generate, list, view, export, and schedule AI/ML security reports",
	}

	// Add subcommands
	cmd.AddCommand(
		reportGenerateCmd(),
		reportListCmd(),
		reportViewCmd(),
		reportExportCmd(),
		reportScheduleCmd(),
	)

	return cmd
}

// reportGenerateCmd generates a new security report
func reportGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "generate [NAME]",
		Aliases: []string{"gen", "create"},
		Short:   "Generate a new security report",
		Long:    "Generate a new security report from scan findings with customizable templates and formats",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runReportGenerate,
		Example: `  # Generate a report from a specific scan
  gibson report generate my-report --scan-id scan-123

  # Generate a report with custom template
  gibson report generate my-report --template executive-summary

  # Generate a report for a time range
  gibson report generate monthly-report --time-range "last-30-days"

  # Generate a PDF report
  gibson report generate my-report --format pdf --scan-id scan-123`,
	}

	// Add flags following k9s pointer patterns
	reportGenNameFlag = cmd.Flags().StringP("name", "n", "", "Report name (if not provided as argument)")
	reportGenScanIDFlag = cmd.Flags().String("scan-id", "", "Specific scan ID to generate report from")
	reportGenTimeRangeFlag = cmd.Flags().String("time-range", "", "Time range for aggregating findings (e.g., 'last-7-days', 'last-30-days')")
	reportGenTemplateFlag = cmd.Flags().StringP("template", "t", "default", "Report template (default, executive-summary, technical, compliance)")
	reportGenFormatFlag = cmd.Flags().StringP("format", "f", "html", "Output format (html, pdf, json)")
	reportGenOutputFlag = cmd.Flags().StringP("output", "o", "", "Output file path (optional)")

	return cmd
}

// reportListCmd lists existing reports
func reportListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "get"},
		Short:   "List security reports",
		Long:    "List all generated security reports with their status and details",
		RunE:    runReportList,
		Example: `  # List all reports
  gibson report list

  # List reports in JSON format
  gibson report list --output json

  # List only scheduled reports
  gibson report list --type scheduled`,
	}

	reportListOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	reportListTypeFlag = cmd.Flags().String("type", "", "Filter by report type (generated, scheduled)")

	return cmd
}

// reportViewCmd shows detailed report content
func reportViewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "view [REPORT_ID]",
		Aliases: []string{"show", "display"},
		Short:   "View detailed report content",
		Long:    "Display the content of a specific security report",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runReportView,
		Example: `  # View a specific report
  gibson report view report-123

  # View report with specific format
  gibson report view report-123 --format json`,
	}

	reportViewIDFlag = cmd.Flags().String("id", "", "Report ID to view (if not provided as argument)")
	reportViewFormatFlag = cmd.Flags().StringP("format", "f", "html", "Display format (html, json, raw)")

	return cmd
}

// reportExportCmd exports reports to external formats
func reportExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "export [REPORT_ID]",
		Aliases: []string{"save"},
		Short:   "Export report to external format",
		Long:    "Export a security report to various external formats (PDF, HTML, JSON)",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runReportExport,
		Example: `  # Export report to PDF
  gibson report export report-123 --format pdf --output /path/to/report.pdf

  # Export report to HTML
  gibson report export report-123 --format html --output /path/to/report.html

  # Export all reports
  gibson report export --all --format pdf`,
	}

	reportExportIDFlag = cmd.Flags().String("id", "", "Report ID to export (if not provided as argument)")
	reportExportFormatFlag = cmd.Flags().StringP("format", "f", "pdf", "Export format (pdf, html, json)")
	reportExportOutputFlag = cmd.Flags().StringP("output", "o", "", "Output file path")
	reportExportAllFlag = cmd.Flags().BoolP("all", "a", false, "Export all reports")

	return cmd
}

// reportScheduleCmd manages report scheduling
func reportScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "schedule",
		Aliases: []string{"cron", "auto"},
		Short:   "Manage report scheduling",
		Long:    "Schedule automatic report generation with cron-like syntax",
		RunE:    runReportSchedule,
		Example: `  # Schedule daily reports
  gibson report schedule --cron "0 9 * * *" --template executive-summary

  # Schedule weekly reports for specific scan type
  gibson report schedule --cron "0 9 * * 1" --time-range "last-7-days"

  # List scheduled reports
  gibson report schedule --list

  # Remove a scheduled report
  gibson report schedule --remove schedule-123`,
	}

	reportScheduleCronFlag = cmd.Flags().String("cron", "", "Cron expression for scheduling (e.g., '0 9 * * *' for daily at 9am)")
	reportScheduleTemplateFlag = cmd.Flags().StringP("template", "t", "default", "Report template for scheduled reports")
	reportScheduleTimeRangeFlag = cmd.Flags().String("time-range", "last-7-days", "Time range for scheduled reports")
	cmd.Flags().Bool("list", false, "List all scheduled reports")
	cmd.Flags().String("remove", "", "Remove a scheduled report by ID")
	reportScheduleOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format for list (table, json, yaml)")

	return cmd
}

// runReportGenerate implements the report generate command
func runReportGenerate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get report name from positional argument or flag
	name := getValue(reportGenNameFlag)
	if len(args) > 0 {
		name = args[0]
	}

	// Operation completed - silent logging

	// Create report view controller
	reportView, err := createReportView()
	if err != nil {
		return fmt.Errorf("failed to create report view: %v", err)
	}

	// Generate the report through the view layer
	return reportView.GenerateReport(ctx, view.ReportGenerateOptions{
		Name:      name,
		ScanID:    getValue(reportGenScanIDFlag),
		TimeRange: getValue(reportGenTimeRangeFlag),
		Template:  getValue(reportGenTemplateFlag),
		Format:    getValue(reportGenFormatFlag),
		Output:    getValue(reportGenOutputFlag),
	})
}

// runReportList implements the report list command
func runReportList(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create report view controller
	reportView, err := createReportView()
	if err != nil {
		return fmt.Errorf("failed to create report view: %v", err)
	}

	// List reports through the view layer
	return reportView.ListReports(ctx, view.ReportListOptions{
		Output: getValue(reportListOutputFlag),
		Type:   getValue(reportListTypeFlag),
	})
}

// runReportView implements the report view command
func runReportView(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get report ID from positional argument or flag
	reportID := getValue(reportViewIDFlag)
	if len(args) > 0 {
		reportID = args[0]
	}

	// Operation completed - silent logging

	// Create report view controller
	reportView, err := createReportView()
	if err != nil {
		return fmt.Errorf("failed to create report view: %v", err)
	}

	// View report through the view layer
	return reportView.ViewReport(ctx, view.ReportViewOptions{
		ID:     reportID,
		Format: getValue(reportViewFormatFlag),
	})
}

// runReportExport implements the report export command
func runReportExport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get report ID from positional argument or flag
	reportID := getValue(reportExportIDFlag)
	if len(args) > 0 {
		reportID = args[0]
	}

	// Operation completed - silent logging

	// Create report view controller
	reportView, err := createReportView()
	if err != nil {
		return fmt.Errorf("failed to create report view: %v", err)
	}

	// Export report through the view layer
	return reportView.ExportReport(ctx, view.ReportExportOptions{
		ID:     reportID,
		Format: getValue(reportExportFormatFlag),
		Output: getValue(reportExportOutputFlag),
		All:    getBoolValue(reportExportAllFlag),
	})
}

// runReportSchedule implements the report schedule command
func runReportSchedule(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create report view controller
	reportView, err := createReportView()
	if err != nil {
		return fmt.Errorf("failed to create report view: %v", err)
	}

	// Handle schedule management through the view layer
	return reportView.ManageSchedule(ctx, view.ReportScheduleOptions{
		Cron:      getValue(reportScheduleCronFlag),
		Template:  getValue(reportScheduleTemplateFlag),
		TimeRange: getValue(reportScheduleTimeRangeFlag),
		Output:    getValue(reportScheduleOutputFlag),
	})
}

// createReportView creates a report view with the service factory
func createReportView() (view.ReportViewer, error) {
	// Get gibson home directory
	gibsonHome := os.Getenv("GIBSON_HOME")
	if gibsonHome == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %v", err)
		}
		gibsonHome = filepath.Join(homeDir, ".gibson")
	}

	// Initialize database connection
	dbPath := filepath.Join(gibsonHome, "gibson.db")
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", dbPath)
	repo, err := dao.NewSQLiteRepository(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize repository: %v", err)
	}

	// Create logger
	logger := slog.Default()

	// For now, use a simple encryption key (in production this should be more secure)
	encryptionKey := []byte("gibson-secret-key-32-chars-long")

	// Create service factory
	serviceFactory := service.NewServiceFactory(repo, logger, encryptionKey)

	// Create and return report view
	return view.NewReportView(serviceFactory)
}
