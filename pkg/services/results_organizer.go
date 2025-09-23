// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"fmt"
	"sort"
	"strings"
)

// ResultsOrganizer handles organization and sorting of scan results
type ResultsOrganizer struct{}

// SeverityStats holds statistics about findings by severity
type SeverityStats struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// OrganizedResults holds scan results organized by severity
type OrganizedResults struct {
	Critical []ScanFinding   `json:"critical"`
	High     []ScanFinding   `json:"high"`
	Medium   []ScanFinding   `json:"medium"`
	Low      []ScanFinding   `json:"low"`
	Stats    SeverityStats   `json:"stats"`
}

// ScanFinding represents a simplified finding for display
type ScanFinding struct {
	ID          string `json:"id"`
	PayloadName string `json:"payload_name"`
	Domain      string `json:"domain"`
	Plugin      string `json:"plugin"`
	Severity    string `json:"severity"`
	Success     bool   `json:"success"`
	Message     string `json:"message,omitempty"`
}

// NewResultsOrganizer creates a new results organizer
func NewResultsOrganizer() *ResultsOrganizer {
	return &ResultsOrganizer{}
}

// OrganizeScanResults organizes scan results by severity
// Implements requirement 8: results organization by severity
func (ro *ResultsOrganizer) OrganizeScanResults(result ScanResult, findings []ScanFinding) OrganizedResults {
	organized := OrganizedResults{
		Critical: []ScanFinding{},
		High:     []ScanFinding{},
		Medium:   []ScanFinding{},
		Low:      []ScanFinding{},
		Stats: SeverityStats{
			Total: len(findings),
		},
	}

	// Organize findings by severity
	for _, finding := range findings {
		severity := ro.normalizeSeverity(finding.Severity)

		switch severity {
		case "critical":
			organized.Critical = append(organized.Critical, finding)
			organized.Stats.Critical++
		case "high":
			organized.High = append(organized.High, finding)
			organized.Stats.High++
		case "medium":
			organized.Medium = append(organized.Medium, finding)
			organized.Stats.Medium++
		case "low":
			organized.Low = append(organized.Low, finding)
			organized.Stats.Low++
		default:
			// Default to medium if unknown severity
			organized.Medium = append(organized.Medium, finding)
			organized.Stats.Medium++
		}
	}

	// Sort within each severity level by domain/plugin/payload name
	ro.sortFindings(organized.Critical)
	ro.sortFindings(organized.High)
	ro.sortFindings(organized.Medium)
	ro.sortFindings(organized.Low)

	return organized
}

// CreateFindingsFromScanResult creates scan findings from scan result
func (ro *ResultsOrganizer) CreateFindingsFromScanResult(result ScanResult) []ScanFinding {
	var findings []ScanFinding

	// Create findings based on scan result statistics
	for domain, stats := range result.DomainStats {
		// Create a summary finding for each domain
		severity := ro.inferSeverityFromStats(stats)

		finding := ScanFinding{
			ID:          domain + "_summary",
			PayloadName: "Domain Summary",
			Domain:      domain,
			Plugin:      "system",
			Severity:    severity,
			Success:     stats.SuccessCount > 0,
			Message:     ro.createDomainSummaryMessage(stats),
		}

		findings = append(findings, finding)

		// If there were failures, create additional findings
		if stats.FailureCount > 0 {
			failureFinding := ScanFinding{
				ID:          domain + "_failures",
				PayloadName: "Execution Failures",
				Domain:      domain,
				Plugin:      "system",
				Severity:    "high",
				Success:     false,
				Message:     ro.createFailureMessage(stats),
			}
			findings = append(findings, failureFinding)
		}
	}

	return findings
}

// GetSeverityOrder returns the severity levels in order from highest to lowest
func (ro *ResultsOrganizer) GetSeverityOrder() []string {
	return []string{"critical", "high", "medium", "low"}
}

// GetSeverityColor returns a color code for display purposes
func (ro *ResultsOrganizer) GetSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "blue"
	default:
		return "gray"
	}
}

// FormatSeverityStats returns a formatted string of severity statistics
func (ro *ResultsOrganizer) FormatSeverityStats(stats SeverityStats) string {
	if stats.Total == 0 {
		return "No findings"
	}

	return fmt.Sprintf("Total: %d (Critical: %d, High: %d, Medium: %d, Low: %d)",
		stats.Total, stats.Critical, stats.High, stats.Medium, stats.Low)
}

// normalizeSeverity normalizes severity strings to standard values
func (ro *ResultsOrganizer) normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "crit":
		return "critical"
	case "high", "hi":
		return "high"
	case "medium", "med", "moderate":
		return "medium"
	case "low", "lo", "info", "informational":
		return "low"
	default:
		return "medium" // Default severity
	}
}

// sortFindings sorts findings within a severity level
func (ro *ResultsOrganizer) sortFindings(findings []ScanFinding) {
	sort.Slice(findings, func(i, j int) bool {
		// Sort by domain first
		if findings[i].Domain != findings[j].Domain {
			return findings[i].Domain < findings[j].Domain
		}
		// Then by plugin
		if findings[i].Plugin != findings[j].Plugin {
			return findings[i].Plugin < findings[j].Plugin
		}
		// Finally by payload name
		return findings[i].PayloadName < findings[j].PayloadName
	})
}

// inferSeverityFromStats infers severity based on execution statistics
func (ro *ResultsOrganizer) inferSeverityFromStats(stats DomainStat) string {
	successRate := float64(stats.SuccessCount) / float64(stats.ExecutedCount)

	if stats.FailureCount > stats.SuccessCount {
		return "high"
	} else if successRate < 0.5 {
		return "medium"
	} else if successRate < 0.8 {
		return "low"
	} else {
		return "low"
	}
}

// createDomainSummaryMessage creates a summary message for domain execution
func (ro *ResultsOrganizer) createDomainSummaryMessage(stats DomainStat) string {
	successRate := float64(stats.SuccessCount) / float64(stats.ExecutedCount) * 100

	return fmt.Sprintf("Executed %d payloads across %d plugins. Success rate: %.1f%% (%d/%d)",
		stats.ExecutedCount, stats.PluginCount, successRate, stats.SuccessCount, stats.ExecutedCount)
}

// createFailureMessage creates a message for execution failures
func (ro *ResultsOrganizer) createFailureMessage(stats DomainStat) string {
	return fmt.Sprintf("%d payloads failed to execute in domain %s",
		stats.FailureCount, stats.Domain)
}