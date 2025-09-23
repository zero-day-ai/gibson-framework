package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiskSpaceHealthCheck(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "gibson-disk-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create the disk space health check
	checkFunc := DiskSpaceHealthCheck(tmpDir, 1) // 1GB minimum

	// Run the health check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := checkFunc(ctx)

	// Verify the result
	if result == nil {
		t.Fatal("Health check returned nil result")
	}

	if result.Name != "disk_space" {
		t.Errorf("Expected check name 'disk_space', got %s", result.Name)
	}

	// The status should be one of the valid statuses
	validStatuses := map[Status]bool{
		StatusHealthy:   true,
		StatusDegraded:  true,
		StatusUnhealthy: true,
	}
	if !validStatuses[result.Status] {
		t.Errorf("Invalid status: %s", result.Status)
	}

	// Verify required details are present
	requiredFields := []string{
		"path", "total_bytes", "used_bytes", "available_bytes",
		"used_percent", "free_percent", "total_formatted",
		"used_formatted", "free_formatted",
	}

	if result.Details == nil {
		t.Fatal("Health check details are nil")
	}

	for _, field := range requiredFields {
		if _, exists := result.Details[field]; !exists {
			t.Errorf("Missing required detail field: %s", field)
		}
	}

	// Verify the path is correct
	if pathDetail, ok := result.Details["path"].(string); ok {
		if pathDetail != tmpDir {
			t.Errorf("Expected path %s, got %s", tmpDir, pathDetail)
		}
	} else {
		t.Error("Path detail is not a string")
	}

	// Verify percentages are reasonable (0-100%)
	if usedPercent, ok := result.Details["used_percent"].(float64); ok {
		if usedPercent < 0 || usedPercent > 100 {
			t.Errorf("Invalid used_percent: %f", usedPercent)
		}
	} else {
		t.Error("used_percent is not a float64")
	}

	if freePercent, ok := result.Details["free_percent"].(float64); ok {
		if freePercent < 0 || freePercent > 100 {
			t.Errorf("Invalid free_percent: %f", freePercent)
		}
	} else {
		t.Error("free_percent is not a float64")
	}

	t.Logf("Disk space check result: %s - %s", result.Status, result.Message)
	t.Logf("Details: %+v", result.Details)
}

func TestDiskSpaceHealthCheckDefaultPath(t *testing.T) {
	// Test with empty path (should default to ~/.gibson)
	checkFunc := DiskSpaceHealthCheck("", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := checkFunc(ctx)

	if result == nil {
		t.Fatal("Health check returned nil result")
	}

	// Should have created the .gibson directory and checked it
	if result.Status == StatusUnhealthy && result.Error != "" {
		t.Logf("Health check failed (this might be expected): %s - %s", result.Message, result.Error)
	} else {
		// Verify the path includes .gibson
		if pathDetail, ok := result.Details["path"].(string); ok {
			homeDir, _ := os.UserHomeDir()
			expectedPath := filepath.Join(homeDir, ".gibson")
			if pathDetail != expectedPath {
				t.Errorf("Expected path %s, got %s", expectedPath, pathDetail)
			}
		}
	}

	t.Logf("Default path check result: %s - %s", result.Status, result.Message)
}

func TestFormatBytes(t *testing.T) {
	testCases := []struct {
		bytes    uint64
		expected string
	}{
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tc := range testCases {
		result := formatBytes(tc.bytes)
		if result != tc.expected {
			t.Errorf("formatBytes(%d) = %s, expected %s", tc.bytes, result, tc.expected)
		}
	}
}

func TestDiskSpaceThresholds(t *testing.T) {
	// This test verifies the threshold logic would work correctly
	// We can't easily simulate different disk usage levels, but we can verify
	// the logic by checking a real path and ensuring the status makes sense

	tmpDir, err := os.MkdirTemp("", "gibson-threshold-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	checkFunc := DiskSpaceHealthCheck(tmpDir, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := checkFunc(ctx)

	if result == nil {
		t.Fatal("Health check returned nil result")
	}

	// Get the usage percentage
	usedPercent, ok := result.Details["used_percent"].(float64)
	if !ok {
		t.Fatal("used_percent not found or not float64")
	}

	// Verify status matches the usage percentage
	expectedStatus := StatusHealthy
	if usedPercent >= 90.0 {
		expectedStatus = StatusUnhealthy
	} else if usedPercent >= 80.0 {
		expectedStatus = StatusDegraded
	}

	if result.Status != expectedStatus {
		t.Errorf("Status mismatch: usage %.1f%% should be %s, got %s",
			usedPercent, expectedStatus, result.Status)
	}

	t.Logf("Threshold test: %.1f%% usage resulted in %s status", usedPercent, result.Status)
}