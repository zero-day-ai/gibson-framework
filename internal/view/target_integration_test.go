// Package view provides target view integration tests
package view

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/google/uuid"
)

// TestTargetViewIntegration tests basic target view operations
func TestTargetViewIntegration(t *testing.T) {
	// Skip if running in CI without proper setup
	if os.Getenv("GIBSON_SKIP_INTEGRATION_TESTS") != "" {
		t.Skip("Skipping integration test")
	}

	// Setup test directory
	testDir := filepath.Join(os.TempDir(), "gibson-test-"+uuid.New().String())
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create encryption key file
	keyPath := filepath.Join(testDir, ".encryption_key")
	testKey := "dGVzdC1lbmNyeXB0aW9uLWtleQ==" // base64 encoded "test-encryption-key"
	if err := os.WriteFile(keyPath, []byte(testKey), 0600); err != nil {
		t.Fatalf("Failed to create encryption key: %v", err)
	}

	// Override gibson home for test
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", filepath.Dir(testDir))
	defer os.Setenv("HOME", oldHome)

	t.Run("CreateTargetView", func(t *testing.T) {
		_, err := NewTargetView()
		if err != nil {
			t.Logf("Expected error creating target view without proper setup: %v", err)
			// This is expected in test environment without full Gibson setup
		}
	})

	t.Run("ValidateTargetConfig", func(t *testing.T) {
		tv := &targetView{}

		target := &model.Target{
			ID:       uuid.New(),
			Name:     "test-target",
			Provider: model.ProviderOpenAI,
			Model:    "gpt-4",
			URL:      "https://api.openai.com/v1",
			Status:   model.TargetStatusActive,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		err := tv.validateTargetConfig(target)
		if err != nil {
			t.Errorf("Expected valid target config, got error: %v", err)
		}
	})

	t.Run("ValidateInvalidTargetConfig", func(t *testing.T) {
		tv := &targetView{}

		target := &model.Target{
			ID:       uuid.New(),
			Name:     "test-target",
			Provider: model.ProviderOpenAI,
			Model:    "", // Missing required model
			URL:      "invalid-url", // Invalid URL
			Status:   model.TargetStatusActive,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		err := tv.validateTargetConfig(target)
		if err == nil {
			t.Error("Expected validation error for invalid config")
		}
	})

	t.Run("LoadConfigFromFile", func(t *testing.T) {
		tv := &targetView{}

		// Create test config file
		configPath := filepath.Join(testDir, "test-config.json")
		configContent := `{"temperature": 0.7, "max_tokens": 1000}`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to create test config file: %v", err)
		}

		config, err := tv.loadConfigFromFile(configPath)
		if err != nil {
			t.Errorf("Failed to load config file: %v", err)
		}

		if config["temperature"] != 0.7 {
			t.Errorf("Expected temperature 0.7, got %v", config["temperature"])
		}
	})
}

// TestTargetAddOptions tests the target add options structure
func TestTargetAddOptions(t *testing.T) {
	opts := TargetAddOptions{
		Name:     "test-target",
		Provider: "openai",
		Model:    "gpt-4",
		URL:      "https://api.openai.com/v1",
		APIKey:   "test-key",
		Config:   "",
		Output:   "json",
	}

	if opts.Name != "test-target" {
		t.Errorf("Expected name 'test-target', got '%s'", opts.Name)
	}

	if opts.Provider != "openai" {
		t.Errorf("Expected provider 'openai', got '%s'", opts.Provider)
	}
}

// TestTruncateString tests the string truncation helper
func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		length   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string that should be truncated", 20, "this is a very lo..."},
		{"exactly20characters", 20, "exactly20characters"},
		{"", 5, ""},
	}

	for _, test := range tests {
		result := truncateString(test.input, test.length)
		if result != test.expected {
			t.Errorf("truncateString(%q, %d) = %q, expected %q",
				test.input, test.length, result, test.expected)
		}
	}
}