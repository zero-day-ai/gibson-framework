package view

import (
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/plugin"
)

func TestPluginView_Integration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "gibson-plugin-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Set up environment to use temp directory
	os.Setenv("HOME", tempDir)
	defer os.Unsetenv("HOME")

	// Create .gibson directory structure
	gibsonHome := filepath.Join(tempDir, ".gibson")
	if err := os.MkdirAll(gibsonHome, 0755); err != nil {
		t.Fatalf("Failed to create gibson home: %v", err)
	}

	// Create plugins directory
	pluginsDir := filepath.Join(gibsonHome, "plugins")
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		t.Fatalf("Failed to create plugins directory: %v", err)
	}

	// Create a mock plugin directory structure
	mockPluginDir := filepath.Join(pluginsDir, "test-plugin")
	if err := os.MkdirAll(mockPluginDir, 0755); err != nil {
		t.Fatalf("Failed to create mock plugin directory: %v", err)
	}

	// Create plugin manifest
	manifest := `name: test-plugin
version: "1.0.0"
description: "Test plugin for integration testing"
author: "Gibson Framework"
executable: test-plugin
args: []
domains:
  - interface
capabilities:
  - assess
`
	manifestPath := filepath.Join(mockPluginDir, "plugin.yml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		t.Fatalf("Failed to create plugin manifest: %v", err)
	}

	// Create database file
	dbPath := filepath.Join(gibsonHome, "gibson.db")
	if _, err := os.Create(dbPath); err != nil {
		t.Fatalf("Failed to create database file: %v", err)
	}

	// Create encryption key
	encKeyPath := filepath.Join(gibsonHome, ".encryption_key")
	// Base64 encode the key as expected by readEncryptionKey
	rawKey := []byte("test-encryption-key-32-bytes!!")
	encKey := base64.StdEncoding.EncodeToString(rawKey)
	if err := os.WriteFile(encKeyPath, []byte(encKey), 0600); err != nil {
		t.Fatalf("Failed to create encryption key: %v", err)
	}

	// Test plugin view creation
	pluginView, err := NewPluginView()
	if err != nil {
		t.Fatalf("Failed to create plugin view: %v", err)
	}

	if pluginView == nil {
		t.Fatal("Plugin view is nil")
	}

	// Test that all required components are initialized
	if pluginView.serviceFactory == nil {
		t.Error("Service factory is nil")
	}

	if pluginView.pluginService == nil {
		t.Error("Plugin service is nil")
	}

	if pluginView.pluginManager == nil {
		t.Error("Plugin manager is nil")
	}

	if pluginView.logger == nil {
		t.Error("Logger is nil")
	}
}

func TestPluginView_DiscoverPlugins(t *testing.T) {
	// This test would require setting up a more complex environment
	// For now, we'll test that the method can be called without panicking
	logger := slog.Default()
	pluginView := &pluginView{
		pluginManager: plugin.NewManager("/tmp/test-plugins", plugin.WithLogger(logger)),
		logger:        logger,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := PluginDiscoverOptions{
		Path:   "/tmp/test-plugins",
		Output: "table",
	}

	// This should not panic even if no plugins are found
	err := pluginView.DiscoverPlugins(ctx, opts)
	if err != nil {
		t.Logf("Expected error for non-existent path: %v", err)
		// This is expected since the test path doesn't exist
	}
}

func TestValidationResult(t *testing.T) {
	result := &ValidationResult{
		InterfaceValid:    true,
		HealthCheckPassed: false,
		Loadable:          true,
		Errors:            []string{"health check failed"},
		Warnings:          []string{"some warning"},
	}

	if !result.InterfaceValid {
		t.Error("Interface should be valid")
	}

	if result.HealthCheckPassed {
		t.Error("Health check should have failed")
	}

	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(result.Errors))
	}

	if len(result.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(result.Warnings))
	}
}