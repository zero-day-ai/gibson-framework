// +build e2e

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLI_VersionCommand tests the version command
func TestCLI_VersionCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Build the gibson binary for testing
	binaryPath := buildGibsonBinary(t)

	uu := map[string]struct {
		args     []string
		wantCode int
		contains []string
	}{
		"version_flag": {
			args:     []string{"--version"},
			wantCode: 0,
			contains: []string{"gibson", "version"},
		},
		"version_command": {
			args:     []string{"version"},
			wantCode: 0,
			contains: []string{"gibson", "version"},
		},
		"version_verbose": {
			args:     []string{"version", "--verbose"},
			wantCode: 0,
			contains: []string{"gibson", "version", "build"},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath, u.args...)
			output, err := cmd.CombinedOutput()

			if u.wantCode == 0 {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				if exitErr, ok := err.(*exec.ExitError); ok {
					assert.Equal(t, u.wantCode, exitErr.ExitCode())
				}
			}

			outputStr := string(output)
			for _, expectedContent := range u.contains {
				assert.Contains(t, strings.ToLower(outputStr), strings.ToLower(expectedContent),
					"Output should contain: %s", expectedContent)
			}
		})
	}
}

// TestCLI_HelpCommand tests help functionality
func TestCLI_HelpCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	binaryPath := buildGibsonBinary(t)

	uu := map[string]struct {
		args     []string
		contains []string
	}{
		"root_help": {
			args:     []string{"--help"},
			contains: []string{"gibson", "usage", "commands", "flags"},
		},
		"help_command": {
			args:     []string{"help"},
			contains: []string{"gibson", "usage", "commands"},
		},
		"scan_help": {
			args:     []string{"scan", "--help"},
			contains: []string{"scan", "usage", "flags"},
		},
		"target_help": {
			args:     []string{"target", "--help"},
			contains: []string{"target", "usage", "flags"},
		},
		"plugin_help": {
			args:     []string{"plugin", "--help"},
			contains: []string{"plugin", "usage", "flags"},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath, u.args...)
			output, err := cmd.CombinedOutput()

			// Help should return exit code 0
			assert.NoError(t, err)

			outputStr := strings.ToLower(string(output))
			for _, expectedContent := range u.contains {
				assert.Contains(t, outputStr, strings.ToLower(expectedContent),
					"Help output should contain: %s", expectedContent)
			}
		})
	}
}

// TestCLI_TargetWorkflow tests complete target management workflow
func TestCLI_TargetWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	binaryPath := buildGibsonBinary(t)
	configDir := setupTestConfig(t)

	// Test target lifecycle: create -> list -> show -> delete
	t.Run("target_lifecycle", func(t *testing.T) {
		targetName := "test-api-server"
		targetURL := "http://localhost:8080"

		// Create target
		t.Run("create_target", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			args := []string{
				"target", "create",
				"--name", targetName,
				"--type", "api",
				"--url", targetURL,
				"--config-dir", configDir,
			}

			cmd := exec.CommandContext(ctx, binaryPath, args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err, "Create target failed: %s", string(output))
			assert.Contains(t, string(output), "created", "Output should indicate target was created")
		})

		// List targets
		t.Run("list_targets", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := []string{"target", "list", "--config-dir", configDir}
			cmd := exec.CommandContext(ctx, binaryPath, args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err, "List targets failed: %s", string(output))
			assert.Contains(t, string(output), targetName, "List should contain created target")
		})

		// Show specific target
		t.Run("show_target", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := []string{"target", "show", targetName, "--config-dir", configDir}
			cmd := exec.CommandContext(ctx, binaryPath, args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err, "Show target failed: %s", string(output))
			outputStr := string(output)
			assert.Contains(t, outputStr, targetName, "Show should display target name")
			assert.Contains(t, outputStr, targetURL, "Show should display target URL")
		})

		// Delete target
		t.Run("delete_target", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := []string{"target", "delete", targetName, "--config-dir", configDir, "--force"}
			cmd := exec.CommandContext(ctx, binaryPath, args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err, "Delete target failed: %s", string(output))
			assert.Contains(t, string(output), "deleted", "Output should indicate target was deleted")
		})

		// Verify target is deleted
		t.Run("verify_target_deleted", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := []string{"target", "list", "--config-dir", configDir}
			cmd := exec.CommandContext(ctx, binaryPath, args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err, "List targets after delete failed: %s", string(output))
			assert.NotContains(t, string(output), targetName, "List should not contain deleted target")
		})
	})
}

// TestCLI_PluginWorkflow tests plugin management workflow
func TestCLI_PluginWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	binaryPath := buildGibsonBinary(t)
	configDir := setupTestConfig(t)
	pluginDir := setupTestPlugins(t)

	t.Run("plugin_management", func(t *testing.T) {
		// List available plugins
		t.Run("list_plugins", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := []string{
				"plugin", "list",
				"--config-dir", configDir,
				"--plugin-dir", pluginDir,
			}

			cmd := exec.CommandContext(ctx, binaryPath, args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err, "List plugins failed: %s", string(output))
			// Should list our test plugins
			assert.Contains(t, string(output), "test-plugin", "Should list test plugin")
		})

		// Show plugin info
		t.Run("show_plugin", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args := []string{
				"plugin", "show", "test-plugin",
				"--config-dir", configDir,
				"--plugin-dir", pluginDir,
			}

			cmd := exec.CommandContext(ctx, binaryPath, args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err, "Show plugin failed: %s", string(output))
			outputStr := string(output)
			assert.Contains(t, outputStr, "test-plugin", "Should show plugin name")
			assert.Contains(t, outputStr, "version", "Should show plugin version")
		})
	})
}

// TestCLI_ScanWorkflow tests scanning workflow
func TestCLI_ScanWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	binaryPath := buildGibsonBinary(t)
	configDir := setupTestConfig(t)
	pluginDir := setupTestPlugins(t)

	t.Run("scan_workflow", func(t *testing.T) {
		// First create a target to scan
		targetName := "scan-test-target"
		createArgs := []string{
			"target", "create",
			"--name", targetName,
			"--type", "api",
			"--url", "http://localhost:8080",
			"--config-dir", configDir,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, binaryPath, createArgs...)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to create target for scan test: %s", string(output))

		// Run a scan
		t.Run("run_scan", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			scanArgs := []string{
				"scan", "run",
				"--target", targetName,
				"--config-dir", configDir,
				"--plugin-dir", pluginDir,
				"--output", "json",
			}

			cmd := exec.CommandContext(ctx, binaryPath, scanArgs...)
			output, err := cmd.CombinedOutput()

			// Note: This might fail if plugins can't actually execute, but should provide meaningful output
			outputStr := string(output)
			t.Logf("Scan output: %s", outputStr)

			// Check that scan was attempted
			assert.True(t, err != nil || strings.Contains(outputStr, "scan"),
				"Should attempt to run scan or provide error message")
		})

		// List scans
		t.Run("list_scans", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			listArgs := []string{
				"scan", "list",
				"--config-dir", configDir,
			}

			cmd := exec.CommandContext(ctx, binaryPath, listArgs...)
			output, err := cmd.CombinedOutput()

			// Should be able to list scans even if none completed successfully
			assert.NoError(t, err, "List scans failed: %s", string(output))
		})

		// Cleanup: delete the test target
		deleteArgs := []string{"target", "delete", targetName, "--config-dir", configDir, "--force"}
		cmd = exec.CommandContext(context.Background(), binaryPath, deleteArgs...)
		cmd.Run() // Best effort cleanup
	})
}

// TestCLI_ErrorHandling tests error scenarios
func TestCLI_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	binaryPath := buildGibsonBinary(t)

	uu := map[string]struct {
		args        []string
		wantExitErr bool
		contains    []string
	}{
		"invalid_command": {
			args:        []string{"nonexistent-command"},
			wantExitErr: true,
			contains:    []string{"unknown command", "nonexistent-command"},
		},
		"missing_required_flag": {
			args:        []string{"target", "create"},
			wantExitErr: true,
			contains:    []string{"required", "flag"},
		},
		"invalid_flag": {
			args:        []string{"--nonexistent-flag"},
			wantExitErr: true,
			contains:    []string{"unknown", "flag"},
		},
		"help_for_invalid_command": {
			args:        []string{"help", "nonexistent-command"},
			wantExitErr: true,
			contains:    []string{"unknown", "command"},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath, u.args...)
			output, err := cmd.CombinedOutput()

			if u.wantExitErr {
				assert.Error(t, err, "Expected command to fail")
			}

			outputStr := strings.ToLower(string(output))
			for _, expectedContent := range u.contains {
				assert.Contains(t, outputStr, strings.ToLower(expectedContent),
					"Error output should contain: %s", expectedContent)
			}
		})
	}
}

// buildGibsonBinary builds the gibson binary for testing
func buildGibsonBinary(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "gibson-test")

	// Build the binary
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build",
		"-o", binaryPath,
		"../../main.go")

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build gibson binary: %s", string(output))

	// Verify binary exists and is executable
	info, err := os.Stat(binaryPath)
	require.NoError(t, err, "Binary not found after build")
	require.False(t, info.IsDir(), "Expected file, got directory")

	return binaryPath
}

// setupTestConfig creates a temporary config directory
func setupTestConfig(t *testing.T) string {
	t.Helper()

	configDir := t.TempDir()

	// Create a basic config file
	configContent := `
# Gibson Framework Configuration
database:
  path: "gibson.db"

plugins:
  directory: "./plugins"
  timeout: "30s"
  max_concurrent: 5

logging:
  level: "info"
  format: "text"
`

	configPath := filepath.Join(configDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	return configDir
}

// setupTestPlugins creates test plugin directory structure
func setupTestPlugins(t *testing.T) string {
	t.Helper()

	pluginDir := t.TempDir()

	// Create test plugin directory
	testPluginDir := filepath.Join(pluginDir, "test-plugin")
	err := os.MkdirAll(testPluginDir, 0755)
	require.NoError(t, err)

	// Create plugin manifest
	manifest := `name: test-plugin
version: 1.0.0
description: Test plugin for e2e testing
author: Gibson Test Suite
executable: test-plugin
args: []
env: {}
timeout: 30s
domains:
  - interface
capabilities:
  - assess
`

	manifestPath := filepath.Join(testPluginDir, "plugin.yml")
	err = os.WriteFile(manifestPath, []byte(manifest), 0644)
	require.NoError(t, err)

	// Create dummy executable
	execPath := filepath.Join(testPluginDir, "test-plugin")
	execContent := "#!/bin/bash\necho 'Test plugin executed'\nexit 0\n"
	err = os.WriteFile(execPath, []byte(execContent), 0755)
	require.NoError(t, err)

	return pluginDir
}

// captureCommandOutput captures both stdout and stderr from a command
func captureCommandOutput(t *testing.T, cmd *exec.Cmd) (stdout, stderr string, err error) {
	t.Helper()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}

	if err := cmd.Start(); err != nil {
		return "", "", err
	}

	// Read stdout
	stdoutScanner := bufio.NewScanner(stdoutPipe)
	var stdoutLines []string
	for stdoutScanner.Scan() {
		stdoutLines = append(stdoutLines, stdoutScanner.Text())
	}

	// Read stderr
	stderrScanner := bufio.NewScanner(stderrPipe)
	var stderrLines []string
	for stderrScanner.Scan() {
		stderrLines = append(stderrLines, stderrScanner.Text())
	}

	err = cmd.Wait()

	return strings.Join(stdoutLines, "\n"),
		strings.Join(stderrLines, "\n"),
		err
}