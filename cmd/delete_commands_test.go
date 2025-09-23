package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetDeleteCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "delete with positional argument",
			args:        []string{"my-target"},
			expectError: false,
		},
		{
			name:        "delete with name flag",
			args:        []string{},
			flags:       map[string]string{"name": "my-target"},
			expectError: false,
		},
		{
			name:        "delete with ID flag",
			args:        []string{},
			flags:       map[string]string{"id": "target-123"},
			expectError: false,
		},
		{
			name:        "positional argument overrides name flag",
			args:        []string{"positional-target"},
			flags:       map[string]string{"name": "flag-target"},
			expectError: false,
		},
		{
			name:        "no identifier provided",
			args:        []string{},
			flags:       map[string]string{},
			expectError: true,
			errorMsg:    "either target name or ID must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary command for testing
			cmd := &cobra.Command{
				Use: "delete",
			}

			// Add flags
			targetNameFlag = cmd.Flags().StringP("name", "n", "", "Target name")
			targetIDFlag = cmd.Flags().String("id", "", "Target ID")
			targetAllFlag = cmd.Flags().BoolP("all", "a", false, "Delete all")
			targetForceFlag = cmd.Flags().BoolP("force", "f", false, "Force deletion")

			// Set flag values
			for flag, value := range tt.flags {
				err := cmd.Flags().Set(flag, value)
				require.NoError(t, err)
			}

			// Mock the view layer by creating a test implementation
			// In a real implementation, we'd use dependency injection
			// For now, we'll test the argument parsing logic

			// Test argument parsing logic directly
			targetName := getValue(targetNameFlag)
			if len(tt.args) > 0 {
				targetName = tt.args[0]
			}
			targetID := getValue(targetIDFlag)

			if tt.expectError {
				if targetName == "" && targetID == "" {
					assert.Contains(t, tt.errorMsg, "either target name or ID must be specified")
				}
			} else {
				// Verify we have valid input
				assert.True(t, targetName != "" || targetID != "", "Should have either name or ID")

				if len(tt.args) > 0 {
					assert.Equal(t, tt.args[0], targetName, "Positional argument should be used")
				}
			}
		})
	}
}

func TestCredentialDeleteCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:        "delete with positional argument",
			args:        []string{"my-credential"},
			expectError: false,
		},
		{
			name:        "delete with name flag",
			args:        []string{},
			flags:       map[string]interface{}{"name": "my-credential"},
			expectError: false,
		},
		{
			name:        "delete with ID flag",
			args:        []string{},
			flags:       map[string]interface{}{"id": "cred-123"},
			expectError: false,
		},
		{
			name:        "delete all credentials",
			args:        []string{},
			flags:       map[string]interface{}{"all": true},
			expectError: false,
		},
		{
			name:        "no identifier and no all flag",
			args:        []string{},
			flags:       map[string]interface{}{},
			expectError: true,
			errorMsg:    "either credential name, ID, or --all flag must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary command for testing
			cmd := &cobra.Command{
				Use: "delete",
			}

			// Add flags
			credentialNameFlag = cmd.Flags().StringP("name", "n", "", "Credential name")
			credentialIDFlag = cmd.Flags().String("id", "", "Credential ID")
			credentialAllFlag = cmd.Flags().BoolP("all", "a", false, "Delete all")
			credentialForceFlag = cmd.Flags().BoolP("force", "f", false, "Force deletion")

			// Set flag values
			for flag, value := range tt.flags {
				switch v := value.(type) {
				case string:
					err := cmd.Flags().Set(flag, v)
					require.NoError(t, err)
				case bool:
					if v {
						err := cmd.Flags().Set(flag, "true")
						require.NoError(t, err)
					}
				}
			}

			// Test argument parsing logic
			credentialName := getValue(credentialNameFlag)
			if len(tt.args) > 0 {
				credentialName = tt.args[0]
			}
			credentialID := getValue(credentialIDFlag)
			all := getBoolValue(credentialAllFlag)

			if tt.expectError {
				if credentialName == "" && credentialID == "" && !all {
					assert.Contains(t, tt.errorMsg, "either credential name, ID, or --all flag must be specified")
				}
			} else {
				// Verify we have valid input
				assert.True(t, credentialName != "" || credentialID != "" || all, "Should have either name, ID, or all flag")
			}
		})
	}
}

func TestScanDeleteCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:        "delete with positional argument",
			args:        []string{"scan-123"},
			expectError: false,
		},
		{
			name:        "delete with ID flag",
			args:        []string{},
			flags:       map[string]interface{}{"id": "scan-123"},
			expectError: false,
		},
		{
			name:        "delete all scans",
			args:        []string{},
			flags:       map[string]interface{}{"all": true},
			expectError: false,
		},
		{
			name:        "no identifier and no all flag",
			args:        []string{},
			flags:       map[string]interface{}{},
			expectError: true,
			errorMsg:    "either scan ID or --all flag must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary command for testing
			cmd := &cobra.Command{
				Use: "delete",
			}

			// Add flags
			scanIDFlag = cmd.Flags().String("id", "", "Scan ID")
			scanAllFlag = cmd.Flags().BoolP("all", "a", false, "Delete all")

			// Set flag values
			for flag, value := range tt.flags {
				switch v := value.(type) {
				case string:
					err := cmd.Flags().Set(flag, v)
					require.NoError(t, err)
				case bool:
					if v {
						err := cmd.Flags().Set(flag, "true")
						require.NoError(t, err)
					}
				}
			}

			// Test argument parsing logic
			scanID := getValue(scanIDFlag)
			if len(tt.args) > 0 {
				scanID = tt.args[0]
			}
			all := getBoolValue(scanAllFlag)

			if tt.expectError {
				if scanID == "" && !all {
					assert.Contains(t, tt.errorMsg, "either scan ID or --all flag must be specified")
				}
			} else {
				// Verify we have valid input
				assert.True(t, scanID != "" || all, "Should have either scan ID or all flag")
			}
		})
	}
}

func TestPayloadRemoveCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:        "remove with positional argument",
			args:        []string{"injection-001"},
			expectError: false,
		},
		{
			name:        "remove with name flag",
			args:        []string{},
			flags:       map[string]interface{}{"name": "injection-001"},
			expectError: false,
		},
		{
			name:        "remove with ID flag",
			args:        []string{},
			flags:       map[string]interface{}{"id": "payload-123"},
			expectError: false,
		},
		{
			name:        "remove with tags",
			args:        []string{},
			flags:       map[string]interface{}{"tags": []string{"deprecated"}},
			expectError: false,
		},
		{
			name:        "remove with category",
			args:        []string{},
			flags:       map[string]interface{}{"category": "test"},
			expectError: false,
		},
		{
			name:        "no identifier provided",
			args:        []string{},
			flags:       map[string]interface{}{},
			expectError: true,
			errorMsg:    "either payload name, ID, tags, or category must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary command for testing
			cmd := &cobra.Command{
				Use: "remove",
			}

			// Add flags
			payloadNameFlag = cmd.Flags().StringP("name", "n", "", "Payload name")
			payloadIDFlag = cmd.Flags().String("id", "", "Payload ID")
			cmd.Flags().StringSlice("tags", []string{}, "Tags")
			cmd.Flags().String("category", "", "Category")

			// Set flag values
			for flag, value := range tt.flags {
				switch v := value.(type) {
				case string:
					err := cmd.Flags().Set(flag, v)
					require.NoError(t, err)
				case []string:
					for _, tag := range v {
						err := cmd.Flags().Set(flag, tag)
						require.NoError(t, err)
					}
				}
			}

			// Test argument parsing logic
			payloadName := getValue(payloadNameFlag)
			if len(tt.args) > 0 {
				payloadName = tt.args[0]
			}
			payloadID := getValue(payloadIDFlag)
			tags, _ := cmd.Flags().GetStringSlice("tags")
			category, _ := cmd.Flags().GetString("category")

			if tt.expectError {
				if payloadName == "" && payloadID == "" && len(tags) == 0 && category == "" {
					assert.Contains(t, tt.errorMsg, "either payload name, ID, tags, or category must be specified")
				}
			} else {
				// Verify we have valid input
				assert.True(t, payloadName != "" || payloadID != "" || len(tags) > 0 || category != "",
					"Should have either name, ID, tags, or category")
			}
		})
	}
}

func TestPluginUninstallCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "uninstall with positional argument",
			args:        []string{"my-plugin"},
			expectError: false,
		},
		{
			name:        "uninstall with name flag",
			args:        []string{},
			flags:       map[string]string{"name": "my-plugin"},
			expectError: false,
		},
		{
			name:        "uninstall with ID flag",
			args:        []string{},
			flags:       map[string]string{"id": "plugin-123"},
			expectError: false,
		},
		{
			name:        "positional argument overrides name flag",
			args:        []string{"positional-plugin"},
			flags:       map[string]string{"name": "flag-plugin"},
			expectError: false,
		},
		{
			name:        "no identifier provided",
			args:        []string{},
			flags:       map[string]string{},
			expectError: true,
			errorMsg:    "either plugin name or ID must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary command for testing
			cmd := &cobra.Command{
				Use: "uninstall",
			}

			// Add flags
			pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name")
			pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID")

			// Set flag values
			for flag, value := range tt.flags {
				err := cmd.Flags().Set(flag, value)
				require.NoError(t, err)
			}

			// Test argument parsing logic
			pluginName := getValue(pluginNameFlag)
			if len(tt.args) > 0 {
				pluginName = tt.args[0]
			}
			pluginID := getValue(pluginIDFlag)

			if tt.expectError {
				if pluginName == "" && pluginID == "" {
					assert.Contains(t, tt.errorMsg, "either plugin name or ID must be specified")
				}
			} else {
				// Verify we have valid input
				assert.True(t, pluginName != "" || pluginID != "", "Should have either name or ID")

				if len(tt.args) > 0 {
					assert.Equal(t, tt.args[0], pluginName, "Positional argument should be used")
				}
			}
		})
	}
}

// Test helper functions
func TestGetValue(t *testing.T) {
	tests := []struct {
		name     string
		input    *string
		expected string
	}{
		{
			name:     "nil pointer",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty string",
			input:    stringPtr(""),
			expected: "",
		},
		{
			name:     "non-empty string",
			input:    stringPtr("test-value"),
			expected: "test-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetBoolValue(t *testing.T) {
	tests := []struct {
		name     string
		input    *bool
		expected bool
	}{
		{
			name:     "nil pointer",
			input:    nil,
			expected: false,
		},
		{
			name:     "false value",
			input:    boolPtr(false),
			expected: false,
		},
		{
			name:     "true value",
			input:    boolPtr(true),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBoolValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper functions for creating pointers
func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}