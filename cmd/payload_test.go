package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPayloadDetailsCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "details with single ID",
			args:        []string{"a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
			expectError: false,
		},
		{
			name:        "details with partial ID",
			args:        []string{"a1b2c3d4"},
			expectError: false,
		},
		{
			name:        "details with multiple IDs",
			args:        []string{"a1b2c3d4", "e5f67890"},
			expectError: false,
		},
		{
			name:        "details with JSON output",
			args:        []string{"a1b2c3d4"},
			flags:       map[string]string{"output": "json"},
			expectError: false,
		},
		{
			name:        "details with YAML output",
			args:        []string{"a1b2c3d4"},
			flags:       map[string]string{"output": "yaml"},
			expectError: false,
		},
		{
			name:        "details with raw output",
			args:        []string{"a1b2c3d4"},
			flags:       map[string]string{"output": "raw"},
			expectError: false,
		},
		{
			name:        "details with no-color flag",
			args:        []string{"a1b2c3d4"},
			flags:       map[string]string{"no-color": "true"},
			expectError: false,
		},
		{
			name:        "details with compare flag",
			args:        []string{"a1b2c3d4", "e5f67890"},
			flags:       map[string]string{"compare": "true"},
			expectError: false,
		},
		{
			name:        "details with verbose flag",
			args:        []string{"a1b2c3d4"},
			flags:       map[string]string{"verbose": "true"},
			expectError: false,
		},
		{
			name:        "no ID provided",
			args:        []string{},
			expectError: true,
			errorMsg:    "requires at least 1 arg(s), only received 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := payloadDetailsCmd()
			require.NotNil(t, cmd)
			assert.Equal(t, "details [ID...]", cmd.Use)
			assert.Contains(t, cmd.Aliases, "detail")
			assert.Contains(t, cmd.Aliases, "show")
			assert.Contains(t, cmd.Aliases, "get")

			// Test command structure
			assert.Equal(t, "Display detailed payload information", cmd.Short)
			assert.Contains(t, cmd.Long, "Display complete payload content and metadata")

			// Test flags
			outputFlag := cmd.Flags().Lookup("output")
			require.NotNil(t, outputFlag)
			assert.Equal(t, "table", outputFlag.DefValue)

			noColorFlag := cmd.Flags().Lookup("no-color")
			require.NotNil(t, noColorFlag)
			assert.Equal(t, "false", noColorFlag.DefValue)

			compareFlag := cmd.Flags().Lookup("compare")
			require.NotNil(t, compareFlag)
			assert.Equal(t, "false", compareFlag.DefValue)

			verboseFlag := cmd.Flags().Lookup("verbose")
			require.NotNil(t, verboseFlag)
			assert.Equal(t, "false", verboseFlag.DefValue)

			// Test argument validation
			cmd.SetArgs(tt.args)

			// Set flags if provided
			for flagName, flagValue := range tt.flags {
				err := cmd.Flags().Set(flagName, flagValue)
				require.NoError(t, err)
			}

			// Validate arguments
			err := cmd.Args(cmd, tt.args)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPayloadDetailsCommandFlags(t *testing.T) {
	cmd := payloadDetailsCmd()

	// Test output flag values
	outputFlag := cmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)
	assert.Equal(t, "table", outputFlag.DefValue)
	assert.Contains(t, outputFlag.Usage, "table, json, yaml, raw")

	// Test no-color flag
	noColorFlag := cmd.Flags().Lookup("no-color")
	require.NotNil(t, noColorFlag)
	assert.Equal(t, "false", noColorFlag.DefValue)
	assert.Contains(t, noColorFlag.Usage, "Disable color output")

	// Test compare flag
	compareFlag := cmd.Flags().Lookup("compare")
	require.NotNil(t, compareFlag)
	assert.Equal(t, "false", compareFlag.DefValue)
	assert.Contains(t, compareFlag.Usage, "Side-by-side comparison")

	// Test verbose flag
	verboseFlag := cmd.Flags().Lookup("verbose")
	require.NotNil(t, verboseFlag)
	assert.Equal(t, "v", verboseFlag.Shorthand)
	assert.Equal(t, "false", verboseFlag.DefValue)
	assert.Contains(t, verboseFlag.Usage, "verbose")
}

func TestPayloadDetailsCommandExamples(t *testing.T) {
	cmd := payloadDetailsCmd()

	// Test that examples are provided
	assert.NotEmpty(t, cmd.Example)

	// Test that examples contain common use cases
	examples := cmd.Example
	assert.Contains(t, examples, "gibson payload details")
	assert.Contains(t, examples, "--output json")
	assert.Contains(t, examples, "--output yaml")
	assert.Contains(t, examples, "--output raw")
	assert.Contains(t, examples, "--no-color")
	assert.Contains(t, examples, "--compare")
	assert.Contains(t, examples, "--verbose")
}

func TestPayloadDetailsCommandIntegration(t *testing.T) {
	// Test that the details command is properly added to the payload command
	payloadCmd := payloadCmd()
	require.NotNil(t, payloadCmd)

	// Find the details subcommand
	var detailsCmd *cobra.Command
	for _, subCmd := range payloadCmd.Commands() {
		if subCmd.Name() == "details" {
			detailsCmd = subCmd
			break
		}
	}

	require.NotNil(t, detailsCmd, "details command should be added as subcommand of payload")
	assert.Equal(t, "details [ID...]", detailsCmd.Use)
}

// Test UUID validation patterns (these would be used by the actual implementation)
func TestPayloadIDValidation(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		valid    bool
		minLength bool
	}{
		{
			name:      "full UUID",
			id:        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			valid:     true,
			minLength: true,
		},
		{
			name:      "partial UUID 8 chars",
			id:        "a1b2c3d4",
			valid:     true,
			minLength: true,
		},
		{
			name:      "partial UUID 12 chars",
			id:        "a1b2c3d4e5f6",
			valid:     true,
			minLength: true,
		},
		{
			name:      "too short",
			id:        "a1b2c3",
			valid:     true, // hex chars are valid
			minLength: false, // but too short
		},
		{
			name:      "invalid hex chars",
			id:        "g1h2i3j4",
			valid:     false,
			minLength: true,
		},
		{
			name:      "empty string",
			id:        "",
			valid:     false,
			minLength: false,
		},
		{
			name:      "mixed case valid",
			id:        "A1B2c3d4",
			valid:     true,
			minLength: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test hex validation
			isHex := isValidHexForTest(tt.id)
			assert.Equal(t, tt.valid, isHex, "hex validation mismatch for %s", tt.id)

			// Test length validation
			hasMinLength := len(tt.id) >= 8
			assert.Equal(t, tt.minLength, hasMinLength, "length validation mismatch for %s", tt.id)
		})
	}
}

// Helper function to test hex validation logic
func isValidHexForTest(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
			return false
		}
	}
	return true
}