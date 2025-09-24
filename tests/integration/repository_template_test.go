// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRepositoryTemplateGenerationE2E tests the complete end-to-end workflow
// of repository template generation using the gibson CLI command
func TestRepositoryTemplateGenerationE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test environment
	tmpDir, err := os.MkdirTemp("", "gibson-e2e-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Build Gibson binary for testing
	gibsonBinary := buildGibsonBinary(t, tmpDir)

	// Test repository generation
	repoPath := filepath.Join(tmpDir, "test-payload-repo")

	// Execute gibson payloads repository generate-template command
	cmd := exec.Command(gibsonBinary, "payload", "repository", "generate-template", repoPath)
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Command failed with output: %s", string(output))

	// Verify command output
	outputStr := string(output)
	assert.Contains(t, outputStr, "Repository template generated successfully")
	assert.Contains(t, outputStr, "manifest.json")
	assert.Contains(t, outputStr, "compatibility.json")
	assert.Contains(t, outputStr, "schemas/")

	// Verify repository structure was created
	verifyRepositoryStructure(t, repoPath)

	// Verify manifest.json content
	verifyManifestContent(t, repoPath)

	// Verify compatibility.json content
	verifyCompatibilityContent(t, repoPath)

	// Verify sample payloads were generated
	verifyGeneratedSamplePayloads(t, repoPath)

	// Verify schema validation works
	verifySchemaValidation(t, repoPath)

	// Verify README.md content
	verifyREADMEContent(t, repoPath)
}

// TestRepositoryTemplateGenerationWithForce tests overwriting existing repositories
func TestRepositoryTemplateGenerationWithForce(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "gibson-force-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	gibsonBinary := buildGibsonBinary(t, tmpDir)
	repoPath := filepath.Join(tmpDir, "existing-repo")

	// Create existing directory with some content
	err = os.MkdirAll(repoPath, 0755)
	require.NoError(t, err)
	existingFile := filepath.Join(repoPath, "existing-file.txt")
	err = os.WriteFile(existingFile, []byte("existing content"), 0644)
	require.NoError(t, err)

	// Test without force - should fail
	cmd := exec.Command(gibsonBinary, "payload", "repository", "generate-template", repoPath)
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	assert.Error(t, err, "Command should fail without --force")
	assert.Contains(t, string(output), "already exists")

	// Test with force - should succeed
	cmd = exec.Command(gibsonBinary, "payload", "repository", "generate-template", repoPath, "--force")
	cmd.Dir = tmpDir
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Command failed with output: %s", string(output))

	// Verify repository was created
	verifyRepositoryStructure(t, repoPath)
}

// TestRepositoryTemplateOutputFormats tests different output formats
func TestRepositoryTemplateOutputFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name         string
		outputFlag   string
		verifyFunc   func(*testing.T, string)
	}{
		{
			name:       "JSON output format",
			outputFlag: "json",
			verifyFunc: verifyJSONOutput,
		},
		{
			name:       "YAML output format",
			outputFlag: "yaml",
			verifyFunc: verifyYAMLOutput,
		},
		{
			name:       "Table output format (default)",
			outputFlag: "table",
			verifyFunc: verifyTableOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "gibson-output-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			gibsonBinary := buildGibsonBinary(t, tmpDir)
			repoPath := filepath.Join(tmpDir, "output-test-repo")

			cmd := exec.Command(gibsonBinary, "payload", "repository", "generate-template", repoPath, "--output", tt.outputFlag)
			cmd.Dir = tmpDir
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "Command failed with output: %s", string(output))

			tt.verifyFunc(t, string(output))
		})
	}
}

// TestSchemaValidationIntegration tests schema validation of generated payloads
func TestSchemaValidationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "gibson-schema-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	gibsonBinary := buildGibsonBinary(t, tmpDir)
	repoPath := filepath.Join(tmpDir, "schema-test-repo")

	// Generate repository
	cmd := exec.Command(gibsonBinary, "payload", "repository", "generate-template", repoPath)
	cmd.Dir = tmpDir
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)

	// Test each domain's sample payload
	domainDirs, err := os.ReadDir(repoPath)
	require.NoError(t, err)

	for _, dir := range domainDirs {
		if !dir.IsDir() || dir.Name() == "schemas" || strings.HasPrefix(dir.Name(), ".") {
			continue
		}

		domainName := dir.Name()
		t.Run("validate_"+domainName+"_payload", func(t *testing.T) {
			samplePath := filepath.Join(repoPath, domainName, "sample-"+domainName+".json")
			assert.FileExists(t, samplePath)

			// Read and validate sample payload
			content, err := os.ReadFile(samplePath)
			require.NoError(t, err)

			var payload models.PayloadDB
			err = json.Unmarshal(content, &payload)
			require.NoError(t, err, "Sample payload should be valid JSON")

			// Validate using PayloadDB validation
			err = payload.Validate()
			assert.NoError(t, err, "Sample payload should pass model validation")

			// Verify domain-specific requirements
			assert.Equal(t, domainName, payload.Domain)
			assert.NotEmpty(t, payload.Content)
			assert.NotEqual(t, uuid.Nil, payload.ID)
			assert.True(t, payload.Enabled)
		})
	}
}

// TestRepositoryImportWorkflow tests the complete workflow from generation to import
func TestRepositoryImportWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "gibson-import-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	gibsonBinary := buildGibsonBinary(t, tmpDir)
	repoPath := filepath.Join(tmpDir, "import-test-repo")

	// Step 1: Generate repository template
	cmd := exec.Command(gibsonBinary, "payload", "repository", "generate-template", repoPath)
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Template generation failed: %s", string(output))

	// Step 2: Initialize git repository (simulating a real payload repository)
	initializeGitRepo(t, repoPath)

	// Step 3: Verify generated structure meets repository requirements
	verifyRepositoryForImport(t, repoPath)

	// Step 4: Test that all files are properly formatted and valid
	verifyFilesForImport(t, repoPath)
}

// TestErrorHandlingIntegration tests error scenarios
func TestErrorHandlingIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name          string
		args          []string
		setupFunc     func(string) error
		expectError   bool
		errorContains string
	}{
		{
			name:          "missing arguments",
			args:          []string{"payload", "repository", "generate-template"},
			expectError:   true,
			errorContains: "required",
		},
		{
			name: "invalid path permissions",
			args: []string{"payload", "repository", "generate-template", "/root/forbidden"},
			setupFunc: func(tmpDir string) error {
				return nil // No setup needed
			},
			expectError:   true,
			errorContains: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "gibson-error-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			gibsonBinary := buildGibsonBinary(t, tmpDir)

			if tt.setupFunc != nil {
				err = tt.setupFunc(tmpDir)
				require.NoError(t, err)
			}

			cmd := exec.Command(gibsonBinary, tt.args...)
			cmd.Dir = tmpDir
			output, err := cmd.CombinedOutput()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, strings.ToLower(string(output)), strings.ToLower(tt.errorContains))
				}
			} else {
				assert.NoError(t, err, "Command output: %s", string(output))
			}
		})
	}
}

// Helper functions

func buildGibsonBinary(t *testing.T, tmpDir string) string {
	// Build Gibson binary for testing
	binaryPath := filepath.Join(tmpDir, "gibson")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/gibson")

	// Get the project root directory
	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Join(wd, "../..")
	buildCmd.Dir = projectRoot

	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "Failed to build Gibson binary: %s", string(output))

	return binaryPath
}

func verifyRepositoryStructure(t *testing.T, repoPath string) {
	// Verify main files exist
	assert.FileExists(t, filepath.Join(repoPath, "manifest.json"))
	assert.FileExists(t, filepath.Join(repoPath, "compatibility.json"))
	assert.FileExists(t, filepath.Join(repoPath, "README.md"))

	// Verify schemas directory exists
	schemasDir := filepath.Join(repoPath, "schemas")
	assert.DirExists(t, schemasDir)

	// Verify at least one domain directory exists
	entries, err := os.ReadDir(repoPath)
	require.NoError(t, err)

	domainCount := 0
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "schemas" && !strings.HasPrefix(entry.Name(), ".") {
			domainCount++
			// Verify domain has sample payload
			samplePath := filepath.Join(repoPath, entry.Name(), "sample-"+entry.Name()+".json")
			assert.FileExists(t, samplePath)
		}
	}
	assert.Greater(t, domainCount, 0, "At least one domain directory should exist")
}

func verifyManifestContent(t *testing.T, repoPath string) {
	manifestPath := filepath.Join(repoPath, "manifest.json")
	content, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	var manifest map[string]interface{}
	err = json.Unmarshal(content, &manifest)
	require.NoError(t, err)

	// Verify required fields
	assert.Contains(t, manifest, "name")
	assert.Contains(t, manifest, "version")
	assert.Contains(t, manifest, "gibsonVersion")
	assert.Contains(t, manifest, "domains")
	assert.Contains(t, manifest, "createdAt")

	// Verify version format
	version, ok := manifest["version"].(string)
	assert.True(t, ok)
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, version, "Version should follow semver format")

	// Verify domains is an array
	domains, ok := manifest["domains"].([]interface{})
	assert.True(t, ok)
	assert.Greater(t, len(domains), 0, "At least one domain should be listed")
}

func verifyCompatibilityContent(t *testing.T, repoPath string) {
	compatPath := filepath.Join(repoPath, "compatibility.json")
	content, err := os.ReadFile(compatPath)
	require.NoError(t, err)

	var compat map[string]interface{}
	err = json.Unmarshal(content, &compat)
	require.NoError(t, err)

	// Verify required fields
	assert.Contains(t, compat, "schemaVersions")
	assert.Contains(t, compat, "gibsonVersions")
	assert.Contains(t, compat, "lastUpdated")

	// Verify schema versions structure
	schemaVersions, ok := compat["schemaVersions"].(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, schemaVersions, "1.0.0", "Initial schema version should be present")
}

func verifyGeneratedSamplePayloads(t *testing.T, repoPath string) {
	entries, err := os.ReadDir(repoPath)
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "schemas" || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		domainName := entry.Name()
		samplePath := filepath.Join(repoPath, domainName, "sample-"+domainName+".json")
		assert.FileExists(t, samplePath, "Sample payload should exist for domain %s", domainName)

		// Verify sample payload is valid JSON
		content, err := os.ReadFile(samplePath)
		require.NoError(t, err)

		var payload map[string]interface{}
		err = json.Unmarshal(content, &payload)
		assert.NoError(t, err, "Sample payload should be valid JSON for domain %s", domainName)

		// Verify required fields
		assert.Equal(t, domainName, payload["domain"])
		assert.NotEmpty(t, payload["id"])
		assert.NotEmpty(t, payload["name"])
		assert.NotEmpty(t, payload["content"])
	}
}

func verifySchemaValidation(t *testing.T, repoPath string) {
	// This is a basic check - in a real implementation, you would use a JSON Schema validator
	schemasDir := filepath.Join(repoPath, "schemas")
	assert.DirExists(t, schemasDir)

	// Check if schema files exist (would be copied from main schemas directory)
	schemaFiles, err := os.ReadDir(schemasDir)
	require.NoError(t, err)

	// At minimum, there should be a way to validate payloads
	// In practice, this would involve copying the current payload schema
	if len(schemaFiles) > 0 {
		for _, file := range schemaFiles {
			if strings.HasSuffix(file.Name(), ".json") {
				schemaPath := filepath.Join(schemasDir, file.Name())
				content, err := os.ReadFile(schemaPath)
				require.NoError(t, err)

				var schema map[string]interface{}
				err = json.Unmarshal(content, &schema)
				assert.NoError(t, err, "Schema file should be valid JSON")
			}
		}
	}
}

func verifyREADMEContent(t *testing.T, repoPath string) {
	readmePath := filepath.Join(repoPath, "README.md")
	content, err := os.ReadFile(readmePath)
	require.NoError(t, err)

	readmeContent := string(content)

	// Verify key sections are present
	assert.Contains(t, readmeContent, "# Repository Structure")
	assert.Contains(t, readmeContent, "# Adding Payloads")
	assert.Contains(t, readmeContent, "# Schema Validation")
	assert.Contains(t, readmeContent, "Gibson Framework")
	assert.Contains(t, readmeContent, "manifest.json")
	assert.Contains(t, readmeContent, "compatibility.json")
}

func verifyJSONOutput(t *testing.T, output string) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(output), &result)
	assert.NoError(t, err, "Output should be valid JSON")

	assert.Equal(t, "success", result["status"])
	assert.Contains(t, result, "message")
	assert.Contains(t, result, "path")
	assert.Contains(t, result, "timestamp")
}

func verifyYAMLOutput(t *testing.T, output string) {
	// Basic YAML verification - should contain key-value pairs
	assert.Contains(t, output, "status:")
	assert.Contains(t, output, "message:")
	assert.Contains(t, output, "path:")
	assert.Contains(t, output, "timestamp:")
}

func verifyTableOutput(t *testing.T, output string) {
	// Table output should contain human-readable success message
	assert.Contains(t, output, "Repository template generated successfully")
	assert.Contains(t, output, "manifest.json")
	assert.Contains(t, output, "Next steps:")
}

func initializeGitRepo(t *testing.T, repoPath string) {
	// Initialize git repository for testing import workflow
	cmd := exec.Command("git", "init")
	cmd.Dir = repoPath
	_, err := cmd.CombinedOutput()
	require.NoError(t, err)

	// Configure git user for testing
	cmd = exec.Command("git", "config", "user.email", "test@gibson.local")
	cmd.Dir = repoPath
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)

	cmd = exec.Command("git", "config", "user.name", "Gibson Test")
	cmd.Dir = repoPath
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)

	// Add and commit all files
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = repoPath
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)

	cmd = exec.Command("git", "commit", "-m", "Initial payload repository template")
	cmd.Dir = repoPath
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)
}

func verifyRepositoryForImport(t *testing.T, repoPath string) {
	// Verify all required files for Gibson import are present
	requiredFiles := []string{
		"manifest.json",
		"compatibility.json",
		"README.md",
	}

	for _, file := range requiredFiles {
		filePath := filepath.Join(repoPath, file)
		assert.FileExists(t, filePath, "Required file %s should exist for import", file)
	}

	// Verify schemas directory structure
	schemasDir := filepath.Join(repoPath, "schemas")
	assert.DirExists(t, schemasDir)

	// Verify domain directories contain valid payloads
	entries, err := os.ReadDir(repoPath)
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "schemas" && !strings.HasPrefix(entry.Name(), ".") {
			domainDir := filepath.Join(repoPath, entry.Name())
			sampleFile := filepath.Join(domainDir, "sample-"+entry.Name()+".json")
			assert.FileExists(t, sampleFile)
		}
	}
}

func verifyFilesForImport(t *testing.T, repoPath string) {
	// Verify all JSON files are properly formatted
	jsonFiles := []string{
		filepath.Join(repoPath, "manifest.json"),
		filepath.Join(repoPath, "compatibility.json"),
	}

	// Add domain sample files
	entries, err := os.ReadDir(repoPath)
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "schemas" && !strings.HasPrefix(entry.Name(), ".") {
			sampleFile := filepath.Join(repoPath, entry.Name(), "sample-"+entry.Name()+".json")
			if _, err := os.Stat(sampleFile); err == nil {
				jsonFiles = append(jsonFiles, sampleFile)
			}
		}
	}

	// Verify each JSON file is valid
	for _, jsonFile := range jsonFiles {
		content, err := os.ReadFile(jsonFile)
		require.NoError(t, err, "Should be able to read %s", jsonFile)

		var parsed interface{}
		err = json.Unmarshal(content, &parsed)
		assert.NoError(t, err, "File %s should contain valid JSON", jsonFile)
	}

	// Verify README.md is readable
	readmePath := filepath.Join(repoPath, "README.md")
	content, err := os.ReadFile(readmePath)
	require.NoError(t, err)
	assert.Greater(t, len(content), 100, "README should have substantial content")
}

// TestRepositoryTemplatePerformance tests the performance of repository generation
func TestRepositoryTemplatePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "gibson-perf-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	gibsonBinary := buildGibsonBinary(t, tmpDir)

	// Test multiple repository generations to check for performance regressions
	for i := 0; i < 5; i++ {
		repoPath := filepath.Join(tmpDir, fmt.Sprintf("perf-test-repo-%d", i))

		start := time.Now()
		cmd := exec.Command(gibsonBinary, "payload", "repository", "generate-template", repoPath)
		cmd.Dir = tmpDir
		_, err := cmd.CombinedOutput()
		require.NoError(t, err)
		duration := time.Since(start)

		// Repository generation should complete in reasonable time
		assert.Less(t, duration, 30*time.Second, "Repository generation should complete within 30 seconds")

		// Verify structure is correct
		verifyRepositoryStructure(t, repoPath)
	}
}
