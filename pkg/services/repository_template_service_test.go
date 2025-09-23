// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepositoryTemplateService(t *testing.T) {
	service := NewRepositoryTemplateService()
	assert.NotNil(t, service)
}

func TestDetectPluginDomains(t *testing.T) {
	tests := []struct {
		name             string
		setupFunc        func(string) error
		expectedDomains  []string
		expectError      bool
	}{
		{
			name: "plugins directory with domains",
			setupFunc: func(basePath string) error {
				pluginsDir := filepath.Join(basePath, "plugins")
				if err := os.MkdirAll(pluginsDir, 0755); err != nil {
					return err
				}
				// Create domain directories
				domains := []string{"model", "data", "interface", "infrastructure"}
				for _, domain := range domains {
					if err := os.MkdirAll(filepath.Join(pluginsDir, domain), 0755); err != nil {
						return err
					}
				}
				return nil
			},
			expectedDomains: []string{"data", "infrastructure", "interface", "model"}, // Should be sorted
			expectError:     false,
		},
		{
			name: "empty plugins directory - use defaults",
			setupFunc: func(basePath string) error {
				pluginsDir := filepath.Join(basePath, "plugins")
				return os.MkdirAll(pluginsDir, 0755)
			},
			expectedDomains: []string{"prompt", "model", "data", "interface", "infrastructure", "output", "process"}, // Default domains
			expectError:     false,
		},
		{
			name: "no plugins directory - use defaults",
			setupFunc: func(basePath string) error {
				return nil // Don't create plugins directory
			},
			expectedDomains: []string{"prompt", "model", "data", "interface", "infrastructure", "output", "process"}, // Default domains
			expectError:     false,
		},
		{
			name: "plugins directory with hidden directories",
			setupFunc: func(basePath string) error {
				pluginsDir := filepath.Join(basePath, "plugins")
				if err := os.MkdirAll(pluginsDir, 0755); err != nil {
					return err
				}
				// Create visible and hidden directories
				if err := os.MkdirAll(filepath.Join(pluginsDir, "model"), 0755); err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Join(pluginsDir, ".hidden"), 0755); err != nil {
					return err
				}
				return nil
			},
			expectedDomains: []string{"model"}, // Hidden directories should be excluded
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "domain-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			err = tt.setupFunc(tmpDir)
			require.NoError(t, err)

			// Change to the test directory to make plugins directory relative
			originalWd, err := os.Getwd()
			require.NoError(t, err)
			err = os.Chdir(tmpDir)
			require.NoError(t, err)
			defer os.Chdir(originalWd)

			service := NewRepositoryTemplateService()
			result := service.detectPluginDomains()

			if tt.expectError {
				assert.True(t, result.IsErr())
			} else {
				assert.True(t, result.IsOk())
				domains := result.Unwrap()
				assert.ElementsMatch(t, tt.expectedDomains, domains)
			}
		})
	}
}

func TestGenerateRepository(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		force       bool
		setupFunc   func(string) error
		expectError bool
		errorMsg    string
	}{
		{
			name:  "successful generation in new directory",
			path:  "new-repo",
			force: false,
			setupFunc: func(basePath string) error {
				return nil
			},
			expectError: false,
		},
		{
			name:  "successful generation with force overwrite",
			path:  "existing-repo",
			force: true,
			setupFunc: func(basePath string) error {
				// Create existing directory
				return os.MkdirAll(filepath.Join(basePath, "existing-repo"), 0755)
			},
			expectError: false,
		},
		{
			name:  "error when directory exists without force",
			path:  "existing-repo",
			force: false,
			setupFunc: func(basePath string) error {
				// Create existing directory
				return os.MkdirAll(filepath.Join(basePath, "existing-repo"), 0755)
			},
			expectError: true,
			errorMsg:    "already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "repo-generation-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			err = tt.setupFunc(tmpDir)
			require.NoError(t, err)

			repoPath := filepath.Join(tmpDir, tt.path)
			service := NewRepositoryTemplateService()
			result := service.GenerateRepository(repoPath, tt.force)

			if tt.expectError {
				assert.True(t, result.IsErr())
				if tt.errorMsg != "" {
					assert.Contains(t, result.Error().Error(), tt.errorMsg)
				}
			} else {
				assert.True(t, result.IsOk())
				// Verify directory structure was created
				verifyRepositoryStructure(t, repoPath)
			}
		})
	}
}

func TestGenerateManifest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "manifest-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	repoPath := filepath.Join(tmpDir, "test-repo")
	err = os.MkdirAll(repoPath, 0755)
	require.NoError(t, err)

	domains := []string{"model", "data", "interface"}
	service := NewRepositoryTemplateService()
	err = service.generateManifest(repoPath, domains)

	assert.NoError(t, err)

	// Verify manifest file was created
	manifestPath := filepath.Join(repoPath, "manifest.json")
	assert.FileExists(t, manifestPath)

	// Verify manifest content
	content, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	var manifest map[string]interface{}
	err = json.Unmarshal(content, &manifest)
	require.NoError(t, err)

	assert.Equal(t, "test-repository", manifest["name"])
	assert.Equal(t, "1.0.0", manifest["version"])
	assert.Contains(t, manifest, "gibsonVersion")
	assert.Contains(t, manifest, "domains")
	assert.Contains(t, manifest, "createdAt")

	// Verify domains are correctly set
	domainList, ok := manifest["domains"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, domainList, 3)
}

func TestGenerateCompatibility(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "compatibility-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	repoPath := filepath.Join(tmpDir, "test-repo")
	err = os.MkdirAll(repoPath, 0755)
	require.NoError(t, err)

	service := NewRepositoryTemplateService()
	err = service.generateCompatibility(repoPath)

	assert.NoError(t, err)

	// Verify compatibility file was created
	compatPath := filepath.Join(repoPath, "compatibility.json")
	assert.FileExists(t, compatPath)

	// Verify compatibility content
	content, err := os.ReadFile(compatPath)
	require.NoError(t, err)

	var compat map[string]interface{}
	err = json.Unmarshal(content, &compat)
	require.NoError(t, err)

	assert.Contains(t, compat, "schemaVersions")
	assert.Contains(t, compat, "gibsonVersions")
	assert.Contains(t, compat, "lastUpdated")

	// Verify current version is present
	schemaVersions, ok := compat["schemaVersions"].(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, schemaVersions, "1.0.0")
}

func TestGenerateSamplePayloads(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		expectedFields []string
	}{
		{
			name:           "model domain payload",
			domain:         "model",
			expectedFields: []string{"id", "name", "category", "domain", "type", "content"},
		},
		{
			name:           "data domain payload",
			domain:         "data",
			expectedFields: []string{"id", "name", "category", "domain", "type", "content"},
		},
		{
			name:           "interface domain payload",
			domain:         "interface",
			expectedFields: []string{"id", "name", "category", "domain", "type", "content"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "sample-payload-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			repoPath := filepath.Join(tmpDir, "test-repo")
			domainPath := filepath.Join(repoPath, tt.domain)
			err = os.MkdirAll(domainPath, 0755)
			require.NoError(t, err)

			service := NewRepositoryTemplateService()
			err = service.generateSamplePayloads(repoPath, []string{tt.domain})

			assert.NoError(t, err)

			// Verify sample payload file was created
			samplePath := filepath.Join(domainPath, "sample-"+tt.domain+".json")
			assert.FileExists(t, samplePath)

			// Verify sample payload content
			content, err := os.ReadFile(samplePath)
			require.NoError(t, err)

			var payload map[string]interface{}
			err = json.Unmarshal(content, &payload)
			require.NoError(t, err)

			// Verify required fields are present
			for _, field := range tt.expectedFields {
				assert.Contains(t, payload, field, "Field %s should be present in sample payload", field)
			}

			// Verify domain-specific content
			assert.Equal(t, tt.domain, payload["domain"])
			assert.NotEmpty(t, payload["content"])
			assert.NotEmpty(t, payload["name"])

			// Verify UUID format
			id, ok := payload["id"].(string)
			assert.True(t, ok)
			_, err = uuid.Parse(id)
			assert.NoError(t, err, "ID should be a valid UUID")
		})
	}
}

func TestCopySchema(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(string) error
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful copy",
			setupFunc: func(basePath string) error {
				// Create source schema file
				schemasDir := filepath.Join(basePath, "schemas")
				if err := os.MkdirAll(schemasDir, 0755); err != nil {
					return err
				}
				schemaContent := `{"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}`
				return os.WriteFile(filepath.Join(schemasDir, "payload_schema.json"), []byte(schemaContent), 0644)
			},
			expectError: false,
		},
		{
			name: "missing source schema",
			setupFunc: func(basePath string) error {
				return nil // Don't create schema file
			},
			expectError: true,
			errorMsg:    "no such file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "copy-schema-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			err = tt.setupFunc(tmpDir)
			require.NoError(t, err)

			repoPath := filepath.Join(tmpDir, "test-repo")
			err = os.MkdirAll(filepath.Join(repoPath, "schemas"), 0755)
			require.NoError(t, err)

			// Change to the test directory to make schema path relative
			originalWd, err := os.Getwd()
			require.NoError(t, err)
			err = os.Chdir(tmpDir)
			require.NoError(t, err)
			defer os.Chdir(originalWd)

			service := NewRepositoryTemplateService()
			err = service.copySchema(repoPath)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				// Verify schema was copied
				destPath := filepath.Join(repoPath, "schemas", "payload_schema.json")
				assert.FileExists(t, destPath)
			}
		})
	}
}

func TestGenerateREADME(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "readme-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	repoPath := filepath.Join(tmpDir, "test-repo")
	err = os.MkdirAll(repoPath, 0755)
	require.NoError(t, err)

	domains := []string{"model", "data", "interface"}
	service := NewRepositoryTemplateService()
	err = service.generateREADME(repoPath, domains)

	assert.NoError(t, err)

	// Verify README file was created
	readmePath := filepath.Join(repoPath, "README.md")
	assert.FileExists(t, readmePath)

	// Verify README content
	content, err := os.ReadFile(readmePath)
	require.NoError(t, err)

	readmeContent := string(content)
	assert.Contains(t, readmeContent, "test-repository")
	assert.Contains(t, readmeContent, "# Repository Structure")
	assert.Contains(t, readmeContent, "# Adding Payloads")
	assert.Contains(t, readmeContent, "# Schema Validation")
	assert.Contains(t, readmeContent, "Gibson Framework")

	// Verify domain-specific content
	for _, domain := range domains {
		assert.Contains(t, readmeContent, domain)
	}
}

func TestServiceIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "service-integration-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create mock schema file
	schemasDir := filepath.Join(tmpDir, "schemas")
	err = os.MkdirAll(schemasDir, 0755)
	require.NoError(t, err)

	schemaContent := `{
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "object",
	"properties": {
		"id": {"type": "string", "format": "uuid"},
		"name": {"type": "string"}
	},
	"required": ["id", "name"]
}`
	err = os.WriteFile(filepath.Join(schemasDir, "payload_schema.json"), []byte(schemaContent), 0644)
	require.NoError(t, err)

	// Create mock plugins directory
	pluginsDir := filepath.Join(tmpDir, "plugins")
	err = os.MkdirAll(pluginsDir, 0755)
	require.NoError(t, err)

	domains := []string{"model", "data"}
	for _, domain := range domains {
		err = os.MkdirAll(filepath.Join(pluginsDir, domain), 0755)
		require.NoError(t, err)
	}

	// Test full repository generation
	repoPath := filepath.Join(tmpDir, "integration-test-repo")
	service := NewRepositoryTemplateService()

	// Change working directory to tmpDir for relative path resolution
	originalWd, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer os.Chdir(originalWd)

	result := service.GenerateRepository(repoPath, false)
	assert.True(t, result.IsOk())

	// Verify complete repository structure
	verifyCompleteRepositoryStructure(t, repoPath, domains)
}

func TestDomainSpecificSampleContent(t *testing.T) {
	tests := []struct {
		domain           string
		expectedCategory string
		expectedType     string
		contentKeywords  []string
	}{
		{
			domain:           "model",
			expectedCategory: "model",
			expectedType:     "prompt",
			contentKeywords:  []string{"model", "extraction", "jailbreak"},
		},
		{
			domain:           "data",
			expectedCategory: "data",
			expectedType:     "query",
			contentKeywords:  []string{"data", "injection", "poisoning"},
		},
		{
			domain:           "interface",
			expectedCategory: "interface",
			expectedType:     "input",
			contentKeywords:  []string{"prompt", "injection", "bypass"},
		},
		{
			domain:           "infrastructure",
			expectedCategory: "infrastructure",
			expectedType:     "script",
			contentKeywords:  []string{"infrastructure", "attack", "deployment"},
		},
		{
			domain:           "output",
			expectedCategory: "output",
			expectedType:     "prompt",
			contentKeywords:  []string{"output", "manipulation", "bias"},
		},
		{
			domain:           "process",
			expectedCategory: "process",
			expectedType:     "code",
			contentKeywords:  []string{"process", "manipulation", "workflow"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.domain+" domain", func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "domain-content-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			repoPath := filepath.Join(tmpDir, "test-repo")
			domainPath := filepath.Join(repoPath, tt.domain)
			err = os.MkdirAll(domainPath, 0755)
			require.NoError(t, err)

			service := NewRepositoryTemplateService()
			err = service.generateSamplePayloads(repoPath, []string{tt.domain})
			assert.NoError(t, err)

			// Read and verify sample content
			samplePath := filepath.Join(domainPath, "sample-"+tt.domain+".json")
			content, err := os.ReadFile(samplePath)
			require.NoError(t, err)

			var payload map[string]interface{}
			err = json.Unmarshal(content, &payload)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedCategory, payload["category"])
			assert.Equal(t, tt.expectedType, payload["type"])

			content_str, ok := payload["content"].(string)
			assert.True(t, ok)

			// Check that content contains domain-specific keywords
			found := false
			for _, keyword := range tt.contentKeywords {
				if contains := containsIgnoreCase(content_str, keyword); contains {
					found = true
					break
				}
			}
			assert.True(t, found, "Content should contain at least one keyword from %v", tt.contentKeywords)
		})
	}
}

// Helper functions for testing

func verifyRepositoryStructure(t *testing.T, repoPath string) {
	// Verify main files
	assert.FileExists(t, filepath.Join(repoPath, "manifest.json"))
	assert.FileExists(t, filepath.Join(repoPath, "compatibility.json"))
	assert.FileExists(t, filepath.Join(repoPath, "README.md"))

	// Verify directories
	assert.DirExists(t, filepath.Join(repoPath, "schemas"))

	// Check for at least one domain directory
	entries, err := os.ReadDir(repoPath)
	require.NoError(t, err)

	domainFound := false
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "schemas" && !startsWithDot(entry.Name()) {
			domainFound = true
			break
		}
	}
	assert.True(t, domainFound, "At least one domain directory should be created")
}

func verifyCompleteRepositoryStructure(t *testing.T, repoPath string, expectedDomains []string) {
	verifyRepositoryStructure(t, repoPath)

	// Verify schema was copied
	assert.FileExists(t, filepath.Join(repoPath, "schemas", "payload_schema.json"))

	// Verify domain directories and sample payloads
	for _, domain := range expectedDomains {
		domainPath := filepath.Join(repoPath, domain)
		assert.DirExists(t, domainPath)
		assert.FileExists(t, filepath.Join(domainPath, "sample-"+domain+".json"))
	}
}

func startsWithDot(name string) bool {
	return len(name) > 0 && name[0] == '.'
}

func containsIgnoreCase(s, substr string) bool {
	return contains(strings.ToLower(s), strings.ToLower(substr))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOfSubstring(s, substr) >= 0)
}

func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Mock functions for testing error scenarios

func TestErrorScenarios(t *testing.T) {
	tests := []struct {
		name        string
		testFunc    func(*testing.T)
	}{
		{
			name: "invalid permissions",
			testFunc: testInvalidPermissions,
		},
		{
			name: "invalid JSON generation",
			testFunc: testInvalidJSONGeneration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}

func testInvalidPermissions(t *testing.T) {
	// Test with read-only directory (Unix-like systems)
	if os.Getenv("CI") != "" {
		t.Skip("Skipping permission test in CI environment")
	}

	tmpDir, err := os.MkdirTemp("", "permission-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create read-only directory
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err = os.MkdirAll(readOnlyDir, 0444) // Read-only
	require.NoError(t, err)

	repoPath := filepath.Join(readOnlyDir, "test-repo")
	service := NewRepositoryTemplateService()
	result := service.GenerateRepository(repoPath, false)

	assert.True(t, result.IsErr())
	assert.Contains(t, result.Error().Error(), "permission")
}

func testInvalidJSONGeneration(t *testing.T) {
	// Test JSON marshaling error scenario
	tmpDir, err := os.MkdirTemp("", "json-error-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	repoPath := filepath.Join(tmpDir, "test-repo")
	err = os.MkdirAll(repoPath, 0755)
	require.NoError(t, err)

	service := NewRepositoryTemplateService()

	// Create a manifest with invalid data that should cause JSON marshaling to work
	// (This is mainly to test the structure, actual JSON marshaling rarely fails with basic types)
	err = service.generateManifest(repoPath, []string{"model"})
	assert.NoError(t, err) // Should succeed with valid data
}

func TestPayloadValidation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "validation-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	repoPath := filepath.Join(tmpDir, "test-repo")
	domainPath := filepath.Join(repoPath, "model")
	err = os.MkdirAll(domainPath, 0755)
	require.NoError(t, err)

	service := NewRepositoryTemplateService()
	err = service.generateSamplePayloads(repoPath, []string{"model"})
	assert.NoError(t, err)

	// Read generated payload
	samplePath := filepath.Join(domainPath, "sample-model.json")
	content, err := os.ReadFile(samplePath)
	require.NoError(t, err)

	var payload models.PayloadDB
	err = json.Unmarshal(content, &payload)
	require.NoError(t, err)

	// Validate payload using model validation
	err = payload.Validate()
	assert.NoError(t, err, "Generated sample payload should pass validation")

	// Verify required fields are set
	assert.NotEqual(t, uuid.Nil, payload.ID)
	assert.NotEmpty(t, payload.Name)
	assert.NotEmpty(t, payload.Domain)
	assert.NotEmpty(t, payload.Content)
	assert.True(t, payload.Enabled)
}
