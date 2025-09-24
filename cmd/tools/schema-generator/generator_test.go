// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePayloadDBStruct(t *testing.T) {
	tests := []struct {
		name           string
		expectError    bool
		expectedFields int
	}{
		{
			name:           "successful parsing",
			expectError:    false,
			expectedFields: 30, // Approximate number of fields in PayloadDB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePayloadDBStruct()

			if tt.expectError {
				assert.True(t, result.IsErr())
			} else {
				assert.True(t, result.IsOk())
				struct_info := result.Unwrap()
				assert.GreaterOrEqual(t, len(struct_info.Fields), tt.expectedFields)
				assert.Equal(t, "PayloadDB", struct_info.Name)
			}
		})
	}
}

func TestMapGoTypeToJSONSchema(t *testing.T) {
	tests := []struct {
		name         string
		goType       string
		expectedType string
		expectedFormat *string
	}{
		{
			name:         "string type",
			goType:       "string",
			expectedType: "string",
		},
		{
			name:         "UUID type",
			goType:       "uuid.UUID",
			expectedType: "string",
			expectedFormat: stringPtr("uuid"),
		},
		{
			name:         "time.Time type",
			goType:       "time.Time",
			expectedType: "string",
			expectedFormat: stringPtr("date-time"),
		},
		{
			name:         "pointer to time.Time",
			goType:       "*time.Time",
			expectedType: "string",
			expectedFormat: stringPtr("date-time"),
		},
		{
			name:         "int type",
			goType:       "int",
			expectedType: "integer",
		},
		{
			name:         "int64 type",
			goType:       "int64",
			expectedType: "integer",
		},
		{
			name:         "float64 type",
			goType:       "float64",
			expectedType: "number",
		},
		{
			name:         "bool type",
			goType:       "bool",
			expectedType: "boolean",
		},
		{
			name:         "slice of strings",
			goType:       "[]string",
			expectedType: "array",
		},
		{
			name:         "map[string]interface{}",
			goType:       "map[string]interface{}",
			expectedType: "object",
		},
		{
			name:         "custom enum type",
			goType:       "PayloadCategory",
			expectedType: "string",
		},
		{
			name:         "pointer to UUID",
			goType:       "*uuid.UUID",
			expectedType: "string",
			expectedFormat: stringPtr("uuid"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapGoTypeToJSONSchema(tt.goType)
			assert.True(t, result.IsOk())

			schemaType := result.Unwrap()
			assert.Equal(t, tt.expectedType, schemaType.Type)

			if tt.expectedFormat != nil {
				assert.Equal(t, *tt.expectedFormat, schemaType.Format)
			} else {
				assert.Empty(t, schemaType.Format)
			}
		})
	}
}

func TestDetectVersionChange(t *testing.T) {
	tests := []struct {
		name          string
		previousHash  string
		currentHash   string
		expectedBump  VersionBump
	}{
		{
			name:         "no previous hash - first version",
			previousHash: "",
			currentHash:  "abc123",
			expectedBump: VersionBumpMinor,
		},
		{
			name:         "no changes",
			previousHash: "abc123",
			currentHash:  "abc123",
			expectedBump: VersionBumpNone,
		},
		{
			name:         "changes detected",
			previousHash: "abc123",
			currentHash:  "def456",
			expectedBump: VersionBumpMinor, // Without breaking change analysis, default to minor
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectVersionChange(tt.previousHash, tt.currentHash)
			assert.True(t, result.IsOk())
			assert.Equal(t, tt.expectedBump, result.Unwrap())
		})
	}
}

func TestGenerateJSONSchema(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "schema-generator-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	outputPath := filepath.Join(tmpDir, "test_schema.json")

	result := generateJSONSchema(outputPath)
	assert.True(t, result.IsOk())

	// Verify the file was created
	assert.FileExists(t, outputPath)

	// Verify the content is valid JSON
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var schema map[string]interface{}
	err = json.Unmarshal(content, &schema)
	require.NoError(t, err)

	// Verify it's a valid JSON Schema
	assert.Equal(t, "http://json-schema.org/draft-07/schema#", schema["$schema"])
	assert.Equal(t, "object", schema["type"])
	assert.Contains(t, schema, "properties")
	assert.Contains(t, schema, "required")

	// Verify some key PayloadDB fields are present
	properties, ok := schema["properties"].(map[string]interface{})
	require.True(t, ok)

	assert.Contains(t, properties, "id")
	assert.Contains(t, properties, "name")
	assert.Contains(t, properties, "category")
	assert.Contains(t, properties, "domain")
	assert.Contains(t, properties, "content")
}

func TestValidateJSONField(t *testing.T) {
	tests := []struct {
		name        string
		fieldName   string
		jsonTag     string
		validateTag string
		expectError bool
	}{
		{
			name:        "valid required field",
			fieldName:   "name",
			jsonTag:     "name",
			validateTag: "required,min=1,max=255",
			expectError: false,
		},
		{
			name:        "optional field",
			fieldName:   "description",
			jsonTag:     "description,omitempty",
			validateTag: "",
			expectError: false,
		},
		{
			name:        "field with validation",
			fieldName:   "category",
			jsonTag:     "category",
			validateTag: "required",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field := FieldInfo{
				Name:        tt.fieldName,
				JSONTag:     tt.jsonTag,
				ValidateTag: tt.validateTag,
			}

			err := validateJSONField(field)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractValidationConstraints(t *testing.T) {
	tests := []struct {
		name         string
		validateTag  string
		expectedKeys []string
	}{
		{
			name:         "required field",
			validateTag:  "required",
			expectedKeys: []string{"required"},
		},
		{
			name:         "string with min/max",
			validateTag:  "required,min=1,max=255",
			expectedKeys: []string{"required", "minLength", "maxLength"},
		},
		{
			name:         "URL validation",
			validateTag:  "required,url",
			expectedKeys: []string{"required", "format"},
		},
		{
			name:         "numeric validation",
			validateTag:  "min=0",
			expectedKeys: []string{"minimum"},
		},
		{
			name:         "empty validation",
			validateTag:  "",
			expectedKeys: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraints := extractValidationConstraints(tt.validateTag)

			for _, key := range tt.expectedKeys {
				assert.Contains(t, constraints, key, "Expected constraint %s to be present", key)
			}
		})
	}
}

func TestCalculateStructHash(t *testing.T) {
	// Create a simple struct info for testing
	structInfo := StructInfo{
		Name: "TestStruct",
		Fields: []FieldInfo{
			{
				Name:    "ID",
				Type:    "uuid.UUID",
				JSONTag: "id",
			},
			{
				Name:        "Name",
				Type:        "string",
				JSONTag:     "name",
				ValidateTag: "required",
			},
		},
	}

	hash1 := calculateStructHash(structInfo)
	assert.NotEmpty(t, hash1)
	assert.Len(t, hash1, 64) // SHA-256 hash should be 64 characters

	// Same struct should produce same hash
	hash2 := calculateStructHash(structInfo)
	assert.Equal(t, hash1, hash2)

	// Different struct should produce different hash
	structInfo.Fields[0].Type = "string"
	hash3 := calculateStructHash(structInfo)
	assert.NotEqual(t, hash1, hash3)
}

func TestSchemaVersionGeneration(t *testing.T) {
	tests := []struct {
		name           string
		previousVersion string
		versionBump     VersionBump
		expectedVersion string
	}{
		{
			name:           "first version",
			previousVersion: "",
			versionBump:     VersionBumpMinor,
			expectedVersion: "1.0.0",
		},
		{
			name:           "patch bump",
			previousVersion: "1.0.0",
			versionBump:     VersionBumpPatch,
			expectedVersion: "1.0.1",
		},
		{
			name:           "minor bump",
			previousVersion: "1.0.0",
			versionBump:     VersionBumpMinor,
			expectedVersion: "1.1.0",
		},
		{
			name:           "major bump",
			previousVersion: "1.5.3",
			versionBump:     VersionBumpMajor,
			expectedVersion: "2.0.0",
		},
		{
			name:           "no bump",
			previousVersion: "1.2.3",
			versionBump:     VersionBumpNone,
			expectedVersion: "1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateNewVersion(tt.previousVersion, tt.versionBump)
			assert.True(t, result.IsOk())
			assert.Equal(t, tt.expectedVersion, result.Unwrap())
		})
	}
}

func TestSchemaMetadataGeneration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "schema-meta-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	schemaPath := filepath.Join(tmpDir, "test_schema.json")
	metaPath := filepath.Join(tmpDir, "schema_metadata.json")

	// First generate a schema
	result := generateJSONSchema(schemaPath)
	require.True(t, result.IsOk())

	// Generate metadata
	result = generateSchemaMetadata(metaPath, "1.0.0", "abc123")
	assert.True(t, result.IsOk())

	// Verify metadata file
	assert.FileExists(t, metaPath)

	content, err := os.ReadFile(metaPath)
	require.NoError(t, err)

	var metadata map[string]interface{}
	err = json.Unmarshal(content, &metadata)
	require.NoError(t, err)

	assert.Equal(t, "1.0.0", metadata["version"])
	assert.Equal(t, "abc123", metadata["modelHash"])
	assert.Contains(t, metadata, "generatedAt")
	assert.Contains(t, metadata, "gibsonVersion")
}

// Helper function to create string pointers for tests
func stringPtr(s string) *string {
	return &s
}

func TestIntegrationSchemaGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "schema-integration-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	schemaPath := filepath.Join(tmpDir, "payload_schema.json")

	// Test full schema generation workflow
	result := generateJSONSchema(schemaPath)
	assert.True(t, result.IsOk())

	// Verify schema file exists and has correct structure
	assert.FileExists(t, schemaPath)

	// Read and validate schema content
	content, err := os.ReadFile(schemaPath)
	require.NoError(t, err)

	var schema map[string]interface{}
	err = json.Unmarshal(content, &schema)
	require.NoError(t, err)

	// Validate schema structure
	assert.Equal(t, "http://json-schema.org/draft-07/schema#", schema["$schema"])
	assert.Equal(t, "object", schema["type"])

	properties, ok := schema["properties"].(map[string]interface{})
	require.True(t, ok)

	// Test critical PayloadDB fields are correctly mapped
	testFieldMapping(t, properties, "id", "string", "uuid")
	testFieldMapping(t, properties, "name", "string", "")
	testFieldMapping(t, properties, "category", "string", "")
	testFieldMapping(t, properties, "created_at", "string", "date-time")
	testFieldMapping(t, properties, "tags", "array", "")
	testFieldMapping(t, properties, "variables", "object", "")
}

func testFieldMapping(t *testing.T, properties map[string]interface{}, fieldName, expectedType, expectedFormat string) {
	field, exists := properties[fieldName]
	assert.True(t, exists, "Field %s should exist in schema", fieldName)

	fieldMap, ok := field.(map[string]interface{})
	assert.True(t, ok, "Field %s should be an object", fieldName)

	assert.Equal(t, expectedType, fieldMap["type"], "Field %s should have type %s", fieldName, expectedType)

	if expectedFormat != "" {
		assert.Equal(t, expectedFormat, fieldMap["format"], "Field %s should have format %s", fieldName, expectedFormat)
	}
}

func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		function    func() models.Result[interface{}]
		expectError bool
	}{
		{
			name: "invalid output path",
			function: func() models.Result[interface{}] {
				result := generateJSONSchema("/invalid/path/that/does/not/exist/schema.json")
				return models.Result[interface{}]{}.Error() // Convert for testing
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test error scenarios
			if tt.expectError {
				// Test that invalid paths are handled gracefully
				result := generateJSONSchema("/invalid/path")
				assert.True(t, result.IsErr())
			}
		})
	}
}
