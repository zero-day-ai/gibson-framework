// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSchemaValidatorFromSchema(t *testing.T) {
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":   "string",
				"format": "uuid",
			},
			"name": map[string]interface{}{
				"type": "string",
			},
		},
		"required": []string{"id", "name"},
	}

	validator := NewSchemaValidatorFromSchema(schema)
	assert.NotNil(t, validator)
}

func TestSchemaValidator_ValidatePayload(t *testing.T) {
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":   "string",
				"format": "uuid",
			},
			"name": map[string]interface{}{
				"type":      "string",
				"minLength": 1,
				"maxLength": 100,
			},
			"category": map[string]interface{}{
				"type": "string",
				"enum": []string{"model", "data", "interface"},
			},
		},
		"required": []string{"id", "name"},
	}

	validator := NewSchemaValidatorFromSchema(schema)

	tests := []struct {
		name    string
		payload map[string]interface{}
		valid   bool
		errorCount int
	}{
		{
			name: "valid payload",
			payload: map[string]interface{}{
				"id":       uuid.New().String(),
				"name":     "test-payload",
				"category": "model",
			},
			valid:      true,
			errorCount: 0,
		},
		{
			name: "missing required field",
			payload: map[string]interface{}{
				"id": uuid.New().String(),
				// name is missing
			},
			valid:      false,
			errorCount: 1,
		},
		{
			name: "invalid UUID format",
			payload: map[string]interface{}{
				"id":   "not-a-uuid",
				"name": "test-payload",
			},
			valid:      false,
			errorCount: 1,
		},
		{
			name: "invalid enum value",
			payload: map[string]interface{}{
				"id":       uuid.New().String(),
				"name":     "test-payload",
				"category": "invalid-category",
			},
			valid:      false,
			errorCount: 1,
		},
		{
			name: "string too long",
			payload: map[string]interface{}{
				"id":   uuid.New().String(),
				"name": "this-is-a-very-long-name-that-exceeds-the-maximum-length-limit-of-one-hundred-characters-set-in-schema",
			},
			valid:      false,
			errorCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidatePayload(tt.payload)
			assert.True(t, result.IsOk())

			validationResult := result.Unwrap()
			assert.Equal(t, tt.valid, validationResult.Valid)
			assert.Len(t, validationResult.Errors, tt.errorCount)
		})
	}
}

func TestSchemaValidator_ValidatePayloadDB(t *testing.T) {
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":   "string",
				"format": "uuid",
			},
			"name": map[string]interface{}{
				"type": "string",
			},
			"domain": map[string]interface{}{
				"type": "string",
			},
			"content": map[string]interface{}{
				"type": "string",
			},
		},
		"required": []string{"id", "name", "domain", "content"},
	}

	validator := NewSchemaValidatorFromSchema(schema)

	// Create a valid PayloadDB
	payload := &models.PayloadDB{
		ID:       uuid.New(),
		Name:     "test-payload",
		Domain:   "model",
		Category: models.PayloadCategoryModel,
		Type:     models.PayloadTypePrompt,
		Content:  "test content",
		Enabled:  true,
	}
	payload.SetDefaults()

	result := validator.ValidatePayloadDB(payload)
	assert.True(t, result.IsOk())

	validationResult := result.Unwrap()
	assert.True(t, validationResult.Valid)
	assert.Empty(t, validationResult.Errors)
}

func TestSchemaValidator_ValidatePayloadJSON(t *testing.T) {
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":   "string",
				"format": "uuid",
			},
			"name": map[string]interface{}{
				"type": "string",
			},
		},
		"required": []string{"id", "name"},
	}

	validator := NewSchemaValidatorFromSchema(schema)

	tests := []struct {
		name    string
		json    string
		valid   bool
		errorCount int
	}{
		{
			name: "valid JSON payload",
			json: `{"id": "` + uuid.New().String() + `", "name": "test"}`,
			valid: true,
			errorCount: 0,
		},
		{
			name: "invalid JSON",
			json: `{"id": "` + uuid.New().String() + `", "name": "test", invalid}`,
			valid: false, // Will fail at JSON parsing
			errorCount: 0, // Error happens during JSON unmarshal, not validation
		},
		{
			name: "missing required field",
			json: `{"id": "` + uuid.New().String() + `"}`,
			valid: false,
			errorCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidatePayloadJSON([]byte(tt.json))
			
			if tt.name == "invalid JSON" {
				// This should fail at JSON parsing stage
				assert.True(t, result.IsErr())
			} else {
				assert.True(t, result.IsOk())
				validationResult := result.Unwrap()
				assert.Equal(t, tt.valid, validationResult.Valid)
				assert.Len(t, validationResult.Errors, tt.errorCount)
			}
		})
	}
}

func TestNewSchemaValidator_FromFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "schema-validator-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a valid schema file
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":   "string",
				"format": "uuid",
			},
		},
		"required": []string{"id"},
	}

	schemaPath := filepath.Join(tmpDir, "test_schema.json")
	file, err := os.Create(schemaPath)
	require.NoError(t, err)
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(schema)
	require.NoError(t, err)

	// Test loading from file
	result := NewSchemaValidator(schemaPath)
	assert.True(t, result.IsOk())

	validator := result.Unwrap()
	assert.NotNil(t, validator)

	// Test with non-existent file
	result = NewSchemaValidator("/path/that/does/not/exist.json")
	assert.True(t, result.IsErr())
}

func TestSchemaValidator_GetSchemaInfo(t *testing.T) {
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"title":   "Test Schema",
		"properties": map[string]interface{}{
			"id":   map[string]interface{}{"type": "string"},
			"name": map[string]interface{}{"type": "string"},
		},
		"required": []string{"id"},
	}

	validator := NewSchemaValidatorFromSchema(schema)
	result := validator.GetSchemaInfo()
	assert.True(t, result.IsOk())

	info := result.Unwrap()
	assert.Equal(t, "http://json-schema.org/draft-07/schema#", info["$schema"])
	assert.Equal(t, "object", info["type"])
	assert.Equal(t, "Test Schema", info["title"])
	assert.Equal(t, 2, info["fieldCount"])

	fields, ok := info["fields"].([]string)
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"id", "name"}, fields)
}

func TestValidatePayloadFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "payload-file-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create schema file
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"properties": map[string]interface{}{
			"id":   map[string]interface{}{"type": "string", "format": "uuid"},
			"name": map[string]interface{}{"type": "string"},
		},
		"required": []string{"id", "name"},
	}

	schemaPath := filepath.Join(tmpDir, "schema.json")
	schemaFile, err := os.Create(schemaPath)
	require.NoError(t, err)
	json.NewEncoder(schemaFile).Encode(schema)
	schemaFile.Close()

	// Create valid payload file
	validPayload := map[string]interface{}{
		"id":   uuid.New().String(),
		"name": "test-payload",
	}

	payloadPath := filepath.Join(tmpDir, "payload.json")
	payloadFile, err := os.Create(payloadPath)
	require.NoError(t, err)
	json.NewEncoder(payloadFile).Encode(validPayload)
	payloadFile.Close()

	// Test validation
	result := ValidatePayloadFile(schemaPath, payloadPath)
	assert.True(t, result.IsOk())

	validationResult := result.Unwrap()
	assert.True(t, validationResult.Valid)
	assert.Empty(t, validationResult.Errors)
}

func TestFormatValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		errors []ValidationError
		expect string
	}{
		{
			name:   "no errors",
			errors: []ValidationError{},
			expect: "No validation errors",
		},
		{
			name: "single error",
			errors: []ValidationError{
				{Field: "name", Message: "required field is missing"},
			},
			expect: "Found 1 validation error(s):\n  1. validation error at field 'name': required field is missing\n",
		},
		{
			name: "multiple errors",
			errors: []ValidationError{
				{Field: "name", Message: "required field is missing"},
				{Field: "id", Message: "invalid UUID format", Value: "not-a-uuid"},
			},
			expect: "Found 2 validation error(s):\n  1. validation error at field 'name': required field is missing\n  2. validation error at field 'id': invalid UUID format\n     Value: not-a-uuid\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatValidationErrors(tt.errors)
			assert.Equal(t, tt.expect, result)
		})
	}
}
