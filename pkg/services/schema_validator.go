// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/google/uuid"
)

// SchemaValidator provides payload validation against JSON Schema
type SchemaValidator struct {
	schema map[string]interface{}
}

// ValidationError represents a schema validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error at field '%s': %s", e.Field, e.Message)
}

// ValidationResult contains the results of schema validation
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// NewSchemaValidator creates a new schema validator by loading the schema from file
func NewSchemaValidator(schemaPath string) models.Result[*SchemaValidator] {
	schemaContent, err := os.ReadFile(schemaPath)
	if err != nil {
		return models.Err[*SchemaValidator](fmt.Errorf("failed to read schema file: %w", err))
	}

	var schema map[string]interface{}
	err = json.Unmarshal(schemaContent, &schema)
	if err != nil {
		return models.Err[*SchemaValidator](fmt.Errorf("failed to parse schema JSON: %w", err))
	}

	validator := &SchemaValidator{
		schema: schema,
	}

	return models.Ok(validator)
}

// NewSchemaValidatorFromSchema creates a validator from an already parsed schema
func NewSchemaValidatorFromSchema(schema map[string]interface{}) *SchemaValidator {
	return &SchemaValidator{
		schema: schema,
	}
}

// ValidatePayload validates a payload against the loaded JSON schema
func (v *SchemaValidator) ValidatePayload(payload map[string]interface{}) models.Result[ValidationResult] {
	result := ValidationResult{
		Valid:  true,
		Errors: []ValidationError{},
	}

	// Get the properties from the schema
	properties, ok := v.schema["properties"].(map[string]interface{})
	if !ok {
		return models.Err[ValidationResult](fmt.Errorf("invalid schema: missing or invalid properties section"))
	}

	// Get required fields
	requiredFields := []string{}
	if requiredInterface, exists := v.schema["required"]; exists {
		if requiredArray, ok := requiredInterface.([]interface{}); ok {
			for _, field := range requiredArray {
				if fieldStr, ok := field.(string); ok {
					requiredFields = append(requiredFields, fieldStr)
				}
			}
		}
	}

	// Validate required fields
	for _, field := range requiredFields {
		if _, exists := payload[field]; !exists {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   field,
				Message: "required field is missing",
			})
		}
	}

	// Validate each field in the payload
	for fieldName, fieldValue := range payload {
		if fieldSchema, exists := properties[fieldName]; exists {
			if fieldSchemaMap, ok := fieldSchema.(map[string]interface{}); ok {
				if err := v.validateField(fieldName, fieldValue, fieldSchemaMap); err != nil {
					result.Valid = false
					result.Errors = append(result.Errors, *err)
				}
			}
		}
	}

	return models.Ok(result)
}

// ValidatePayloadJSON validates a payload from JSON bytes
func (v *SchemaValidator) ValidatePayloadJSON(payloadJSON []byte) models.Result[ValidationResult] {
	var payload map[string]interface{}
	err := json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return models.Err[ValidationResult](fmt.Errorf("failed to parse payload JSON: %w", err))
	}

	return v.ValidatePayload(payload)
}

// ValidatePayloadDB validates a PayloadDB struct against the schema
func (v *SchemaValidator) ValidatePayloadDB(payload *models.PayloadDB) models.Result[ValidationResult] {
	// Convert PayloadDB to map[string]interface{} for validation
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return models.Err[ValidationResult](fmt.Errorf("failed to marshal payload: %w", err))
	}

	return v.ValidatePayloadJSON(payloadJSON)
}

// validateField validates a single field against its schema definition
func (v *SchemaValidator) validateField(fieldName string, value interface{}, fieldSchema map[string]interface{}) *ValidationError {
	// Get the expected type
	expectedType, ok := fieldSchema["type"].(string)
	if !ok {
		return &ValidationError{
			Field:   fieldName,
			Message: "field schema missing type",
			Value:   value,
		}
	}

	// Handle null values
	if value == nil {
		// Check if field is nullable or optional
		if nullable, exists := fieldSchema["nullable"]; exists {
			if nullableBool, ok := nullable.(bool); ok && nullableBool {
				return nil // Null is allowed
			}
		}
		return &ValidationError{
			Field:   fieldName,
			Message: "field cannot be null",
			Value:   value,
		}
	}

	// Validate type
	if err := v.validateType(fieldName, value, expectedType, fieldSchema); err != nil {
		return err
	}

	// Validate format if specified
	if format, exists := fieldSchema["format"]; exists {
		if formatStr, ok := format.(string); ok {
			if err := v.validateFormat(fieldName, value, formatStr); err != nil {
				return err
			}
		}
	}

	// Validate constraints
	if err := v.validateConstraints(fieldName, value, fieldSchema); err != nil {
		return err
	}

	return nil
}

// validateType validates the type of a field value
func (v *SchemaValidator) validateType(fieldName string, value interface{}, expectedType string, fieldSchema map[string]interface{}) *ValidationError {
	valueType := getJSONType(value)

	switch expectedType {
	case "string":
		if valueType != "string" {
			return &ValidationError{
				Field:   fieldName,
				Message: fmt.Sprintf("expected string, got %s", valueType),
				Value:   value,
			}
		}
	case "number":
		if valueType != "number" {
			return &ValidationError{
				Field:   fieldName,
				Message: fmt.Sprintf("expected number, got %s", valueType),
				Value:   value,
			}
		}
	case "integer":
		if valueType != "number" {
			return &ValidationError{
				Field:   fieldName,
				Message: fmt.Sprintf("expected integer, got %s", valueType),
				Value:   value,
			}
		}
		// Additional check for integer
		if floatVal, ok := value.(float64); ok {
			if floatVal != float64(int64(floatVal)) {
				return &ValidationError{
					Field:   fieldName,
					Message: "expected integer, got decimal number",
					Value:   value,
				}
			}
		}
	case "boolean":
		if valueType != "boolean" {
			return &ValidationError{
				Field:   fieldName,
				Message: fmt.Sprintf("expected boolean, got %s", valueType),
				Value:   value,
			}
		}
	case "array":
		if valueType != "array" {
			return &ValidationError{
				Field:   fieldName,
				Message: fmt.Sprintf("expected array, got %s", valueType),
				Value:   value,
			}
		}
		// Validate array items if items schema is provided
		if items, exists := fieldSchema["items"]; exists {
			if itemsSchema, ok := items.(map[string]interface{}); ok {
				if arrayVal, ok := value.([]interface{}); ok {
					for i, item := range arrayVal {
						itemFieldName := fmt.Sprintf("%s[%d]", fieldName, i)
						if err := v.validateField(itemFieldName, item, itemsSchema); err != nil {
							return err
						}
					}
				}
			}
		}
	case "object":
		if valueType != "object" {
			return &ValidationError{
				Field:   fieldName,
				Message: fmt.Sprintf("expected object, got %s", valueType),
				Value:   value,
			}
		}
	}

	return nil
}

// validateFormat validates format constraints (e.g., uuid, date-time)
func (v *SchemaValidator) validateFormat(fieldName string, value interface{}, format string) *ValidationError {
	strValue, ok := value.(string)
	if !ok {
		return &ValidationError{
			Field:   fieldName,
			Message: "format validation requires string value",
			Value:   value,
		}
	}

	switch format {
	case "uuid":
		if _, err := uuid.Parse(strValue); err != nil {
			return &ValidationError{
				Field:   fieldName,
				Message: "invalid UUID format",
				Value:   value,
			}
		}
	case "date-time":
		// Try multiple date-time formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05.000Z",
		}
		validFormat := false
		for _, timeFormat := range formats {
			if _, err := time.Parse(timeFormat, strValue); err == nil {
				validFormat = true
				break
			}
		}
		if !validFormat {
			return &ValidationError{
				Field:   fieldName,
				Message: "invalid date-time format (expected ISO 8601)",
				Value:   value,
			}
		}
	case "email":
		// Basic email validation
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(strValue) {
			return &ValidationError{
				Field:   fieldName,
				Message: "invalid email format",
				Value:   value,
			}
		}
	case "uri":
		// Basic URI validation
		if !strings.Contains(strValue, "://") {
			return &ValidationError{
				Field:   fieldName,
				Message: "invalid URI format",
				Value:   value,
			}
		}
	}

	return nil
}

// validateConstraints validates field constraints (min, max, minLength, maxLength, etc.)
func (v *SchemaValidator) validateConstraints(fieldName string, value interface{}, fieldSchema map[string]interface{}) *ValidationError {
	// String length constraints
	if strValue, ok := value.(string); ok {
		if minLength, exists := fieldSchema["minLength"]; exists {
			if minLengthFloat, ok := minLength.(float64); ok {
				if len(strValue) < int(minLengthFloat) {
					return &ValidationError{
						Field:   fieldName,
						Message: fmt.Sprintf("string too short (minimum length: %d)", int(minLengthFloat)),
						Value:   value,
					}
				}
			}
		}

		if maxLength, exists := fieldSchema["maxLength"]; exists {
			if maxLengthFloat, ok := maxLength.(float64); ok {
				if len(strValue) > int(maxLengthFloat) {
					return &ValidationError{
						Field:   fieldName,
						Message: fmt.Sprintf("string too long (maximum length: %d)", int(maxLengthFloat)),
						Value:   value,
					}
				}
			}
		}

		// Pattern validation
		if pattern, exists := fieldSchema["pattern"]; exists {
			if patternStr, ok := pattern.(string); ok {
				if regex, err := regexp.Compile(patternStr); err == nil {
					if !regex.MatchString(strValue) {
						return &ValidationError{
							Field:   fieldName,
							Message: fmt.Sprintf("string does not match pattern: %s", patternStr),
							Value:   value,
						}
					}
				}
			}
		}
	}

	// Numeric constraints
	if numValue, ok := value.(float64); ok {
		if minimum, exists := fieldSchema["minimum"]; exists {
			if minimumFloat, ok := minimum.(float64); ok {
				if numValue < minimumFloat {
					return &ValidationError{
						Field:   fieldName,
						Message: fmt.Sprintf("number too small (minimum: %g)", minimumFloat),
						Value:   value,
					}
				}
			}
		}

		if maximum, exists := fieldSchema["maximum"]; exists {
			if maximumFloat, ok := maximum.(float64); ok {
				if numValue > maximumFloat {
					return &ValidationError{
						Field:   fieldName,
						Message: fmt.Sprintf("number too large (maximum: %g)", maximumFloat),
						Value:   value,
					}
				}
			}
		}
	}

	// Array length constraints
	if arrayValue, ok := value.([]interface{}); ok {
		if minItems, exists := fieldSchema["minItems"]; exists {
			if minItemsFloat, ok := minItems.(float64); ok {
				if len(arrayValue) < int(minItemsFloat) {
					return &ValidationError{
						Field:   fieldName,
						Message: fmt.Sprintf("array too short (minimum items: %d)", int(minItemsFloat)),
						Value:   value,
					}
				}
			}
		}

		if maxItems, exists := fieldSchema["maxItems"]; exists {
			if maxItemsFloat, ok := maxItems.(float64); ok {
				if len(arrayValue) > int(maxItemsFloat) {
					return &ValidationError{
						Field:   fieldName,
						Message: fmt.Sprintf("array too long (maximum items: %d)", int(maxItemsFloat)),
						Value:   value,
					}
				}
			}
		}
	}

	// Enum validation
	if enum, exists := fieldSchema["enum"]; exists {
		if enumArray, ok := enum.([]interface{}); ok {
			validValue := false
			for _, enumValue := range enumArray {
				if reflect.DeepEqual(value, enumValue) {
					validValue = true
					break
				}
			}
			if !validValue {
				enumStrings := make([]string, len(enumArray))
				for i, v := range enumArray {
					enumStrings[i] = fmt.Sprintf("%v", v)
				}
				return &ValidationError{
					Field:   fieldName,
					Message: fmt.Sprintf("value not in enum: [%s]", strings.Join(enumStrings, ", ")),
					Value:   value,
				}
			}
		}
	}

	return nil
}

// getJSONType returns the JSON type of a Go value
func getJSONType(value interface{}) string {
	if value == nil {
		return "null"
	}

	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64, int, int32, int64, float32:
		return "number"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

// GetSchemaInfo returns information about the loaded schema
func (v *SchemaValidator) GetSchemaInfo() models.Result[map[string]interface{}] {
	info := map[string]interface{}{
		"$schema": v.schema["$schema"],
		"type":    v.schema["type"],
		"title":   v.schema["title"],
	}

	if properties, exists := v.schema["properties"]; exists {
		if propMap, ok := properties.(map[string]interface{}); ok {
			info["fieldCount"] = len(propMap)
			fieldNames := make([]string, 0, len(propMap))
			for fieldName := range propMap {
				fieldNames = append(fieldNames, fieldName)
			}
			info["fields"] = fieldNames
		}
	}

	if required, exists := v.schema["required"]; exists {
		info["required"] = required
	}

	return models.Ok(info)
}

// ValidateMultiplePayloads validates multiple payloads and returns aggregated results
func (v *SchemaValidator) ValidateMultiplePayloads(payloads []map[string]interface{}) models.Result[[]ValidationResult] {
	results := make([]ValidationResult, len(payloads))

	for i, payload := range payloads {
		result := v.ValidatePayload(payload)
		if result.IsErr() {
			return models.Err[[]ValidationResult](result.Error())
		}
		results[i] = result.Unwrap()
	}

	return models.Ok(results)
}

// CreateValidationSummary creates a summary of validation results
func CreateValidationSummary(results []ValidationResult) map[string]interface{} {
	totalPayloads := len(results)
	validPayloads := 0
	totalErrors := 0
	errorsByField := make(map[string]int)

	for _, result := range results {
		if result.Valid {
			validPayloads++
		} else {
			totalErrors += len(result.Errors)
			for _, err := range result.Errors {
				errorsByField[err.Field]++
			}
		}
	}

	summary := map[string]interface{}{
		"totalPayloads":  totalPayloads,
		"validPayloads":  validPayloads,
		"invalidPayloads": totalPayloads - validPayloads,
		"totalErrors":    totalErrors,
		"successRate":    float64(validPayloads) / float64(totalPayloads) * 100,
		"errorsByField":  errorsByField,
	}

	return summary
}

// Helper functions for common validation scenarios

// ValidatePayloadFile validates a payload from a JSON file
func ValidatePayloadFile(schemaPath, payloadPath string) models.Result[ValidationResult] {
	validatorResult := NewSchemaValidator(schemaPath)
	if validatorResult.IsErr() {
		return models.Err[ValidationResult](validatorResult.Error())
	}
	validator := validatorResult.Unwrap()

	payloadContent, err := os.ReadFile(payloadPath)
	if err != nil {
		return models.Err[ValidationResult](fmt.Errorf("failed to read payload file: %w", err))
	}

	return validator.ValidatePayloadJSON(payloadContent)
}

// ValidatePayloadDirectory validates all JSON files in a directory
func ValidatePayloadDirectory(schemaPath, directoryPath string) models.Result[map[string]ValidationResult] {
	validatorResult := NewSchemaValidator(schemaPath)
	if validatorResult.IsErr() {
		return models.Err[map[string]ValidationResult](validatorResult.Error())
	}
	validator := validatorResult.Unwrap()

	entries, err := os.ReadDir(directoryPath)
	if err != nil {
		return models.Err[map[string]ValidationResult](fmt.Errorf("failed to read directory: %w", err))
	}

	results := make(map[string]ValidationResult)

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			filePath := entry.Name()
			fullPath := directoryPath + "/" + filePath

			payloadContent, err := os.ReadFile(fullPath)
			if err != nil {
				results[filePath] = ValidationResult{
					Valid: false,
					Errors: []ValidationError{{
						Field:   "file",
						Message: fmt.Sprintf("failed to read file: %v", err),
					}},
				}
				continue
			}

			validationResult := validator.ValidatePayloadJSON(payloadContent)
			if validationResult.IsErr() {
				results[filePath] = ValidationResult{
					Valid: false,
					Errors: []ValidationError{{
						Field:   "json",
						Message: fmt.Sprintf("JSON parsing error: %v", validationResult.Error()),
					}},
				}
			} else {
				results[filePath] = validationResult.Unwrap()
			}
		}
	}

	return models.Ok(results)
}

// FormatValidationErrors formats validation errors for display
func FormatValidationErrors(errors []ValidationError) string {
	if len(errors) == 0 {
		return "No validation errors"
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Found %d validation error(s):\n", len(errors)))

	for i, err := range errors {
		builder.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err.Error()))
		if err.Value != nil {
			builder.WriteString(fmt.Sprintf("     Value: %v\n", err.Value))
		}
	}

	return builder.String()
}
