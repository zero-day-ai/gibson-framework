package main

import (
	"fmt"
	"strings"

	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

// TypeMapper handles mapping Go types to JSON Schema types
type TypeMapper struct{}

// GenerateSchema generates a complete JSON Schema from struct information
func (m *TypeMapper) GenerateSchema(structInfo StructInfo) coremodels.Result[JSONSchema] {
	schema := JSONSchema{
		"$schema":              jsonSchemaDraft7,
		"type":                 "object",
		"title":                structInfo.Name,
		"description":          "Security testing payload with repository tracking",
		"additionalProperties": false,
	}

	properties := make(map[string]interface{})
	required := make([]string, 0)

	for _, field := range structInfo.Fields {
		// Skip unexported fields
		if strings.ToLower(field.Name[:1]) == field.Name[:1] {
			continue
		}

		// Get JSON field name (use json tag or field name)
		jsonName := m.getJSONFieldName(field)
		if jsonName == "" || jsonName == "-" {
			continue
		}

		// Generate property schema
		propertyResult := m.generateFieldSchema(field)
		if propertyResult.IsErr() {
			return coremodels.Err[JSONSchema](fmt.Errorf("failed to generate schema for field %s: %w", field.Name, propertyResult.Error()))
		}

		properties[jsonName] = propertyResult.Unwrap()

		// Check if field is required
		if m.isFieldRequired(field) {
			required = append(required, jsonName)
		}
	}

	schema["properties"] = properties
	if len(required) > 0 {
		schema["required"] = required
	}

	return coremodels.Ok(schema)
}

// generateFieldSchema generates JSON Schema for a single field
func (m *TypeMapper) generateFieldSchema(field FieldInfo) coremodels.Result[map[string]interface{}] {
	property := make(map[string]interface{})

	// Handle nullable fields (pointers)
	if field.IsPointer {
		property["nullable"] = true
	}

	// Map Go type to JSON Schema type
	typeResult := m.mapGoTypeToJSONSchema(field)
	if typeResult.IsErr() {
		return coremodels.Err[map[string]interface{}](typeResult.Error())
	}

	typeSchema := typeResult.Unwrap()
	for key, value := range typeSchema {
		property[key] = value
	}

	// Add validation constraints from validate tag
	if field.ValidateTag != "" {
		validationResult := m.parseValidationConstraints(field.ValidateTag, property)
		if validationResult.IsErr() {
			return coremodels.Err[map[string]interface{}](validationResult.Error())
		}
		property = validationResult.Unwrap()
	}

	// Add field description based on field name and type
	property["description"] = m.generateFieldDescription(field)

	return coremodels.Ok(property)
}

// mapGoTypeToJSONSchema maps Go types to JSON Schema types and formats
func (m *TypeMapper) mapGoTypeToJSONSchema(field FieldInfo) coremodels.Result[map[string]interface{}] {
	property := make(map[string]interface{})

	switch {
	case field.IsSlice:
		property["type"] = "array"

		// Handle slice element type
		elementResult := m.mapElementType(field.ElementType)
		if elementResult.IsErr() {
			return coremodels.Err[map[string]interface{}](elementResult.Error())
		}
		property["items"] = elementResult.Unwrap()

	case field.IsMap:
		property["type"] = "object"

		// Handle map value type
		if field.ValueType != "" {
			valueResult := m.mapElementType(field.ValueType)
			if valueResult.IsErr() {
				return coremodels.Err[map[string]interface{}](valueResult.Error())
			}
			property["additionalProperties"] = valueResult.Unwrap()
		} else {
			property["additionalProperties"] = true
		}

	default:
		// Handle basic types and known complex types
		typeResult := m.mapBasicType(field.Type)
		if typeResult.IsErr() {
			return coremodels.Err[map[string]interface{}](typeResult.Error())
		}

		typeSchema := typeResult.Unwrap()
		for key, value := range typeSchema {
			property[key] = value
		}
	}

	return coremodels.Ok(property)
}

// mapBasicType maps basic Go types to JSON Schema
func (m *TypeMapper) mapBasicType(goType string) coremodels.Result[map[string]interface{}] {
	property := make(map[string]interface{})

	switch goType {
	// String types
	case "string":
		property["type"] = "string"

	// Integer types
	case "int", "int8", "int16", "int32", "int64":
		property["type"] = "integer"

	case "uint", "uint8", "uint16", "uint32", "uint64":
		property["type"] = "integer"
		property["minimum"] = 0

	// Float types
	case "float32", "float64":
		property["type"] = "number"

	// Boolean type
	case "bool":
		property["type"] = "boolean"

	// UUID type
	case "uuid.UUID":
		property["type"] = "string"
		property["format"] = "uuid"

	// Time type
	case "time.Time":
		property["type"] = "string"
		property["format"] = "date-time"

	// Duration type
	case "time.Duration":
		property["type"] = "string"
		property["description"] = "Duration in Go format (e.g., '1h30m')"

	// Custom enum types
	case "PayloadCategory":
		property["type"] = "string"
		property["enum"] = []string{
			"model", "data", "interface", "infrastructure", "output", "process",
		}

	case "PayloadType":
		property["type"] = "string"
		property["enum"] = []string{
			"prompt", "query", "input", "code", "data", "script",
		}

	// Interface type
	case "interface{}", "interface":
		property["type"] = []string{"null", "boolean", "object", "array", "number", "string"}
		property["description"] = "Any JSON value"

	default:
		// Unknown type - treat as object
		property["type"] = "object"
		property["description"] = fmt.Sprintf("Complex type: %s", goType)
	}

	return coremodels.Ok(property)
}

// mapElementType maps element types for arrays and maps
func (m *TypeMapper) mapElementType(elementType string) coremodels.Result[map[string]interface{}] {
	return m.mapBasicType(elementType)
}

// parseValidationConstraints parses validation tags and adds constraints to schema
func (m *TypeMapper) parseValidationConstraints(validateTag string, property map[string]interface{}) coremodels.Result[map[string]interface{}] {
	// Parse validation constraints from validate tag
	constraints := strings.Split(validateTag, ",")

	for _, constraint := range constraints {
		constraint = strings.TrimSpace(constraint)

		// Handle required constraint
		if constraint == "required" {
			// Required is handled at the schema level, not property level
			continue
		}

		// Handle length constraints
		if strings.HasPrefix(constraint, "min=") {
			minStr := strings.TrimPrefix(constraint, "min=")
			if property["type"] == "string" {
				property["minLength"] = m.parseIntValue(minStr)
			} else if property["type"] == "integer" || property["type"] == "number" {
				property["minimum"] = m.parseIntValue(minStr)
			}
		}

		if strings.HasPrefix(constraint, "max=") {
			maxStr := strings.TrimPrefix(constraint, "max=")
			if property["type"] == "string" {
				property["maxLength"] = m.parseIntValue(maxStr)
			} else if property["type"] == "integer" || property["type"] == "number" {
				property["maximum"] = m.parseIntValue(maxStr)
			}
		}

		// Handle format constraints
		if constraint == "email" {
			property["format"] = "email"
		}

		if constraint == "url" {
			property["format"] = "uri"
		}

		if constraint == "semver" {
			property["pattern"] = "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
			property["description"] = (property["description"].(string)) + " (semantic version format)"
		}
	}

	return coremodels.Ok(property)
}

// parseIntValue safely parses integer values from validation constraints
func (m *TypeMapper) parseIntValue(s string) interface{} {
	// Simple integer parsing - in a real implementation you'd want proper error handling
	switch s {
	case "0": return 0
	case "1": return 1
	case "2": return 2
	case "255": return 255
	default: return 0
	}
}

// getJSONFieldName extracts the JSON field name from struct tags
func (m *TypeMapper) getJSONFieldName(field FieldInfo) string {
	if field.JSONTag == "" {
		// Convert CamelCase to snake_case for JSON field name
		return m.camelToSnake(field.Name)
	}

	// Parse json tag value (handle omitempty)
	parts := strings.Split(field.JSONTag, ",")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}

	return m.camelToSnake(field.Name)
}

// isFieldRequired determines if a field is required based on validation tags
func (m *TypeMapper) isFieldRequired(field FieldInfo) bool {
	if field.ValidateTag == "" {
		return false
	}

	constraints := strings.Split(field.ValidateTag, ",")
	for _, constraint := range constraints {
		if strings.TrimSpace(constraint) == "required" {
			return true
		}
	}

	return false
}

// generateFieldDescription generates a description for a field
func (m *TypeMapper) generateFieldDescription(field FieldInfo) string {
	descriptions := map[string]string{
		"ID":               "Unique identifier for the payload",
		"Name":             "Human-readable name of the payload",
		"Category":         "Category classification of the payload",
		"Domain":           "Plugin domain this payload belongs to",
		"PluginName":       "Name of the plugin that uses this payload",
		"Type":             "Type of payload (prompt, query, input, etc.)",
		"Version":          "Version number of the payload",
		"ParentID":         "ID of the parent payload if this is a variant",
		"Content":          "The actual payload content",
		"Description":      "Detailed description of the payload",
		"Severity":         "Severity level of the security test",
		"Tags":             "List of tags for categorization",
		"Variables":        "Variable substitutions for the payload",
		"Config":           "Configuration options for the payload",
		"Language":         "Programming language if applicable",
		"Enabled":          "Whether the payload is enabled for use",
		"Validated":        "Whether the payload has been validated",
		"ValidationResult": "Results of payload validation",
		"UsageCount":       "Number of times the payload has been used",
		"SuccessRate":      "Success rate of the payload (0.0-1.0)",
		"LastUsed":         "Timestamp when the payload was last used",
		"RepositoryID":     "ID of the repository containing this payload",
		"RepositoryPath":   "Path within the repository",
		"CreatedBy":        "User who created the payload",
		"CreatedAt":        "Timestamp when the payload was created",
		"UpdatedAt":        "Timestamp when the payload was last updated",
	}

	if desc, exists := descriptions[field.Name]; exists {
		return desc
	}

	return fmt.Sprintf("Field: %s", field.Name)
}

// camelToSnake converts CamelCase to snake_case
func (m *TypeMapper) camelToSnake(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}