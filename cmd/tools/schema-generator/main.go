package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

const (
	jsonSchemaDraft7 = "http://json-schema.org/draft-07/schema#"
	outputDir       = "schemas"
	outputFile      = "payload_schema.json"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Println("Gibson Schema Generator")
	fmt.Println("Parsing PayloadDB struct...")

	// Parse the PayloadDB struct
	parseResult := parsePayloadDBStruct()
	if parseResult.IsErr() {
		return fmt.Errorf("failed to parse PayloadDB struct: %w", parseResult.Error())
	}

	structInfo := parseResult.Unwrap()
	fmt.Printf("Successfully parsed PayloadDB with %d fields\n", len(structInfo.Fields))

	// Generate JSON Schema
	schemaResult := generateJSONSchema(structInfo)
	if schemaResult.IsErr() {
		return fmt.Errorf("failed to generate JSON schema: %w", schemaResult.Error())
	}

	schema := schemaResult.Unwrap()
	fmt.Println("JSON Schema generated successfully")

	// Detect version changes
	versionResult := detectSchemaVersion(schema)
	if versionResult.IsErr() {
		return fmt.Errorf("failed to detect schema version: %w", versionResult.Error())
	}

	versionInfo := versionResult.Unwrap()
	fmt.Printf("Schema version: %s (change type: %s)\n", versionInfo.Version, versionInfo.ChangeType)

	// Update schema with version information
	schema["version"] = versionInfo.Version
	schema["$id"] = fmt.Sprintf("https://schemas.gibson-sec.com/payload/%s", versionInfo.Version)

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write schema to file
	outputPath := filepath.Join(outputDir, outputFile)
	schemaJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal schema to JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, schemaJSON, 0644); err != nil {
		return fmt.Errorf("failed to write schema file: %w", err)
	}

	fmt.Printf("Schema written to %s\n", outputPath)

	// Store model hash for future version detection
	storeResult := storeModelHash(structInfo)
	if storeResult.IsErr() {
		fmt.Printf("Warning: failed to store model hash: %v\n", storeResult.Error())
	}

	return nil
}

// StructInfo represents parsed struct information
type StructInfo struct {
	Name   string
	Fields []FieldInfo
}

// FieldInfo represents a parsed struct field
type FieldInfo struct {
	Name         string
	Type         string
	JSONTag      string
	DBTag        string
	ValidateTag  string
	IsPointer    bool
	IsSlice      bool
	IsMap        bool
	ElementType  string
	KeyType      string
	ValueType    string
}

// JSONSchema represents a JSON Schema object
type JSONSchema map[string]interface{}

// VersionInfo represents schema version information
type VersionInfo struct {
	Version    string
	ChangeType string
	Hash       string
}

// parsePayloadDBStruct parses the PayloadDB struct using go/ast
func parsePayloadDBStruct() coremodels.Result[StructInfo] {
	parser := &StructParser{}
	return parser.ParsePayloadDB()
}

// generateJSONSchema generates JSON Schema from struct information
func generateJSONSchema(structInfo StructInfo) coremodels.Result[JSONSchema] {
	mapper := &TypeMapper{}
	return mapper.GenerateSchema(structInfo)
}

// detectSchemaVersion detects schema version based on changes
func detectSchemaVersion(schema JSONSchema) coremodels.Result[VersionInfo] {
	detector := &VersionDetector{}
	return detector.DetectVersion(schema)
}

// storeModelHash stores the model hash for future comparison
func storeModelHash(structInfo StructInfo) coremodels.Result[bool] {
	detector := &VersionDetector{}
	return detector.StoreModelHash(structInfo)
}