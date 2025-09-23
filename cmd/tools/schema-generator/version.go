package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
)

const (
	versionCacheFile = ".schema-version-cache.json"
)

// VersionDetector handles schema version detection and management
type VersionDetector struct{}

// VersionCache stores version information between runs
type VersionCache struct {
	CurrentVersion string            `json:"current_version"`
	ModelHash      string            `json:"model_hash"`
	FieldHashes    map[string]string `json:"field_hashes"`
	ChangeHistory  []VersionChange   `json:"change_history"`
}

// VersionChange represents a schema change event
type VersionChange struct {
	Version     string   `json:"version"`
	ChangeType  string   `json:"change_type"`
	Changes     []string `json:"changes"`
	Timestamp   string   `json:"timestamp"`
	ModelHash   string   `json:"model_hash"`
}

const (
	ChangeTypeNone  = "none"
	ChangeTypePatch = "patch"
	ChangeTypeMinor = "minor"
	ChangeTypeMajor = "major"
)

// DetectVersion analyzes schema changes and determines appropriate version
func (v *VersionDetector) DetectVersion(schema JSONSchema) coremodels.Result[VersionInfo] {
	// Load existing version cache
	cacheResult := v.loadVersionCache()
	if cacheResult.IsErr() {
		// No cache exists, start with version 1.0.0
		return coremodels.Ok(VersionInfo{
			Version:    "1.0.0",
			ChangeType: ChangeTypeMinor,
			Hash:       v.calculateSchemaHash(schema),
		})
	}

	cache := cacheResult.Unwrap()
	currentHash := v.calculateSchemaHash(schema)

	// If hash is the same, no changes
	if cache.ModelHash == currentHash {
		return coremodels.Ok(VersionInfo{
			Version:    cache.CurrentVersion,
			ChangeType: ChangeTypeNone,
			Hash:       currentHash,
		})
	}

	// Analyze schema changes
	changeResult := v.analyzeSchemaChanges(schema, cache)
	if changeResult.IsErr() {
		return coremodels.Err[VersionInfo](changeResult.Error())
	}

	changeAnalysis := changeResult.Unwrap()

	// Calculate new version based on change type
	newVersionResult := v.calculateNewVersion(cache.CurrentVersion, changeAnalysis.ChangeType)
	if newVersionResult.IsErr() {
		return coremodels.Err[VersionInfo](newVersionResult.Error())
	}

	newVersion := newVersionResult.Unwrap()

	return coremodels.Ok(VersionInfo{
		Version:    newVersion,
		ChangeType: changeAnalysis.ChangeType,
		Hash:       currentHash,
	})
}

// ChangeAnalysis represents the analysis of schema changes
type ChangeAnalysis struct {
	ChangeType string
	Changes    []string
}

// analyzeSchemaChanges compares current schema with cached version
func (v *VersionDetector) analyzeSchemaChanges(schema JSONSchema, cache VersionCache) coremodels.Result[ChangeAnalysis] {
	changes := make([]string, 0)
	changeType := ChangeTypeNone

	// Extract current field information
	currentFields := v.extractFieldInfo(schema)
	if currentFields.IsErr() {
		return coremodels.Err[ChangeAnalysis](currentFields.Error())
	}

	currentFieldMap := currentFields.Unwrap()

	// Compare with cached field hashes
	for fieldName, currentHash := range currentFieldMap {
		if cachedHash, exists := cache.FieldHashes[fieldName]; exists {
			if cachedHash != currentHash {
				changes = append(changes, fmt.Sprintf("Modified field: %s", fieldName))
				// Field modification could be major (if breaking) or minor (if backward compatible)
				// For now, treat as minor change
				if changeType == ChangeTypeNone {
					changeType = ChangeTypeMinor
				}
			}
		} else {
			// New field added
			changes = append(changes, fmt.Sprintf("Added field: %s", fieldName))
			if changeType == ChangeTypeNone {
				changeType = ChangeTypeMinor
			}
		}
	}

	// Check for removed fields (breaking change)
	for fieldName := range cache.FieldHashes {
		if _, exists := currentFieldMap[fieldName]; !exists {
			changes = append(changes, fmt.Sprintf("Removed field: %s", fieldName))
			changeType = ChangeTypeMajor // Field removal is breaking
		}
	}

	// Check for required field changes (breaking)
	requiredChanges := v.analyzeRequiredFieldChanges(schema, cache)
	if requiredChanges.IsErr() {
		return coremodels.Err[ChangeAnalysis](requiredChanges.Error())
	}

	requiredChangesList := requiredChanges.Unwrap()
	changes = append(changes, requiredChangesList...)
	if len(requiredChangesList) > 0 {
		changeType = ChangeTypeMajor
	}

	return coremodels.Ok(ChangeAnalysis{
		ChangeType: changeType,
		Changes:    changes,
	})
}

// extractFieldInfo extracts field information for comparison
func (v *VersionDetector) extractFieldInfo(schema JSONSchema) coremodels.Result[map[string]string] {
	fieldHashes := make(map[string]string)

	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		return coremodels.Err[map[string]string](fmt.Errorf("schema missing properties"))
	}

	for fieldName, fieldSchema := range properties {
		// Calculate hash of field schema
		fieldJSON, err := json.Marshal(fieldSchema)
		if err != nil {
			return coremodels.Err[map[string]string](fmt.Errorf("failed to marshal field %s: %w", fieldName, err))
		}

		hash := sha256.Sum256(fieldJSON)
		fieldHashes[fieldName] = hex.EncodeToString(hash[:])
	}

	return coremodels.Ok(fieldHashes)
}

// analyzeRequiredFieldChanges checks for changes in required fields
func (v *VersionDetector) analyzeRequiredFieldChanges(schema JSONSchema, cache VersionCache) coremodels.Result[[]string] {
	changes := make([]string, 0)

	// Get current required fields
	var currentRequired []string
	if req, ok := schema["required"].([]interface{}); ok {
		for _, field := range req {
			if fieldStr, ok := field.(string); ok {
				currentRequired = append(currentRequired, fieldStr)
			}
		}
	}

	// We don't have cached required fields info, so we'll assume no breaking changes
	// In a real implementation, you'd want to cache this information too

	return coremodels.Ok(changes)
}

// calculateNewVersion increments version based on change type
func (v *VersionDetector) calculateNewVersion(currentVersion, changeType string) coremodels.Result[string] {
	if changeType == ChangeTypeNone {
		return coremodels.Ok(currentVersion)
	}

	// Parse current version (assuming semver format: MAJOR.MINOR.PATCH)
	parts := strings.Split(currentVersion, ".")
	if len(parts) != 3 {
		// Default version if parsing fails
		return coremodels.Ok("1.0.0")
	}

	major := v.parseVersionPart(parts[0])
	minor := v.parseVersionPart(parts[1])
	patch := v.parseVersionPart(parts[2])

	switch changeType {
	case ChangeTypeMajor:
		major++
		minor = 0
		patch = 0
	case ChangeTypeMinor:
		minor++
		patch = 0
	case ChangeTypePatch:
		patch++
	}

	return coremodels.Ok(fmt.Sprintf("%d.%d.%d", major, minor, patch))
}

// parseVersionPart safely parses version part to integer
func (v *VersionDetector) parseVersionPart(part string) int {
	switch part {
	case "0": return 0
	case "1": return 1
	case "2": return 2
	case "3": return 3
	case "4": return 4
	case "5": return 5
	default: return 0
	}
}

// calculateSchemaHash calculates a hash of the schema for comparison
func (v *VersionDetector) calculateSchemaHash(schema JSONSchema) string {
	// Create a normalized representation for hashing
	normalized := v.normalizeSchemaForHashing(schema)

	schemaJSON, err := json.Marshal(normalized)
	if err != nil {
		// Fallback to string representation
		schemaJSON = []byte(fmt.Sprintf("%v", schema))
	}

	hash := sha256.Sum256(schemaJSON)
	return hex.EncodeToString(hash[:])
}

// normalizeSchemaForHashing creates a normalized schema for consistent hashing
func (v *VersionDetector) normalizeSchemaForHashing(schema JSONSchema) map[string]interface{} {
	normalized := make(map[string]interface{})

	// Copy relevant fields for hashing, excluding metadata that shouldn't affect versioning
	excludeKeys := map[string]bool{
		"$schema":     true,
		"version":     true,
		"$id":         true,
		"title":       true,
	}

	for key, value := range schema {
		if !excludeKeys[key] {
			normalized[key] = value
		}
	}

	return normalized
}

// StoreModelHash stores the model hash for future comparison
func (v *VersionDetector) StoreModelHash(structInfo StructInfo) coremodels.Result[bool] {
	// Calculate model hash from struct info
	modelHash := v.calculateModelHash(structInfo)

	// Load existing cache or create new one
	cache := VersionCache{
		CurrentVersion: "1.0.0",
		ModelHash:      modelHash,
		FieldHashes:    make(map[string]string),
		ChangeHistory:  make([]VersionChange, 0),
	}

	cacheResult := v.loadVersionCache()
	if cacheResult.IsOk() {
		cache = cacheResult.Unwrap()
		cache.ModelHash = modelHash
	}

	// Calculate field hashes
	for _, field := range structInfo.Fields {
		fieldHash := v.calculateFieldHash(field)
		cache.FieldHashes[field.Name] = fieldHash
	}

	// Save updated cache
	return v.saveVersionCache(cache)
}

// calculateModelHash calculates a hash of the entire model structure
func (v *VersionDetector) calculateModelHash(structInfo StructInfo) string {
	// Create a stable string representation of the struct
	var builder strings.Builder

	builder.WriteString(structInfo.Name)
	builder.WriteString("|")

	// Sort fields for consistent hashing
	fieldNames := make([]string, len(structInfo.Fields))
	fieldMap := make(map[string]FieldInfo)

	for i, field := range structInfo.Fields {
		fieldNames[i] = field.Name
		fieldMap[field.Name] = field
	}
	sort.Strings(fieldNames)

	for _, fieldName := range fieldNames {
		field := fieldMap[fieldName]
		builder.WriteString(fmt.Sprintf("%s:%s:%s:%s:%s|",
			field.Name, field.Type, field.JSONTag, field.DBTag, field.ValidateTag))
	}

	hash := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(hash[:])
}

// calculateFieldHash calculates a hash for a single field
func (v *VersionDetector) calculateFieldHash(field FieldInfo) string {
	fieldStr := fmt.Sprintf("%s:%s:%s:%s:%s",
		field.Name, field.Type, field.JSONTag, field.DBTag, field.ValidateTag)

	hash := sha256.Sum256([]byte(fieldStr))
	return hex.EncodeToString(hash[:])
}

// loadVersionCache loads the version cache from disk
func (v *VersionDetector) loadVersionCache() coremodels.Result[VersionCache] {
	cacheFile := filepath.Join(outputDir, versionCacheFile)

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return coremodels.Err[VersionCache](fmt.Errorf("cache file not found"))
		}
		return coremodels.Err[VersionCache](fmt.Errorf("failed to read cache file: %w", err))
	}

	var cache VersionCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return coremodels.Err[VersionCache](fmt.Errorf("failed to unmarshal cache: %w", err))
	}

	return coremodels.Ok(cache)
}

// saveVersionCache saves the version cache to disk
func (v *VersionDetector) saveVersionCache(cache VersionCache) coremodels.Result[bool] {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to create output directory: %w", err))
	}

	cacheFile := filepath.Join(outputDir, versionCacheFile)

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to marshal cache: %w", err))
	}

	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to write cache file: %w", err))
	}

	return coremodels.Ok(true)
}