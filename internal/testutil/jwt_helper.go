// Package testutil provides JWT testing utilities for Gibson Framework
package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWTHeader represents a JWT header
type JWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

// JWTPayload represents a JWT payload with common claims
type JWTPayload struct {
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
}

// GenerateTestJWT creates a valid JWT-format token for testing purposes
// The token follows the standard JWT structure: header.payload.signature
func GenerateTestJWT() (string, error) {
	// Create header
	header := JWTHeader{
		Type:      "JWT",
		Algorithm: "RS256",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Create payload
	payload := JWTPayload{
		Audience: "https://cognitiveservices.azure.com",
		Issuer:   "https://sts.windows.net",
		Subject:  "test-subject",
		ExpiresAt: 1699999999, // Far future
		IssuedAt:  1600000000, // Past timestamp
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encode header and payload
	headerEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerJSON)
	payloadEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadJSON)

	// Generate random signature (for testing, doesn't need to be cryptographically valid)
	signature := make([]byte, 32)
	if _, err := rand.Read(signature); err != nil {
		return "", fmt.Errorf("failed to generate signature: %w", err)
	}
	signatureEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature)

	// Combine into JWT format
	jwt := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded)
	return jwt, nil
}

// GenerateTestJWTWithPayload creates a JWT with custom payload for testing
func GenerateTestJWTWithPayload(customPayload map[string]interface{}) (string, error) {
	// Create header
	header := JWTHeader{
		Type:      "JWT",
		Algorithm: "RS256",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Use custom payload
	payloadJSON, err := json.Marshal(customPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encode header and payload
	headerEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerJSON)
	payloadEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadJSON)

	// Generate random signature
	signature := make([]byte, 32)
	if _, err := rand.Read(signature); err != nil {
		return "", fmt.Errorf("failed to generate signature: %w", err)
	}
	signatureEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature)

	// Combine into JWT format
	jwt := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded)
	return jwt, nil
}

// ValidateJWTStructure validates that a string follows JWT format (header.payload.signature)
// This is a structural validation only, not cryptographic verification
func ValidateJWTStructure(token string) error {
	if token == "" {
		return fmt.Errorf("JWT token cannot be empty")
	}

	// Split into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("JWT must have exactly 3 parts separated by dots, got %d parts", len(parts))
	}

	// Validate each part is non-empty and valid base64
	partNames := []string{"header", "payload", "signature"}
	for i, part := range parts {
		if part == "" {
			return fmt.Errorf("JWT %s cannot be empty", partNames[i])
		}

		// Add padding if needed for base64 validation
		padded := part
		for len(padded)%4 != 0 {
			padded += "="
		}

		// Try to decode as base64
		if _, err := base64.URLEncoding.DecodeString(padded); err != nil {
			return fmt.Errorf("JWT %s is not valid base64: %w", partNames[i], err)
		}
	}

	return nil
}

// IsValidJWT checks if a string is a valid JWT structure
func IsValidJWT(token string) bool {
	return ValidateJWTStructure(token) == nil
}

// ParseJWTParts splits a JWT into its constituent parts for testing
func ParseJWTParts(token string) (header, payload, signature string, err error) {
	if err := ValidateJWTStructure(token); err != nil {
		return "", "", "", err
	}

	parts := strings.Split(token, ".")
	return parts[0], parts[1], parts[2], nil
}

// DecodeJWTHeader decodes the header part of a JWT for testing
func DecodeJWTHeader(token string) (*JWTHeader, error) {
	headerPart, _, _, err := ParseJWTParts(token)
	if err != nil {
		return nil, err
	}

	// Add padding if needed
	padded := headerPart
	for len(padded)%4 != 0 {
		padded += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	return &header, nil
}

// DecodeJWTPayload decodes the payload part of a JWT for testing
func DecodeJWTPayload(token string) (map[string]interface{}, error) {
	_, payloadPart, _, err := ParseJWTParts(token)
	if err != nil {
		return nil, err
	}

	// Add padding if needed
	padded := payloadPart
	for len(padded)%4 != 0 {
		padded += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return payload, nil
}

// GenerateInvalidJWT creates an invalid JWT for negative testing
func GenerateInvalidJWT(invalidType string) string {
	switch invalidType {
	case "empty":
		return ""
	case "single_part":
		return "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
	case "two_parts":
		return "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ0ZXN0In0"
	case "invalid_base64":
		return "invalid.invalid.invalid"
	case "empty_parts":
		return ".."
	default:
		return "not-a-jwt-token"
	}
}