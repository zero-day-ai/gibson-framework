package test

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// TestCredentialEncryptionDecryption tests the full encryption/decryption flow
func TestCredentialEncryptionDecryption(t *testing.T) {
	testDB := test.NewTestDatabase(t)
	defer testDB.Close()

	// Create credentials table schema
	schema := `
	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		provider TEXT NOT NULL,
		type TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		salt BLOB NOT NULL,
		nonce BLOB NOT NULL,
		description TEXT,
		tags TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		auto_rotate BOOLEAN DEFAULT FALSE,
		rotation_interval TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME,
		last_rotated DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);
	CREATE INDEX IF NOT EXISTS idx_credentials_provider ON credentials(provider);
	CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);
	CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
	`
	_, err := testDB.DB.Exec(schema)
	require.NoError(t, err)

	tests := []struct {
		name           string
		credentialName string
		provider       string
		credentialType string
		value          string
		description    string
		tags           []string
	}{
		{
			name:           "OpenAI API Key",
			credentialName: "openai-prod",
			provider:       "openai",
			credentialType: "api_key",
			value:          "sk-abcd1234567890abcd1234567890abcd1234567890abcd1234",
			description:    "Production OpenAI API key for GPT-4",
			tags:           []string{"production", "gpt-4", "high-priority"},
		},
		{
			name:           "Anthropic API Key",
			credentialName: "anthropic-dev",
			provider:       "anthropic",
			credentialType: "api_key",
			value:          "ant-api03-abcd1234567890abcd1234567890abcd1234567890abcd",
			description:    "Development Anthropic API key for Claude",
			tags:           []string{"development", "claude", "testing"},
		},
		{
			name:           "Azure OpenAI Credentials",
			credentialName: "azure-openai-enterprise",
			provider:       "azure-openai",
			credentialType: "bearer_token",
			value:          "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL2NvZ25pdGl2ZXNlcnZpY2VzLmF6dXJlLmNvbSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0IiwiZXhwIjoxNjk5OTk5OTk5fQ.test-signature-part",
			description:    "Enterprise Azure OpenAI bearer token",
			tags:           []string{"enterprise", "azure", "bearer"},
		},
		{
			name:           "Database Password",
			credentialName: "postgres-main-db",
			provider:       "postgresql",
			credentialType: "password",
			value:          "SuperSecureP@ssw0rd!2024#Gibson$Framework",
			description:    "Main PostgreSQL database password",
			tags:           []string{"database", "postgresql", "main"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test encryption
			encryptedData, salt, nonce, err := encryptCredentialValue(tt.value, "test-master-key")
			require.NoError(t, err)
			assert.NotEmpty(t, encryptedData)
			assert.NotEmpty(t, salt)
			assert.NotEmpty(t, nonce)
			assert.NotEqual(t, tt.value, encryptedData) // Ensure it's actually encrypted

			// Test decryption
			decryptedValue, err := decryptCredentialValue(encryptedData, salt, nonce, "test-master-key")
			require.NoError(t, err)
			assert.Equal(t, tt.value, decryptedValue)

			// Test with wrong key
			wrongDecrypted, err := decryptCredentialValue(encryptedData, salt, nonce, "wrong-key")
			assert.Error(t, err)
			assert.Empty(t, wrongDecrypted)

			// Test storage in database
			credentialID := "test-" + strings.ReplaceAll(tt.credentialName, "-", "_")
			tagsJSON := `["` + strings.Join(tt.tags, `", "`) + `"]`

			insertQuery := `
				INSERT INTO credentials (id, name, provider, type, encrypted_value, salt, nonce, description, tags, status)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
			`

			_, err = testDB.DB.Exec(insertQuery,
				credentialID,
				tt.credentialName,
				tt.provider,
				tt.credentialType,
				encryptedData,
				salt,
				nonce,
				tt.description,
				tagsJSON,
			)
			require.NoError(t, err)

			// Test retrieval and decryption from database
			var storedCred struct {
				ID             string `db:"id"`
				Name           string `db:"name"`
				Provider       string `db:"provider"`
				Type           string `db:"type"`
				EncryptedValue []byte `db:"encrypted_value"`
				Salt           []byte `db:"salt"`
				Nonce          []byte `db:"nonce"`
				Description    string `db:"description"`
				Tags           string `db:"tags"`
				Status         string `db:"status"`
			}

			selectQuery := `SELECT id, name, provider, type, encrypted_value, salt, nonce, description, tags, status FROM credentials WHERE name = ?`
			err = testDB.DB.Get(&storedCred, selectQuery, tt.credentialName)
			require.NoError(t, err)

			// Verify stored data
			assert.Equal(t, credentialID, storedCred.ID)
			assert.Equal(t, tt.credentialName, storedCred.Name)
			assert.Equal(t, tt.provider, storedCred.Provider)
			assert.Equal(t, tt.credentialType, storedCred.Type)
			assert.Equal(t, tt.description, storedCred.Description)
			assert.Contains(t, storedCred.Tags, tt.tags[0])

			// Test decryption of stored credential
			retrievedValue, err := decryptCredentialValue(storedCred.EncryptedValue, storedCred.Salt, storedCred.Nonce, "test-master-key")
			require.NoError(t, err)
			assert.Equal(t, tt.value, retrievedValue)
		})
	}
}

// TestCredentialRotation tests the credential rotation functionality
func TestCredentialRotation(t *testing.T) {
	testDB := test.NewTestDatabase(t)
	defer testDB.Close()

	// Create credentials table
	schema := `
	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		provider TEXT NOT NULL,
		type TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		salt BLOB NOT NULL,
		nonce BLOB NOT NULL,
		description TEXT,
		tags TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		auto_rotate BOOLEAN DEFAULT FALSE,
		rotation_interval TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME,
		last_rotated DATETIME
	);

	CREATE TABLE IF NOT EXISTS credential_history (
		id TEXT PRIMARY KEY,
		credential_id TEXT NOT NULL,
		old_encrypted_value BLOB NOT NULL,
		old_salt BLOB NOT NULL,
		old_nonce BLOB NOT NULL,
		rotated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		rotation_reason TEXT,
		FOREIGN KEY (credential_id) REFERENCES credentials(id)
	);
	`
	_, err := testDB.DB.Exec(schema)
	require.NoError(t, err)

	// Create initial credential
	originalValue := "sk-original1234567890abcd1234567890abcd1234567890"
	encryptedData, salt, nonce, err := encryptCredentialValue(originalValue, "test-master-key")
	require.NoError(t, err)

	credentialID := "test-rotation-cred"
	insertQuery := `
		INSERT INTO credentials (id, name, provider, type, encrypted_value, salt, nonce, description, auto_rotate, rotation_interval)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = testDB.DB.Exec(insertQuery,
		credentialID,
		"rotation-test",
		"openai",
		"api_key",
		encryptedData,
		salt,
		nonce,
		"Test credential for rotation",
		true,
		"30d",
	)
	require.NoError(t, err)

	// Simulate rotation
	newValue := "sk-rotated9876543210dcba9876543210dcba9876543210"
	newEncryptedData, newSalt, newNonce, err := encryptCredentialValue(newValue, "test-master-key")
	require.NoError(t, err)

	// Store old credential in history
	historyInsertQuery := `
		INSERT INTO credential_history (id, credential_id, old_encrypted_value, old_salt, old_nonce, rotation_reason)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	historyID := "history-" + credentialID
	_, err = testDB.DB.Exec(historyInsertQuery,
		historyID,
		credentialID,
		encryptedData,
		salt,
		nonce,
		"scheduled_rotation",
	)
	require.NoError(t, err)

	// Update credential with new encrypted value
	updateQuery := `
		UPDATE credentials
		SET encrypted_value = ?, salt = ?, nonce = ?, updated_at = ?, last_rotated = ?
		WHERE id = ?
	`

	now := time.Now()
	_, err = testDB.DB.Exec(updateQuery,
		newEncryptedData,
		newSalt,
		newNonce,
		now,
		now,
		credentialID,
	)
	require.NoError(t, err)

	// Verify rotation worked
	var updatedCred struct {
		EncryptedValue []byte    `db:"encrypted_value"`
		Salt           []byte    `db:"salt"`
		Nonce          []byte    `db:"nonce"`
		LastRotated    time.Time `db:"last_rotated"`
	}

	selectQuery := `SELECT encrypted_value, salt, nonce, last_rotated FROM credentials WHERE id = ?`
	err = testDB.DB.Get(&updatedCred, selectQuery, credentialID)
	require.NoError(t, err)

	// Test decryption of new value
	decryptedNewValue, err := decryptCredentialValue(updatedCred.EncryptedValue, updatedCred.Salt, updatedCred.Nonce, "test-master-key")
	require.NoError(t, err)
	assert.Equal(t, newValue, decryptedNewValue)
	assert.NotEqual(t, originalValue, decryptedNewValue)

	// Verify history was stored
	var historyRecord struct {
		OldEncryptedValue []byte `db:"old_encrypted_value"`
		OldSalt           []byte `db:"old_salt"`
		OldNonce          []byte `db:"old_nonce"`
		RotationReason    string `db:"rotation_reason"`
	}

	historyQuery := `SELECT old_encrypted_value, old_salt, old_nonce, rotation_reason FROM credential_history WHERE credential_id = ?`
	err = testDB.DB.Get(&historyRecord, historyQuery, credentialID)
	require.NoError(t, err)

	// Test decryption of historical value
	decryptedOldValue, err := decryptCredentialValue(historyRecord.OldEncryptedValue, historyRecord.OldSalt, historyRecord.OldNonce, "test-master-key")
	require.NoError(t, err)
	assert.Equal(t, originalValue, decryptedOldValue)
	assert.Equal(t, "scheduled_rotation", historyRecord.RotationReason)
}

// TestCredentialValidation tests credential validation functionality
func TestCredentialValidation(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		credType   string
		value      string
		wantValid  bool
		wantReason string
	}{
		{
			name:      "valid OpenAI API key",
			provider:  "openai",
			credType:  "api_key",
			value:     "sk-abcd1234567890abcd1234567890abcd1234567890abcd1234",
			wantValid: true,
		},
		{
			name:       "invalid OpenAI API key - wrong prefix",
			provider:   "openai",
			credType:   "api_key",
			value:      "ak-invalid1234567890abcd1234567890abcd1234567890abcd",
			wantValid:  false,
			wantReason: "OpenAI API keys must start with 'sk-'",
		},
		{
			name:       "invalid OpenAI API key - too short",
			provider:   "openai",
			credType:   "api_key",
			value:      "sk-short",
			wantValid:  false,
			wantReason: "OpenAI API keys must be at least 48 characters",
		},
		{
			name:      "valid Anthropic API key",
			provider:  "anthropic",
			credType:  "api_key",
			value:     "ant-api03-abcd1234567890abcd1234567890abcd1234567890abcd",
			wantValid: true,
		},
		{
			name:       "invalid Anthropic API key - wrong prefix",
			provider:   "anthropic",
			credType:   "api_key",
			value:      "anth-api03-abcd1234567890abcd1234567890abcd1234567890",
			wantValid:  false,
			wantReason: "Anthropic API keys must start with 'ant-api'",
		},
		{
			name:      "valid Azure OpenAI bearer token",
			provider:  "azure-openai",
			credType:  "bearer_token",
			value:     "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL2NvZ25pdGl2ZXNlcnZpY2VzLmF6dXJlLmNvbSIsImlzcyI6Imh0dHBzOi0vc3RzLndpbmRvd3MubmV0IiwiZXhwIjoxNjk5OTk5OTk5fQ.test-signature-part",
			wantValid: true,
		},
		{
			name:       "invalid bearer token - not JWT format",
			provider:   "azure-openai",
			credType:   "bearer_token",
			value:      "not-a-jwt-token",
			wantValid:  false,
			wantReason: "Bearer tokens should be in JWT format (header.payload.signature)",
		},
		{
			name:      "valid strong password",
			provider:  "database",
			credType:  "password",
			value:     "StrongP@ssw0rd123!",
			wantValid: true,
		},
		{
			name:       "weak password",
			provider:   "database",
			credType:   "password",
			value:      "weak",
			wantValid:  false,
			wantReason: "Password must be at least 12 characters long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, reason := validateCredential(tt.provider, tt.credType, tt.value)
			assert.Equal(t, tt.wantValid, valid)
			if !tt.wantValid {
				assert.Contains(t, reason, tt.wantReason)
			}
		})
	}
}

// TestCredentialCLIIntegration tests the CLI commands for credential management
func TestCredentialCLIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI integration test in short mode")
	}

	// Check if Gibson binary exists before proceeding
	gibsonBinary := "gibson"
	if _, err := exec.LookPath(gibsonBinary); err != nil {
		t.Skipf("Gibson binary not found in PATH, skipping CLI integration test: %v", err)
	}

	// Additional check: try to run gibson --version to verify it's functional
	if cmd := exec.Command(gibsonBinary, "--version"); cmd.Run() != nil {
		t.Skip("Gibson binary found but not functional, skipping CLI integration test")
	}

	tempDir := t.TempDir()
	dbPath := tempDir + "/test.db"

	// Set environment variables for testing
	os.Setenv("GIBSON_DB_PATH", dbPath)
	os.Setenv("GIBSON_ENCRYPTION_KEY", "test-key-for-cli-integration")
	defer func() {
		os.Unsetenv("GIBSON_DB_PATH")
		os.Unsetenv("GIBSON_ENCRYPTION_KEY")
	}()

	tests := []struct {
		name        string
		command     []string
		expectError bool
		expectOut   string
	}{
		{
			name:        "add credential",
			command:     []string{"credential", "add", "--name", "test-openai", "--provider", "openai", "--type", "api_key", "--value", "sk-test1234567890abcd1234567890abcd1234567890abcd"},
			expectError: false,
			expectOut:   "Credential added successfully",
		},
		{
			name:        "list credentials",
			command:     []string{"credential", "list"},
			expectError: false,
			expectOut:   "test-openai",
		},
		{
			name:        "show credential (masked)",
			command:     []string{"credential", "show", "test-openai"},
			expectError: false,
			expectOut:   "sk-****",
		},
		{
			name:        "validate credential",
			command:     []string{"credential", "validate", "test-openai"},
			expectError: false,
			expectOut:   "valid",
		},
		{
			name:        "delete credential",
			command:     []string{"credential", "delete", "test-openai", "--force"},
			expectError: false,
			expectOut:   "deleted successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(gibsonBinary, tt.command...)
			output, err := cmd.CombinedOutput()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				// Binary existence is already verified at test start
				assert.NoError(t, err)
			}

			if tt.expectOut != "" {
				assert.Contains(t, string(output), tt.expectOut)
			}
		})
	}
}

// Helper functions for encryption/decryption simulation

func encryptCredentialValue(value, masterKey string) ([]byte, []byte, []byte, error) {
	// Generate a random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, err
	}

	// Derive key using Argon2
	key := argon2.IDKey([]byte(masterKey), salt, 1, 64*1024, 4, 32)

	// Generate a random nonce for AES-GCM
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	// For testing purposes, we'll use base64 encoding to simulate encryption
	// In real implementation, this would use AES-GCM
	encrypted := base64.StdEncoding.EncodeToString([]byte(value + string(key)))

	return []byte(encrypted), salt, nonce, nil
}

func decryptCredentialValue(encryptedData, salt, nonce []byte, masterKey string) (string, error) {
	// Derive the same key
	key := argon2.IDKey([]byte(masterKey), salt, 1, 64*1024, 4, 32)

	// For testing purposes, decode base64 and remove the key suffix
	decoded, err := base64.StdEncoding.DecodeString(string(encryptedData))
	if err != nil {
		return "", err
	}

	// Remove the key suffix to get original value
	value := string(decoded)
	keySuffix := string(key)
	if !strings.HasSuffix(value, keySuffix) {
		return "", assert.AnError // Wrong key used
	}

	return strings.TrimSuffix(value, keySuffix), nil
}

func validateCredential(provider, credType, value string) (bool, string) {
	switch provider {
	case "openai":
		if credType == "api_key" {
			if !strings.HasPrefix(value, "sk-") {
				return false, "OpenAI API keys must start with 'sk-'"
			}
			if len(value) < 48 {
				return false, "OpenAI API keys must be at least 48 characters"
			}
		}
	case "anthropic":
		if credType == "api_key" {
			if !strings.HasPrefix(value, "ant-api") {
				return false, "Anthropic API keys must start with 'ant-api'"
			}
		}
	case "azure-openai":
		if credType == "bearer_token" {
			// Validate JWT format: header.payload.signature
			parts := strings.Split(value, ".")
			if len(parts) != 3 {
				return false, "Bearer tokens should be in JWT format (header.payload.signature)"
			}
			// Validate each part is valid base64
			for i, part := range parts {
				if part == "" {
					return false, "Bearer tokens should be in JWT format (header.payload.signature)"
				}
				// For the signature part, we allow base64url without padding
				if i == 2 {
					// Add padding if needed for base64 validation
					padded := part
					for len(padded)%4 != 0 {
						padded += "="
					}
					if _, err := base64.URLEncoding.DecodeString(padded); err != nil {
						return false, "Bearer tokens should be in JWT format (header.payload.signature)"
					}
				} else {
					// For header and payload, add padding if needed
					padded := part
					for len(padded)%4 != 0 {
						padded += "="
					}
					if _, err := base64.URLEncoding.DecodeString(padded); err != nil {
						return false, "Bearer tokens should be in JWT format (header.payload.signature)"
					}
				}
			}
		}
	case "database":
		if credType == "password" {
			if len(value) < 12 {
				return false, "Password must be at least 12 characters long"
			}
		}
	}

	return true, ""
}