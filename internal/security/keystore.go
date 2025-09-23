// Package security provides secure key storage and management for Gibson framework
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const (
	// KeySize defines the size of encryption keys (32 bytes for AES-256)
	KeySize = 32

	// SaltSize defines the size of salt used in key derivation
	SaltSize = 16

	// PBKDF2Iterations defines the number of iterations for key derivation
	PBKDF2Iterations = 100000

	// KeyFilePermissions sets restrictive permissions for key files (owner read/write only)
	KeyFilePermissions = 0600

	// KeyDirectoryPermissions sets permissions for key directories
	KeyDirectoryPermissions = 0700

	// MaxKeyVersions limits the number of key versions to keep
	MaxKeyVersions = 3
)

// KeyPurpose defines the intended use of a key
type KeyPurpose string

const (
	// KeyPurposeEncryption for data encryption/decryption
	KeyPurposeEncryption KeyPurpose = "encryption"

	// KeyPurposeSigning for digital signatures
	KeyPurposeSigning KeyPurpose = "signing"

	// KeyPurposeMAC for message authentication codes
	KeyPurposeMAC KeyPurpose = "mac"

	// KeyPurposeKDF for key derivation functions
	KeyPurposeKDF KeyPurpose = "kdf"
)

// KeyMetadata contains information about a stored key
type KeyMetadata struct {
	ID          string     `json:"id"`
	Purpose     KeyPurpose `json:"purpose"`
	Version     int        `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  time.Time  `json:"last_used_at"`
	IsActive    bool       `json:"is_active"`
	Salt        []byte     `json:"salt"`
	Iterations  int        `json:"iterations"`
}

// KeyEntry represents a complete key with its metadata
type KeyEntry struct {
	Metadata *KeyMetadata `json:"metadata"`
	KeyData  []byte       `json:"key_data"`
}

// SecureKey represents a key in memory with automatic cleanup
type SecureKey struct {
	data     []byte
	metadata *KeyMetadata
	mu       sync.RWMutex
	cleared  bool
}

// NewSecureKey creates a new SecureKey with automatic cleanup
func NewSecureKey(data []byte, metadata *KeyMetadata) *SecureKey {
	key := &SecureKey{
		data:     make([]byte, len(data)),
		metadata: metadata,
	}
	copy(key.data, data)

	// Set finalizer for automatic cleanup
	runtime.SetFinalizer(key, (*SecureKey).finalize)

	return key
}

// Data returns a copy of the key data
func (sk *SecureKey) Data() []byte {
	sk.mu.RLock()
	defer sk.mu.RUnlock()

	if sk.cleared {
		return nil
	}

	// Return a copy to prevent external modification
	data := make([]byte, len(sk.data))
	copy(data, sk.data)
	return data
}

// Metadata returns the key metadata
func (sk *SecureKey) Metadata() *KeyMetadata {
	sk.mu.RLock()
	defer sk.mu.RUnlock()
	return sk.metadata
}

// Clear securely clears the key data from memory
func (sk *SecureKey) Clear() {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	if !sk.cleared {
		// Overwrite with random data multiple times for extra security
		for i := 0; i < 3; i++ {
			rand.Read(sk.data)
		}
		// Final overwrite with zeros
		for i := range sk.data {
			sk.data[i] = 0
		}
		sk.cleared = true
		runtime.SetFinalizer(sk, nil)
	}
}

// finalize ensures key data is cleared when object is garbage collected
func (sk *SecureKey) finalize() {
	sk.Clear()
}

// KeyStore defines the interface for secure key storage operations
type KeyStore interface {
	// GenerateKey creates a new key for the specified purpose
	GenerateKey(purpose KeyPurpose) (*SecureKey, error)

	// StoreKey saves a key to persistent storage
	StoreKey(key *SecureKey) error

	// LoadKey retrieves a key by ID and purpose
	LoadKey(id string, purpose KeyPurpose) (*SecureKey, error)

	// LoadActiveKey retrieves the currently active key for a purpose
	LoadActiveKey(purpose KeyPurpose) (*SecureKey, error)

	// RotateKey creates a new key version and marks it as active
	RotateKey(purpose KeyPurpose) (*SecureKey, error)

	// ListKeys returns metadata for all keys of a specific purpose
	ListKeys(purpose KeyPurpose) ([]*KeyMetadata, error)

	// DeactivateKey marks a key as inactive (but doesn't delete it)
	DeactivateKey(id string, purpose KeyPurpose) error

	// DeleteKey permanently removes a key from storage
	DeleteKey(id string, purpose KeyPurpose) error

	// DeriveKey derives a key from the master key using PBKDF2
	DeriveKey(purpose KeyPurpose, salt []byte, info string) (*SecureKey, error)

	// Health checks the integrity of the key store
	Health() error
}

// FileKeyStore implements KeyStore using the filesystem
type FileKeyStore struct {
	basePath    string
	masterKey   *SecureKey
	keyCache    map[string]*SecureKey
	cacheMu     sync.RWMutex
	storeMu     sync.RWMutex
}

// NewFileKeyStore creates a new file-based key store
func NewFileKeyStore(basePath string) (*FileKeyStore, error) {
	if basePath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		basePath = filepath.Join(homeDir, ".gibson")
	}

	// Ensure directory exists with correct permissions
	if err := os.MkdirAll(basePath, KeyDirectoryPermissions); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}

	keyStore := &FileKeyStore{
		basePath: basePath,
		keyCache: make(map[string]*SecureKey),
	}

	// Initialize or load master key
	if err := keyStore.initializeMasterKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize master key: %w", err)
	}

	return keyStore, nil
}

// initializeMasterKey creates or loads the master key
func (fks *FileKeyStore) initializeMasterKey() error {
	masterKeyPath := filepath.Join(fks.basePath, ".encryption_key")

	// Check if master key file exists
	if _, err := os.Stat(masterKeyPath); os.IsNotExist(err) {
		// Generate new master key
		return fks.generateMasterKey(masterKeyPath)
	} else if err != nil {
		return fmt.Errorf("failed to check master key file: %w", err)
	}

	// Load existing master key
	return fks.loadMasterKey(masterKeyPath)
}

// generateMasterKey creates a new master key and saves it
func (fks *FileKeyStore) generateMasterKey(path string) error {
	// Generate random key data
	keyData := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Generate salt for the master key
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create metadata for master key
	metadata := &KeyMetadata{
		ID:         "master",
		Purpose:    KeyPurposeKDF,
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		IsActive:   true,
		Salt:       salt,
		Iterations: PBKDF2Iterations,
	}

	// Create secure key
	fks.masterKey = NewSecureKey(keyData, metadata)

	// Save to file
	return fks.saveMasterKeyToFile(path)
}

// loadMasterKey loads the master key from file
func (fks *FileKeyStore) loadMasterKey(path string) error {
	// Read and parse the key file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read master key file: %w", err)
	}

	var keyEntry KeyEntry
	if err := json.Unmarshal(data, &keyEntry); err != nil {
		return fmt.Errorf("failed to parse master key file: %w", err)
	}

	// Decode base64 key data
	keyData, err := base64.StdEncoding.DecodeString(string(keyEntry.KeyData))
	if err != nil {
		return fmt.Errorf("failed to decode master key data: %w", err)
	}

	// Create secure key
	fks.masterKey = NewSecureKey(keyData, keyEntry.Metadata)

	return nil
}

// saveMasterKeyToFile saves the master key to file with proper permissions
func (fks *FileKeyStore) saveMasterKeyToFile(path string) error {
	if fks.masterKey == nil {
		return errors.New("master key is nil")
	}

	// Encode key data as base64
	encodedData := base64.StdEncoding.EncodeToString(fks.masterKey.Data())

	keyEntry := KeyEntry{
		Metadata: fks.masterKey.Metadata(),
		KeyData:  []byte(encodedData),
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(keyEntry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal master key: %w", err)
	}

	// Write to temporary file first for atomic operation
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, jsonData, KeyFilePermissions); err != nil {
		return fmt.Errorf("failed to write temporary master key file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename master key file: %w", err)
	}

	return nil
}

// GenerateKey creates a new key for the specified purpose
func (fks *FileKeyStore) GenerateKey(purpose KeyPurpose) (*SecureKey, error) {
	// Generate random key data
	keyData := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
		return nil, fmt.Errorf("failed to generate key data: %w", err)
	}

	// Generate unique ID
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}
	keyID := base64.RawURLEncoding.EncodeToString(idBytes)

	// Generate salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create metadata
	metadata := &KeyMetadata{
		ID:         keyID,
		Purpose:    purpose,
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		IsActive:   true,
		Salt:       salt,
		Iterations: PBKDF2Iterations,
	}

	return NewSecureKey(keyData, metadata), nil
}

// StoreKey saves a key to persistent storage
func (fks *FileKeyStore) StoreKey(key *SecureKey) error {
	return fks.storeKeyInternal(key, true)
}

// storeKeyInternal is the internal implementation with optional locking
func (fks *FileKeyStore) storeKeyInternal(key *SecureKey, useLock bool) error {
	if key == nil {
		return errors.New("key is nil")
	}

	if useLock {
		fks.storeMu.Lock()
		defer fks.storeMu.Unlock()
	}

	metadata := key.Metadata()
	if metadata == nil {
		return errors.New("key metadata is nil")
	}

	// Create directory for the key purpose
	purposeDir := filepath.Join(fks.basePath, string(metadata.Purpose))
	if err := os.MkdirAll(purposeDir, KeyDirectoryPermissions); err != nil {
		return fmt.Errorf("failed to create purpose directory: %w", err)
	}

	// Create key file path
	keyPath := filepath.Join(purposeDir, fmt.Sprintf("%s.v%d.key", metadata.ID, metadata.Version))

	// Encode key data as base64
	encodedData := base64.StdEncoding.EncodeToString(key.Data())

	keyEntry := KeyEntry{
		Metadata: metadata,
		KeyData:  []byte(encodedData),
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(keyEntry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// Write to temporary file first for atomic operation
	tempPath := keyPath + ".tmp"
	if err := os.WriteFile(tempPath, jsonData, KeyFilePermissions); err != nil {
		return fmt.Errorf("failed to write temporary key file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, keyPath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename key file: %w", err)
	}

	// Cache the key
	fks.cacheMu.Lock()
	cacheKey := fmt.Sprintf("%s-%s", metadata.ID, string(metadata.Purpose))
	fks.keyCache[cacheKey] = key
	fks.cacheMu.Unlock()

	return nil
}

// LoadKey retrieves a key by ID and purpose
func (fks *FileKeyStore) LoadKey(id string, purpose KeyPurpose) (*SecureKey, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s-%s", id, string(purpose))
	fks.cacheMu.RLock()
	if cachedKey, exists := fks.keyCache[cacheKey]; exists {
		// Update last used time
		cachedKey.metadata.LastUsedAt = time.Now().UTC()
		fks.cacheMu.RUnlock()
		return cachedKey, nil
	}
	fks.cacheMu.RUnlock()

	// Load from file
	purposeDir := filepath.Join(fks.basePath, string(purpose))

	// Find the latest version of the key
	pattern := filepath.Join(purposeDir, fmt.Sprintf("%s.v*.key", id))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to find key files: %w", err)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("key not found: %s/%s", id, purpose)
	}

	// Load the most recent file (they should be sorted by version)
	var keyPath string
	var latestVersion int
	for _, match := range matches {
		// Parse version from filename
		var version int
		if _, err := fmt.Sscanf(filepath.Base(match), fmt.Sprintf("%s.v%%d.key", id), &version); err == nil {
			if version > latestVersion {
				latestVersion = version
				keyPath = match
			}
		}
	}

	if keyPath == "" {
		return nil, fmt.Errorf("no valid key file found for: %s/%s", id, purpose)
	}

	// Read and parse the key file
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var keyEntry KeyEntry
	if err := json.Unmarshal(data, &keyEntry); err != nil {
		return nil, fmt.Errorf("failed to parse key file: %w", err)
	}

	// Decode base64 key data
	keyData, err := base64.StdEncoding.DecodeString(string(keyEntry.KeyData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode key data: %w", err)
	}

	// Update last used time
	keyEntry.Metadata.LastUsedAt = time.Now().UTC()

	// Create secure key
	key := NewSecureKey(keyData, keyEntry.Metadata)

	// Cache the key
	fks.cacheMu.Lock()
	fks.keyCache[cacheKey] = key
	fks.cacheMu.Unlock()

	return key, nil
}

// LoadActiveKey retrieves the currently active key for a purpose
func (fks *FileKeyStore) LoadActiveKey(purpose KeyPurpose) (*SecureKey, error) {
	keys, err := fks.ListKeys(purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Find the active key with the highest version
	var activeKey *KeyMetadata
	for _, key := range keys {
		if key.IsActive && (activeKey == nil || key.Version > activeKey.Version) {
			activeKey = key
		}
	}

	if activeKey == nil {
		return nil, fmt.Errorf("no active key found for purpose: %s", purpose)
	}

	return fks.LoadKey(activeKey.ID, purpose)
}

// RotateKey creates a new key version and marks it as active
func (fks *FileKeyStore) RotateKey(purpose KeyPurpose) (*SecureKey, error) {
	fks.storeMu.Lock()
	defer fks.storeMu.Unlock()

	// List existing keys to determine next version
	keys, err := fks.ListKeys(purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to list existing keys: %w", err)
	}

	var maxVersion int
	var activeKeys []string

	for _, key := range keys {
		if key.Version > maxVersion {
			maxVersion = key.Version
		}
		if key.IsActive {
			activeKeys = append(activeKeys, key.ID)
		}
	}

	// Deactivate current active keys
	for _, keyID := range activeKeys {
		if err := fks.deactivateKeyInternal(keyID, purpose); err != nil {
			return nil, fmt.Errorf("failed to deactivate key %s: %w", keyID, err)
		}
	}

	// Generate new key with incremented version
	newKey, err := fks.GenerateKey(purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// Update version
	newKey.metadata.Version = maxVersion + 1

	// Store the new key (without locking since we already have the lock)
	if err := fks.storeKeyInternal(newKey, false); err != nil {
		return nil, fmt.Errorf("failed to store new key: %w", err)
	}

	// Clean up old versions if we have too many
	if err := fks.cleanupOldVersions(purpose); err != nil {
		// Log warning but don't fail the rotation
		fmt.Fprintf(os.Stderr, "Warning: failed to cleanup old key versions: %v\n", err)
	}

	return newKey, nil
}

// ListKeys returns metadata for all keys of a specific purpose
func (fks *FileKeyStore) ListKeys(purpose KeyPurpose) ([]*KeyMetadata, error) {
	purposeDir := filepath.Join(fks.basePath, string(purpose))

	// Check if directory exists
	if _, err := os.Stat(purposeDir); os.IsNotExist(err) {
		return []*KeyMetadata{}, nil
	}

	// Read directory
	entries, err := os.ReadDir(purposeDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read purpose directory: %w", err)
	}

	var keys []*KeyMetadata
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}

		keyPath := filepath.Join(purposeDir, entry.Name())
		data, err := os.ReadFile(keyPath)
		if err != nil {
			continue // Skip unreadable files
		}

		var keyEntry KeyEntry
		if err := json.Unmarshal(data, &keyEntry); err != nil {
			continue // Skip unparseable files
		}

		// Skip entries with invalid metadata
		if keyEntry.Metadata == nil || keyEntry.Metadata.ID == "" {
			continue
		}

		keys = append(keys, keyEntry.Metadata)
	}

	return keys, nil
}

// DeactivateKey marks a key as inactive (but doesn't delete it)
func (fks *FileKeyStore) DeactivateKey(id string, purpose KeyPurpose) error {
	fks.storeMu.Lock()
	defer fks.storeMu.Unlock()

	return fks.deactivateKeyInternal(id, purpose)
}

// deactivateKeyInternal is the internal implementation without locking
func (fks *FileKeyStore) deactivateKeyInternal(id string, purpose KeyPurpose) error {
	// Load the key
	key, err := fks.LoadKey(id, purpose)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}

	// Mark as inactive
	key.metadata.IsActive = false

	// Save the updated key (without locking since we already have the lock)
	return fks.storeKeyInternal(key, false)
}

// DeleteKey permanently removes a key from storage
func (fks *FileKeyStore) DeleteKey(id string, purpose KeyPurpose) error {
	fks.storeMu.Lock()
	defer fks.storeMu.Unlock()

	// Remove from cache
	cacheKey := fmt.Sprintf("%s-%s", id, string(purpose))
	fks.cacheMu.Lock()
	if cachedKey, exists := fks.keyCache[cacheKey]; exists {
		cachedKey.Clear() // Secure cleanup
		delete(fks.keyCache, cacheKey)
	}
	fks.cacheMu.Unlock()

	// Remove all versions of the key from filesystem
	purposeDir := filepath.Join(fks.basePath, string(purpose))
	pattern := filepath.Join(purposeDir, fmt.Sprintf("%s.v*.key", id))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to find key files: %w", err)
	}

	for _, keyPath := range matches {
		if err := os.Remove(keyPath); err != nil {
			return fmt.Errorf("failed to remove key file %s: %w", keyPath, err)
		}
	}

	return nil
}

// DeriveKey derives a key from the master key using PBKDF2
func (fks *FileKeyStore) DeriveKey(purpose KeyPurpose, salt []byte, info string) (*SecureKey, error) {
	if fks.masterKey == nil {
		return nil, errors.New("master key not initialized")
	}

	if len(salt) < SaltSize {
		return nil, fmt.Errorf("salt too short, minimum %d bytes required", SaltSize)
	}

	// Combine info with purpose for additional context in the derivation
	contextInfo := fmt.Sprintf("%s:%s", purpose, info)
	contextSalt := append(salt, []byte(contextInfo)...)

	// Derive key using PBKDF2 with SHA3-256
	derivedKey := pbkdf2.Key(fks.masterKey.Data(), contextSalt, PBKDF2Iterations, KeySize, sha3.New256)

	// Create metadata for derived key
	metadata := &KeyMetadata{
		ID:         base64.RawURLEncoding.EncodeToString(salt[:8]), // Use first 8 bytes of salt as ID
		Purpose:    purpose,
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		IsActive:   true,
		Salt:       salt,
		Iterations: PBKDF2Iterations,
	}

	return NewSecureKey(derivedKey, metadata), nil
}

// cleanupOldVersions removes old key versions, keeping only the latest MaxKeyVersions
func (fks *FileKeyStore) cleanupOldVersions(purpose KeyPurpose) error {
	keys, err := fks.ListKeys(purpose)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	// Group keys by ID
	keysByID := make(map[string][]*KeyMetadata)
	for _, key := range keys {
		keysByID[key.ID] = append(keysByID[key.ID], key)
	}

	// Clean up each key ID
	for keyID, versions := range keysByID {
		if len(versions) <= MaxKeyVersions {
			continue
		}

		// Sort by version (descending)
		sort.Slice(versions, func(i, j int) bool {
			return versions[i].Version > versions[j].Version
		})

		// Delete old versions (keep MaxKeyVersions)
		for i := MaxKeyVersions; i < len(versions); i++ {
			keyPath := filepath.Join(fks.basePath, string(purpose),
				fmt.Sprintf("%s.v%d.key", keyID, versions[i].Version))
			if err := os.Remove(keyPath); err != nil {
				return fmt.Errorf("failed to remove old key version %s: %w", keyPath, err)
			}
		}
	}

	return nil
}

// Health checks the integrity of the key store
func (fks *FileKeyStore) Health() error {
	// Check if base directory exists and is accessible
	if _, err := os.Stat(fks.basePath); err != nil {
		return fmt.Errorf("base directory not accessible: %w", err)
	}

	// Check if master key is loaded
	if fks.masterKey == nil {
		return errors.New("master key not loaded")
	}

	// Check master key file exists and is readable
	masterKeyPath := filepath.Join(fks.basePath, ".encryption_key")
	if _, err := os.Stat(masterKeyPath); err != nil {
		return fmt.Errorf("master key file not accessible: %w", err)
	}

	// Verify file permissions
	info, err := os.Stat(masterKeyPath)
	if err != nil {
		return fmt.Errorf("failed to check master key permissions: %w", err)
	}

	if info.Mode().Perm() != KeyFilePermissions {
		return fmt.Errorf("master key file has incorrect permissions: %v (expected %v)",
			info.Mode().Perm(), KeyFilePermissions)
	}

	return nil
}

// Close cleans up the key store and clears sensitive data
func (fks *FileKeyStore) Close() {
	fks.storeMu.Lock()
	defer fks.storeMu.Unlock()

	// Clear master key
	if fks.masterKey != nil {
		fks.masterKey.Clear()
		fks.masterKey = nil
	}

	// Clear cached keys
	fks.cacheMu.Lock()
	for _, key := range fks.keyCache {
		key.Clear()
	}
	fks.keyCache = make(map[string]*SecureKey)
	fks.cacheMu.Unlock()
}

// secureCompare performs a constant-time comparison of two byte slices
func secureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}