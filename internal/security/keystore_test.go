package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a temporary directory for testing
func createTempDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "gibson-keystore-test-*")
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return tempDir
}

// Helper function to create a test keystore
func createTestKeyStore(t *testing.T) *FileKeyStore {
	tempDir := createTempDir(t)

	keyStore, err := NewFileKeyStore(tempDir)
	require.NoError(t, err)
	require.NotNil(t, keyStore)

	t.Cleanup(func() {
		keyStore.Close()
	})

	return keyStore
}

func TestSecureKey(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "NewSecureKey_ValidData",
			run: func(t *testing.T) {
				testData := []byte("test-key-data-32-bytes-long!!!")
				metadata := &KeyMetadata{
					ID:         "test-key",
					Purpose:    KeyPurposeEncryption,
					Version:    1,
					CreatedAt:  time.Now().UTC(),
					IsActive:   true,
					Salt:       make([]byte, SaltSize),
					Iterations: PBKDF2Iterations,
				}

				key := NewSecureKey(testData, metadata)
				assert.NotNil(t, key)
				assert.Equal(t, testData, key.Data())
				assert.Equal(t, metadata, key.Metadata())
			},
		},
		{
			name: "SecureKey_Clear",
			run: func(t *testing.T) {
				testData := []byte("sensitive-data-to-be-cleared!")
				metadata := &KeyMetadata{
					ID:      "test-key",
					Purpose: KeyPurposeEncryption,
				}

				key := NewSecureKey(testData, metadata)
				originalData := key.Data()
				assert.Equal(t, testData, originalData)

				key.Clear()
				clearedData := key.Data()
				assert.Nil(t, clearedData)
				assert.NotEqual(t, testData, key.data) // Internal data should be cleared
			},
		},
		{
			name: "SecureKey_Finalizer",
			run: func(t *testing.T) {
				testData := []byte("data-for-finalizer-test-123!!")
				metadata := &KeyMetadata{
					ID:      "test-key",
					Purpose: KeyPurposeEncryption,
				}

				// Create key and immediately lose reference
				createAndLoseReference := func() []byte {
					key := NewSecureKey(testData, metadata)
					return key.data // Return internal data slice
				}

				internalData := createAndLoseReference()

				// Force garbage collection
				runtime.GC()
				runtime.GC()

				// Give finalizer time to run
				time.Sleep(10 * time.Millisecond)
				runtime.GC()

				// The data should be cleared (though this test is somewhat unreliable
				// due to GC timing, it demonstrates the concept)
				assert.NotEqual(t, testData, internalData[:len(testData)])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestNewFileKeyStore(t *testing.T) {
	tests := []struct {
		name        string
		basePath    string
		expectError bool
	}{
		{
			name:        "ValidPath",
			basePath:    createTempDir(t),
			expectError: false,
		},
		{
			name:        "CustomPath",
			basePath:    createTempDir(t),
			expectError: false,
		},
		{
			name:        "InvalidPath",
			basePath:    "/proc/invalid/path/that/should/not/exist",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keyStore *FileKeyStore
			var err error

			if tt.basePath == "" {
				// Use default path (user home)
				keyStore, err = NewFileKeyStore("")
			} else {
				keyStore, err = NewFileKeyStore(tt.basePath)
			}

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, keyStore)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, keyStore)

				if keyStore != nil {
					keyStore.Close()
				}
			}
		})
	}
}

func TestFileKeyStore_GenerateKey(t *testing.T) {
	keyStore := createTestKeyStore(t)

	tests := []struct {
		name    string
		purpose KeyPurpose
	}{
		{"EncryptionKey", KeyPurposeEncryption},
		{"SigningKey", KeyPurposeSigning},
		{"MACKey", KeyPurposeMAC},
		{"KDFKey", KeyPurposeKDF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := keyStore.GenerateKey(tt.purpose)
			require.NoError(t, err)
			require.NotNil(t, key)

			// Verify key properties
			assert.Len(t, key.Data(), KeySize)
			assert.Equal(t, tt.purpose, key.Metadata().Purpose)
			assert.Equal(t, 1, key.Metadata().Version)
			assert.True(t, key.Metadata().IsActive)
			assert.NotEmpty(t, key.Metadata().ID)
			assert.Len(t, key.Metadata().Salt, SaltSize)
			assert.Equal(t, PBKDF2Iterations, key.Metadata().Iterations)

			// Verify key data is not all zeros
			allZero := true
			for _, b := range key.Data() {
				if b != 0 {
					allZero = false
					break
				}
			}
			assert.False(t, allZero, "Generated key should not be all zeros")
		})
	}
}

func TestFileKeyStore_StoreAndLoadKey(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate a test key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)

	// Store the key
	err = keyStore.StoreKey(key)
	require.NoError(t, err)

	// Load the key
	loadedKey, err := keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)
	require.NotNil(t, loadedKey)

	// Verify loaded key matches original
	assert.Equal(t, key.Data(), loadedKey.Data())
	assert.Equal(t, key.Metadata().ID, loadedKey.Metadata().ID)
	assert.Equal(t, key.Metadata().Purpose, loadedKey.Metadata().Purpose)
	assert.Equal(t, key.Metadata().Version, loadedKey.Metadata().Version)
}

func TestFileKeyStore_LoadKey_NotFound(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Try to load non-existent key
	key, err := keyStore.LoadKey("non-existent-key", KeyPurposeEncryption)
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "key not found")
}

func TestFileKeyStore_LoadActiveKey(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate and store multiple keys
	key1, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key1)
	require.NoError(t, err)

	key2, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	key2.metadata.Version = 2 // Higher version
	err = keyStore.StoreKey(key2)
	require.NoError(t, err)

	// Deactivate the first key
	key1.metadata.IsActive = false
	err = keyStore.StoreKey(key1)
	require.NoError(t, err)

	// Load active key (should be key2)
	activeKey, err := keyStore.LoadActiveKey(KeyPurposeEncryption)
	require.NoError(t, err)
	require.NotNil(t, activeKey)

	assert.Equal(t, key2.Data(), activeKey.Data())
	assert.Equal(t, key2.Metadata().ID, activeKey.Metadata().ID)
	assert.Equal(t, 2, activeKey.Metadata().Version)
	assert.True(t, activeKey.Metadata().IsActive)
}

func TestFileKeyStore_LoadActiveKey_NotFound(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Try to load active key when none exist
	key, err := keyStore.LoadActiveKey(KeyPurposeEncryption)
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "no active key found")
}

func TestFileKeyStore_RotateKey(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate initial key
	initialKey, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(initialKey)
	require.NoError(t, err)

	// Rotate the key
	newKey, err := keyStore.RotateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	require.NotNil(t, newKey)

	// Verify new key properties
	assert.Equal(t, 2, newKey.Metadata().Version) // Should be incremented
	assert.True(t, newKey.Metadata().IsActive)
	assert.NotEqual(t, initialKey.Data(), newKey.Data()) // Should be different data

	// Verify old key is deactivated
	oldKey, err := keyStore.LoadKey(initialKey.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)
	assert.False(t, oldKey.Metadata().IsActive)

	// Verify new key is the active key
	activeKey, err := keyStore.LoadActiveKey(KeyPurposeEncryption)
	require.NoError(t, err)
	assert.Equal(t, newKey.Data(), activeKey.Data())
}

func TestFileKeyStore_ListKeys(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Initially should be empty
	keys, err := keyStore.ListKeys(KeyPurposeEncryption)
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Generate and store multiple keys
	key1, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key1)
	require.NoError(t, err)

	key2, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key2)
	require.NoError(t, err)

	key3, err := keyStore.GenerateKey(KeyPurposeSigning)
	require.NoError(t, err)
	err = keyStore.StoreKey(key3)
	require.NoError(t, err)

	// List encryption keys
	encKeys, err := keyStore.ListKeys(KeyPurposeEncryption)
	require.NoError(t, err)
	assert.Len(t, encKeys, 2)

	// List signing keys
	sigKeys, err := keyStore.ListKeys(KeyPurposeSigning)
	require.NoError(t, err)
	assert.Len(t, sigKeys, 1)

	// Verify key IDs are present
	encKeyIDs := make([]string, len(encKeys))
	for i, key := range encKeys {
		encKeyIDs[i] = key.ID
	}
	assert.Contains(t, encKeyIDs, key1.Metadata().ID)
	assert.Contains(t, encKeyIDs, key2.Metadata().ID)
}

func TestFileKeyStore_DeactivateKey(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate and store key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key)
	require.NoError(t, err)

	// Verify key is initially active
	assert.True(t, key.Metadata().IsActive)

	// Deactivate the key
	err = keyStore.DeactivateKey(key.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)

	// Load key and verify it's deactivated
	deactivatedKey, err := keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)
	assert.False(t, deactivatedKey.Metadata().IsActive)
}

func TestFileKeyStore_DeleteKey(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate and store key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key)
	require.NoError(t, err)

	// Verify key exists
	_, err = keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)

	// Delete the key
	err = keyStore.DeleteKey(key.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)

	// Verify key no longer exists
	_, err = keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

func TestFileKeyStore_DeriveKey(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Test with valid salt and info
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i) // Predictable salt for testing
	}

	derivedKey, err := keyStore.DeriveKey(KeyPurposeEncryption, salt, "test-context")
	require.NoError(t, err)
	require.NotNil(t, derivedKey)

	// Verify derived key properties
	assert.Len(t, derivedKey.Data(), KeySize)
	assert.Equal(t, KeyPurposeEncryption, derivedKey.Metadata().Purpose)
	assert.Equal(t, salt, derivedKey.Metadata().Salt)
	assert.Equal(t, PBKDF2Iterations, derivedKey.Metadata().Iterations)

	// Derive another key with same parameters - should be identical
	derivedKey2, err := keyStore.DeriveKey(KeyPurposeEncryption, salt, "test-context")
	require.NoError(t, err)
	assert.Equal(t, derivedKey.Data(), derivedKey2.Data())

	// Derive key with different context - should be different
	derivedKey3, err := keyStore.DeriveKey(KeyPurposeEncryption, salt, "different-context")
	require.NoError(t, err)
	assert.NotEqual(t, derivedKey.Data(), derivedKey3.Data())
}

func TestFileKeyStore_DeriveKey_InvalidSalt(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Test with salt that's too short
	shortSalt := make([]byte, SaltSize-1)
	_, err := keyStore.DeriveKey(KeyPurposeEncryption, shortSalt, "test-context")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "salt too short")
}

func TestFileKeyStore_Health(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Health check should pass for properly initialized keystore
	err := keyStore.Health()
	assert.NoError(t, err)
}

func TestFileKeyStore_Health_Failures(t *testing.T) {
	tempDir := createTempDir(t)
	keyStore, err := NewFileKeyStore(tempDir)
	require.NoError(t, err)

	tests := []struct {
		name   string
		setup  func()
		errMsg string
	}{
		{
			name: "MasterKeyCleared",
			setup: func() {
				keyStore.masterKey.Clear()
				keyStore.masterKey = nil
			},
			errMsg: "master key not loaded",
		},
		{
			name: "BaseDirectoryRemoved",
			setup: func() {
				os.RemoveAll(tempDir)
			},
			errMsg: "base directory not accessible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			err := keyStore.Health()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestFileKeyStore_FilePermissions(t *testing.T) {
	tempDir := createTempDir(t)
	keyStore, err := NewFileKeyStore(tempDir)
	require.NoError(t, err)
	defer keyStore.Close()

	// Check master key file permissions
	masterKeyPath := filepath.Join(tempDir, ".encryption_key")
	info, err := os.Stat(masterKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(KeyFilePermissions), info.Mode().Perm())

	// Generate and store a key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key)
	require.NoError(t, err)

	// Check key file permissions
	keyPath := filepath.Join(tempDir, string(KeyPurposeEncryption),
		key.Metadata().ID+".v1.key")
	info, err = os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(KeyFilePermissions), info.Mode().Perm())
}

func TestFileKeyStore_AtomicOperations(t *testing.T) {
	tempDir := createTempDir(t)
	keyStore, err := NewFileKeyStore(tempDir)
	require.NoError(t, err)
	defer keyStore.Close()

	// Generate key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)

	// Store key (this should be atomic)
	err = keyStore.StoreKey(key)
	require.NoError(t, err)

	// Verify no temporary files are left behind
	keyDir := filepath.Join(tempDir, string(KeyPurposeEncryption))
	entries, err := os.ReadDir(keyDir)
	require.NoError(t, err)

	for _, entry := range entries {
		assert.False(t, strings.HasSuffix(entry.Name(), ".tmp"),
			"Temporary file should not exist: %s", entry.Name())
	}
}

func TestFileKeyStore_ConcurrentAccess(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate and store initial key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key)
	require.NoError(t, err)

	// Test concurrent reads
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- true }()

			// Load key multiple times
			for j := 0; j < 5; j++ {
				loadedKey, err := keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
				assert.NoError(t, err)
				if err == nil {
					assert.Equal(t, key.Data(), loadedKey.Data())
				}
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestFileKeyStore_KeyVersioning(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate initial key
	key1, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key1)
	require.NoError(t, err)

	// Create version 2 of the same key ID
	key2 := &SecureKey{
		data: make([]byte, KeySize),
		metadata: &KeyMetadata{
			ID:         key1.Metadata().ID, // Same ID
			Purpose:    KeyPurposeEncryption,
			Version:    2, // Higher version
			CreatedAt:  time.Now().UTC(),
			LastUsedAt: time.Now().UTC(),
			IsActive:   true,
			Salt:       make([]byte, SaltSize),
			Iterations: PBKDF2Iterations,
		},
	}
	// Fill with different data
	for i := range key2.data {
		key2.data[i] = byte(i)
	}

	err = keyStore.StoreKey(key2)
	require.NoError(t, err)

	// Load should return the latest version
	loadedKey, err := keyStore.LoadKey(key1.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)
	assert.Equal(t, 2, loadedKey.Metadata().Version)
	assert.Equal(t, key2.Data(), loadedKey.Data())
}

func TestFileKeyStore_MasterKeyPersistence(t *testing.T) {
	tempDir := createTempDir(t)

	// Create first keystore instance
	keyStore1, err := NewFileKeyStore(tempDir)
	require.NoError(t, err)

	// Get master key data
	masterKey1Data := keyStore1.masterKey.Data()
	keyStore1.Close()

	// Create second keystore instance (should load existing master key)
	keyStore2, err := NewFileKeyStore(tempDir)
	require.NoError(t, err)
	defer keyStore2.Close()

	// Master key should be the same
	masterKey2Data := keyStore2.masterKey.Data()
	assert.Equal(t, masterKey1Data, masterKey2Data)
}

func TestFileKeyStore_KeyCaching(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate and store key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key)
	require.NoError(t, err)

	// Load key first time
	startTime := time.Now()
	loadedKey1, err := keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)
	firstLoadTime := time.Since(startTime)

	// Load key second time (should be cached)
	startTime = time.Now()
	loadedKey2, err := keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)
	secondLoadTime := time.Since(startTime)

	// Verify both loads return the same data
	assert.Equal(t, loadedKey1.Data(), loadedKey2.Data())

	// Second load should be faster (though this is not guaranteed in all environments)
	t.Logf("First load: %v, Second load: %v", firstLoadTime, secondLoadTime)
}

func TestFileKeyStore_InvalidKeyFiles(t *testing.T) {
	tempDir := createTempDir(t)
	keyStore, err := NewFileKeyStore(tempDir)
	require.NoError(t, err)
	defer keyStore.Close()

	// Create directory for encryption keys
	encDir := filepath.Join(tempDir, string(KeyPurposeEncryption))
	err = os.MkdirAll(encDir, KeyDirectoryPermissions)
	require.NoError(t, err)

	// Create invalid key files
	invalidFiles := []struct {
		name    string
		content string
	}{
		{"invalid.key", "not json"},
		{"missing-metadata.key", `{"key_data": "dGVzdA=="}`},
		{"invalid-metadata.key", `{"metadata": "not-an-object", "key_data": "dGVzdA=="}`},
	}

	for _, file := range invalidFiles {
		filePath := filepath.Join(encDir, file.name)
		err = os.WriteFile(filePath, []byte(file.content), KeyFilePermissions)
		require.NoError(t, err)
	}

	// ListKeys should handle invalid files gracefully
	keys, err := keyStore.ListKeys(KeyPurposeEncryption)
	require.NoError(t, err)
	// Should return empty list since all files are invalid
	assert.Empty(t, keys)
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"Equal", []byte("hello"), []byte("hello"), true},
		{"NotEqual", []byte("hello"), []byte("world"), false},
		{"DifferentLengths", []byte("hello"), []byte("hi"), false},
		{"Empty", []byte{}, []byte{}, true},
		{"OneEmpty", []byte("hello"), []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := secureCompare(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKeyPurposeValidation(t *testing.T) {
	keyStore := createTestKeyStore(t)

	validPurposes := []KeyPurpose{
		KeyPurposeEncryption,
		KeyPurposeSigning,
		KeyPurposeMAC,
		KeyPurposeKDF,
	}

	for _, purpose := range validPurposes {
		t.Run(string(purpose), func(t *testing.T) {
			key, err := keyStore.GenerateKey(purpose)
			require.NoError(t, err)
			assert.Equal(t, purpose, key.Metadata().Purpose)
		})
	}
}

func TestKeyStoreCloseCleanup(t *testing.T) {
	keyStore := createTestKeyStore(t)

	// Generate and cache some keys
	key1, err := keyStore.GenerateKey(KeyPurposeEncryption)
	require.NoError(t, err)
	err = keyStore.StoreKey(key1)
	require.NoError(t, err)

	key2, err := keyStore.GenerateKey(KeyPurposeSigning)
	require.NoError(t, err)
	err = keyStore.StoreKey(key2)
	require.NoError(t, err)

	// Load keys to populate cache
	_, err = keyStore.LoadKey(key1.Metadata().ID, KeyPurposeEncryption)
	require.NoError(t, err)
	_, err = keyStore.LoadKey(key2.Metadata().ID, KeyPurposeSigning)
	require.NoError(t, err)

	// Verify cache has entries
	keyStore.cacheMu.RLock()
	cacheSize := len(keyStore.keyCache)
	keyStore.cacheMu.RUnlock()
	assert.Greater(t, cacheSize, 0)

	// Close keystore
	keyStore.Close()

	// Verify cache is cleared
	keyStore.cacheMu.RLock()
	assert.Empty(t, keyStore.keyCache)
	keyStore.cacheMu.RUnlock()

	// Verify master key is cleared
	assert.Nil(t, keyStore.masterKey)
}

// Benchmark tests
func BenchmarkFileKeyStore_GenerateKey(b *testing.B) {
	keyStore := createBenchKeyStore(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := keyStore.GenerateKey(KeyPurposeEncryption)
		if err != nil {
			b.Fatal(err)
		}
		key.Clear() // Clean up
	}
}

func BenchmarkFileKeyStore_StoreKey(b *testing.B) {
	keyStore := createBenchKeyStore(b)

	// Pre-generate keys
	keys := make([]*SecureKey, b.N)
	for i := 0; i < b.N; i++ {
		key, err := keyStore.GenerateKey(KeyPurposeEncryption)
		if err != nil {
			b.Fatal(err)
		}
		keys[i] = key
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyStore.StoreKey(keys[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileKeyStore_LoadKey(b *testing.B) {
	keyStore := createBenchKeyStore(b)

	// Pre-store a key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	if err != nil {
		b.Fatal(err)
	}
	err = keyStore.StoreKey(key)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loadedKey, err := keyStore.LoadKey(key.Metadata().ID, KeyPurposeEncryption)
		if err != nil {
			b.Fatal(err)
		}
		loadedKey.Clear() // Clean up
	}
}

func BenchmarkFileKeyStore_DeriveKey(b *testing.B) {
	keyStore := createBenchKeyStore(b)

	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		derivedKey, err := keyStore.DeriveKey(KeyPurposeEncryption, salt, "benchmark")
		if err != nil {
			b.Fatal(err)
		}
		derivedKey.Clear() // Clean up
	}
}

// Helper function for benchmarks
func createBenchKeyStore(b *testing.B) *FileKeyStore {
	tempDir, err := os.MkdirTemp("", "gibson-keystore-bench-*")
	if err != nil {
		b.Fatal(err)
	}

	keyStore, err := NewFileKeyStore(tempDir)
	if err != nil {
		b.Fatal(err)
	}

	b.Cleanup(func() {
		keyStore.Close()
		os.RemoveAll(tempDir)
	})

	return keyStore
}