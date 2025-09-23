package security

import (
	"fmt"
	"os"
	"path/filepath"
)

// Example showing how to use the secure keystore system
func ExampleFileKeyStore() {
	// Create a temporary directory for this example
	tempDir, err := os.MkdirTemp("", "gibson-keystore-example-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize keystore
	keyStore, err := NewFileKeyStore(tempDir)
	if err != nil {
		panic(fmt.Sprintf("Failed to create keystore: %v", err))
	}
	defer keyStore.Close()

	// Generate a new encryption key
	encryptionKey, err := keyStore.GenerateKey(KeyPurposeEncryption)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Store the key
	if err := keyStore.StoreKey(encryptionKey); err != nil {
		panic(fmt.Sprintf("Failed to store key: %v", err))
	}

	// Load the key back
	loadedKey, err := keyStore.LoadKey(encryptionKey.Metadata().ID, KeyPurposeEncryption)
	if err != nil {
		panic(fmt.Sprintf("Failed to load key: %v", err))
	}

	// Verify key data matches
	fmt.Printf("Key loaded successfully: %t\n", len(loadedKey.Data()) == KeySize)

	// Generate a signing key
	signingKey, err := keyStore.GenerateKey(KeyPurposeSigning)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate signing key: %v", err))
	}

	if err := keyStore.StoreKey(signingKey); err != nil {
		panic(fmt.Sprintf("Failed to store signing key: %v", err))
	}

	// List all encryption keys
	encKeys, err := keyStore.ListKeys(KeyPurposeEncryption)
	if err != nil {
		panic(fmt.Sprintf("Failed to list keys: %v", err))
	}

	fmt.Printf("Number of encryption keys: %d\n", len(encKeys))

	// Rotate the encryption key
	newEncKey, err := keyStore.RotateKey(KeyPurposeEncryption)
	if err != nil {
		panic(fmt.Sprintf("Failed to rotate key: %v", err))
	}

	fmt.Printf("New key version: %d\n", newEncKey.Metadata().Version)

	// Derive a key from master key
	salt := make([]byte, SaltSize)
	copy(salt, "example-salt-123")

	derivedKey, err := keyStore.DeriveKey(KeyPurposeMAC, salt, "session-mac")
	if err != nil {
		panic(fmt.Sprintf("Failed to derive key: %v", err))
	}

	fmt.Printf("Derived key length: %d bytes\n", len(derivedKey.Data()))

	// Clean up sensitive data
	encryptionKey.Clear()
	loadedKey.Clear()
	signingKey.Clear()
	newEncKey.Clear()
	derivedKey.Clear()

	// Output:
	// Key loaded successfully: true
	// Number of encryption keys: 1
	// New key version: 2
	// Derived key length: 32 bytes
}

// Example showing key rotation with versioning
func ExampleFileKeyStore_keyRotation() {
	tempDir, err := os.MkdirTemp("", "gibson-keystore-rotation-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	keyStore, err := NewFileKeyStore(tempDir)
	if err != nil {
		panic(err)
	}
	defer keyStore.Close()

	// Generate initial key
	key1, err := keyStore.GenerateKey(KeyPurposeEncryption)
	if err != nil {
		panic(err)
	}
	if err := keyStore.StoreKey(key1); err != nil {
		panic(err)
	}

	fmt.Printf("Initial key version: %d\n", key1.Metadata().Version)

	// Rotate key multiple times
	key2, err := keyStore.RotateKey(KeyPurposeEncryption)
	if err != nil {
		panic(err)
	}

	key3, err := keyStore.RotateKey(KeyPurposeEncryption)
	if err != nil {
		panic(err)
	}

	fmt.Printf("After 1st rotation: %d\n", key2.Metadata().Version)
	fmt.Printf("After 2nd rotation: %d\n", key3.Metadata().Version)

	// Load active key (should be the latest)
	activeKey, err := keyStore.LoadActiveKey(KeyPurposeEncryption)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Active key version: %d\n", activeKey.Metadata().Version)

	// List all keys (including inactive ones)
	allKeys, err := keyStore.ListKeys(KeyPurposeEncryption)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Total keys stored: %d\n", len(allKeys))

	// Output:
	// Initial key version: 1
	// After 1st rotation: 2
	// After 2nd rotation: 3
	// Active key version: 3
	// Total keys stored: 3
}

// Example showing secure memory handling
func ExampleSecureKey_securityFeatures() {
	// Generate test data
	testData := make([]byte, KeySize)
	copy(testData, "sensitive-key-data-that-needs-clearing")

	metadata := &KeyMetadata{
		ID:      "demo-key",
		Purpose: KeyPurposeEncryption,
		Version: 1,
	}

	// Create secure key
	secureKey := NewSecureKey(testData, metadata)

	// Data is accessible
	data := secureKey.Data()
	fmt.Printf("Key accessible: %t\n", len(data) == KeySize)

	// Clear sensitive data from memory
	secureKey.Clear()

	// Data is no longer accessible
	clearedData := secureKey.Data()
	fmt.Printf("Key cleared: %t\n", clearedData == nil)

	// Original test data is also cleared internally for security
	// (the internal data slice has been overwritten)

	// Output:
	// Key accessible: true
	// Key cleared: true
}

// Example showing file permissions and security
func ExampleFileKeyStore_securityFeatures() {
	tempDir, err := os.MkdirTemp("", "gibson-keystore-security-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	keyStore, err := NewFileKeyStore(tempDir)
	if err != nil {
		panic(err)
	}
	defer keyStore.Close()

	// Generate and store a key
	key, err := keyStore.GenerateKey(KeyPurposeEncryption)
	if err != nil {
		panic(err)
	}

	if err := keyStore.StoreKey(key); err != nil {
		panic(err)
	}

	// Check master key file permissions
	masterKeyPath := filepath.Join(tempDir, ".encryption_key")
	info, err := os.Stat(masterKeyPath)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Master key permissions: %o\n", info.Mode().Perm())

	// Check health of the keystore
	if err := keyStore.Health(); err != nil {
		panic(fmt.Sprintf("Health check failed: %v", err))
	}

	fmt.Println("Health check: passed")

	// Key files are stored with restricted permissions
	keyPath := filepath.Join(tempDir, string(KeyPurposeEncryption),
		key.Metadata().ID+".v1.key")

	if keyInfo, err := os.Stat(keyPath); err == nil {
		fmt.Printf("Key file permissions: %o\n", keyInfo.Mode().Perm())
	}

	// Output:
	// Master key permissions: 600
	// Health check: passed
	// Key file permissions: 600
}