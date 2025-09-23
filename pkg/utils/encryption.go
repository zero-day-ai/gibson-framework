// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package utils

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// CredentialDecryptor provides credential decryption utilities
// This mirrors the encryption logic from the credential service
type CredentialDecryptor struct {
	encryptionKey []byte
}

// NewCredentialDecryptor creates a new credential decryptor
func NewCredentialDecryptor(encryptionKey []byte) *CredentialDecryptor {
	return &CredentialDecryptor{
		encryptionKey: encryptionKey,
	}
}

// DecryptValue decrypts a credential value using the same logic as the credential service
func (cd *CredentialDecryptor) DecryptValue(encrypted, iv, salt []byte) (string, error) {
	// Derive the same key using the stored salt
	key, err := scrypt.Key(cd.encryptionKey, salt, 32768, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %w", err)
	}

	// Decrypt using XOR (same as encryption in credential service)
	decrypted := make([]byte, len(encrypted))
	for i := range encrypted {
		decrypted[i] = encrypted[i] ^ key[i%len(key)]
	}

	return string(decrypted), nil
}

// EncryptValue encrypts a credential value using the same logic as the credential service
func (cd *CredentialDecryptor) EncryptValue(value string) (encrypted, iv, salt []byte, err error) {
	// Generate random salt for key derivation
	salt = make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random IV
	iv = make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Derive key using scrypt
	key, err := scrypt.Key(cd.encryptionKey, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt using XOR
	encrypted = make([]byte, len(value))
	valueBytes := []byte(value)
	for i := range valueBytes {
		encrypted[i] = valueBytes[i] ^ key[i%len(key)]
	}

	return encrypted, iv, salt, nil
}