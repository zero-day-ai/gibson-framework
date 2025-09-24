// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/service"
)

// ExampleGitAuthSetup demonstrates how to set up Git authentication
func ExampleGitAuthSetup() {
	ctx := context.Background()

	// Initialize Gibson's components
	gibsonHome, err := getGibsonHome()
	if err != nil {
		fmt.Printf("Error getting gibson home: %v\n", err)
		return
	}

	// Initialize database connection
	dbPath := filepath.Join(gibsonHome, "gibson.db")
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", dbPath)
	repo, err := dao.NewSQLiteRepository(dsn)
	if err != nil {
		fmt.Printf("Error initializing repository: %v\n", err)
		return
	}

	// Read encryption key
	encryptionKey, err := readGibsonEncryptionKey(gibsonHome)
	if err != nil {
		fmt.Printf("Error reading encryption key: %v\n", err)
		return
	}

	// Create service factory
	logger := slog.Default()
	serviceFactory := service.NewServiceFactory(repo, logger, encryptionKey)

	// Create Git authenticator
	authConfig := &GitAuthConfig{
		SSHKeyPaths:    getDefaultSSHKeyPaths(),
		CacheTimeout:   15 * 60, // 15 minutes
		// KnownHostsPath can be set if needed
	}

	gitAuth := NewGitAuthenticator(serviceFactory, encryptionKey, authConfig)

	// Example: Store a GitHub personal access token
	token := "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Replace with actual token
	_, err = gitAuth.StoreGitCredential(ctx, "github-token", "https://github.com", token, model.CredentialTypeBearer)
	if err != nil {
		fmt.Printf("Error storing credential: %v\n", err)
		return
	}

	// Example: Test repository access
	repoURL := "https://github.com/user/private-repo.git"
	err = gitAuth.ValidateRepositoryAccess(ctx, repoURL, coremodels.PayloadRepositoryAuthTypeHTTPS)
	if err != nil {
		fmt.Printf("Repository access validation failed: %v\n", err)
		return
	}

	fmt.Println("Git authentication setup completed successfully!")
}

// Helper functions

// getGibsonHome returns the Gibson home directory
func getGibsonHome() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".gibson"), nil
}

// readGibsonEncryptionKey reads the encryption key from Gibson home
func readGibsonEncryptionKey(gibsonHome string) ([]byte, error) {
	keyPath := filepath.Join(gibsonHome, ".encryption_key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption key file: %w", err)
	}

	// The key might be base64 encoded
	return keyData, nil
}

// GitAuthHelperConfig provides configuration for Git authentication helper
type GitAuthHelperConfig struct {
	GibsonHome     string
	DatabasePath   string
	EncryptionKey  []byte
	ServiceFactory *service.ServiceFactory
}

// NewGitAuthHelper creates a ready-to-use Git authentication helper
func NewGitAuthHelper(config GitAuthHelperConfig) (*GitAuthenticator, error) {
	authConfig := &GitAuthConfig{
		SSHKeyPaths:  getDefaultSSHKeyPaths(),
		CacheTimeout: 15 * 60, // 15 minutes
	}

	if config.GibsonHome != "" {
		authConfig.KnownHostsPath = filepath.Join(config.GibsonHome, ".ssh", "known_hosts")
	}

	return NewGitAuthenticator(config.ServiceFactory, config.EncryptionKey, authConfig), nil
}

// GitAuthenticationResult provides information about authentication attempts
type GitAuthenticationResult struct {
	Success    bool
	AuthType   coremodels.PayloadRepositoryAuthType
	Method     string
	Error      string
	CacheHit   bool
	Credential *GitCredentialInfo
}

// GetAuthenticationWithDetails returns authentication method with detailed results
func (ga *GitAuthenticator) GetAuthenticationWithDetails(ctx context.Context, repoURL string, authType coremodels.PayloadRepositoryAuthType) (*GitAuthenticationResult, error) {
	result := &GitAuthenticationResult{
		AuthType: authType,
	}

	// Check cache
	cacheKey := fmt.Sprintf("%s:%s", repoURL, string(authType))
	if _, exists := ga.credentialCache[cacheKey]; exists {
		result.CacheHit = true
		result.Method = "cached"
	}

	auth, err := ga.GetAuthentication(ctx, repoURL, authType)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	result.Success = true
	if auth != nil {
		result.Method = fmt.Sprintf("%T", auth)
	} else {
		result.Method = "none (public repository)"
	}

	return result, nil
}