// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/gibson-sec/gibson-framework-2/internal/service"
	"github.com/google/uuid"
	"github.com/gibson-sec/gibson-framework-2/pkg/utils"
	ssh2 "golang.org/x/crypto/ssh"
)

// GitAuthenticator handles Git authentication for both SSH and HTTPS
type GitAuthenticator struct {
	credentialService service.CredentialService
	serviceFactory    *service.ServiceFactory
	decryptor         *utils.CredentialDecryptor
	cacheTimeout      time.Duration
	credentialCache   map[string]*CachedCredential
}

// CachedCredential represents a cached Git credential
type CachedCredential struct {
	Auth      transport.AuthMethod
	CachedAt  time.Time
	ExpiresAt time.Time
}

// GitAuthConfig holds configuration for Git authentication
type GitAuthConfig struct {
	// Default SSH key paths to search
	SSHKeyPaths []string
	// Cache timeout for credentials
	CacheTimeout time.Duration
	// Known hosts file path
	KnownHostsPath string
}

// NewGitAuthenticator creates a new Git authenticator
func NewGitAuthenticator(serviceFactory *service.ServiceFactory, encryptionKey []byte, config *GitAuthConfig) *GitAuthenticator {
	if config == nil {
		config = &GitAuthConfig{
			CacheTimeout: 15 * time.Minute,
		}
	}

	if len(config.SSHKeyPaths) == 0 {
		config.SSHKeyPaths = getDefaultSSHKeyPaths()
	}

	return &GitAuthenticator{
		credentialService: serviceFactory.CredentialService(),
		serviceFactory:    serviceFactory,
		decryptor:         utils.NewCredentialDecryptor(encryptionKey),
		cacheTimeout:      config.CacheTimeout,
		credentialCache:   make(map[string]*CachedCredential),
	}
}

// GetAuthentication returns appropriate authentication method for the given repository URL
func (ga *GitAuthenticator) GetAuthentication(ctx context.Context, repoURL string, authType coremodels.PayloadRepositoryAuthType) (transport.AuthMethod, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", repoURL, string(authType))
	if cached, exists := ga.credentialCache[cacheKey]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			return cached.Auth, nil
		}
		// Remove expired cache entry
		delete(ga.credentialCache, cacheKey)
	}

	var auth transport.AuthMethod
	var err error

	switch authType {
	case coremodels.PayloadRepositoryAuthTypeNone:
		auth = nil
	case coremodels.PayloadRepositoryAuthTypeSSH:
		auth, err = ga.getSSHAuthentication(ctx, repoURL)
	case coremodels.PayloadRepositoryAuthTypeHTTPS, coremodels.PayloadRepositoryAuthTypeToken:
		auth, err = ga.getHTTPSAuthentication(ctx, repoURL)
	default:
		// Auto-detect authentication type based on URL
		auth, err = ga.autoDetectAuthentication(ctx, repoURL)
	}

	if err != nil {
		return nil, err
	}

	// Cache the authentication method
	if auth != nil {
		ga.credentialCache[cacheKey] = &CachedCredential{
			Auth:      auth,
			CachedAt:  time.Now(),
			ExpiresAt: time.Now().Add(ga.cacheTimeout),
		}
	}

	return auth, nil
}

// getSSHAuthentication attempts to get SSH authentication
func (ga *GitAuthenticator) getSSHAuthentication(ctx context.Context, repoURL string) (transport.AuthMethod, error) {
	// First try to get SSH credentials from credential store
	sshCreds, err := ga.getCredentialsByType(ctx, model.CredentialTypeCustom, "ssh")
	if err == nil && len(sshCreds) > 0 {
		for _, cred := range sshCreds {
			// Decrypt the SSH private key
			decryptedKey, err := ga.decryptCredentialValue(cred)
			if err != nil {
				continue
			}

			// Try to create SSH auth with this key
			signer, err := ssh2.ParsePrivateKey([]byte(decryptedKey))
			if err != nil {
				continue
			}

			username := "git" // Default Git username for SSH
			if strings.Contains(repoURL, "@") {
				parts := strings.Split(strings.Split(repoURL, "://")[1], "@")
				if len(parts) > 1 {
					username = parts[0]
				}
			}

			return &ssh.PublicKeys{
				User:   username,
				Signer: signer,
			}, nil
		}
	}

	// Fall back to auto-discovery of SSH keys
	return ga.discoverSSHKeys(repoURL)
}

// getHTTPSAuthentication attempts to get HTTPS authentication
func (ga *GitAuthenticator) getHTTPSAuthentication(ctx context.Context, repoURL string) (transport.AuthMethod, error) {
	// Look for personal access tokens first
	tokenCreds, err := ga.getCredentialsByType(ctx, model.CredentialTypeBearer, "git")
	if err == nil && len(tokenCreds) > 0 {
		for _, cred := range tokenCreds {
			decryptedToken, err := ga.decryptCredentialValue(cred)
			if err != nil {
				continue
			}

			// Use token as password with empty username for GitHub/GitLab style auth
			return &http.BasicAuth{
				Username: "",
				Password: decryptedToken,
			}, nil
		}
	}

	// Look for basic authentication credentials
	basicCreds, err := ga.getCredentialsByType(ctx, model.CredentialTypeBasic, "git")
	if err == nil && len(basicCreds) > 0 {
		for _, cred := range basicCreds {
			decryptedValue, err := ga.decryptCredentialValue(cred)
			if err != nil {
				continue
			}

			// Assume format is "username:password"
			parts := strings.SplitN(decryptedValue, ":", 2)
			if len(parts) == 2 {
				return &http.BasicAuth{
					Username: parts[0],
					Password: parts[1],
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable HTTPS credentials found for repository: %s", repoURL)
}

// autoDetectAuthentication tries to determine appropriate authentication method
func (ga *GitAuthenticator) autoDetectAuthentication(ctx context.Context, repoURL string) (transport.AuthMethod, error) {
	if strings.HasPrefix(repoURL, "git@") || strings.Contains(repoURL, "ssh://") {
		return ga.getSSHAuthentication(ctx, repoURL)
	}

	if strings.HasPrefix(repoURL, "https://") {
		// Try HTTPS authentication, but don't fail if none found (public repo)
		auth, err := ga.getHTTPSAuthentication(ctx, repoURL)
		if err != nil {
			// Return nil auth for public HTTPS repositories
			return nil, nil
		}
		return auth, nil
	}

	return nil, nil
}

// discoverSSHKeys automatically discovers SSH keys from standard locations
func (ga *GitAuthenticator) discoverSSHKeys(repoURL string) (transport.AuthMethod, error) {
	sshKeyPaths := getDefaultSSHKeyPaths()

	username := "git" // Default Git username
	if strings.Contains(repoURL, "@") {
		parts := strings.Split(strings.Split(repoURL, "@")[0], "://")
		if len(parts) > 1 {
			username = parts[1]
		} else {
			username = parts[0]
		}
	}

	for _, keyPath := range sshKeyPaths {
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			continue
		}

		// Try to use this SSH key
		auth, err := ssh.NewPublicKeysFromFile(username, keyPath, "")
		if err != nil {
			// Try with potential passphrase (empty for now)
			continue
		}

		return auth, nil
	}

	return nil, fmt.Errorf("no SSH keys found in standard locations for repository: %s", repoURL)
}

// getDefaultSSHKeyPaths returns default SSH key locations to search
func getDefaultSSHKeyPaths() []string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return []string{}
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	return []string{
		filepath.Join(sshDir, "id_rsa"),
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_ecdsa"),
		filepath.Join(sshDir, "id_dsa"),
	}
}

// getCredentialsByType retrieves credentials from the credential service by type and tags
func (ga *GitAuthenticator) getCredentialsByType(ctx context.Context, credType model.CredentialType, tag string) ([]*model.Credential, error) {
	// Get all credentials
	allCreds, err := ga.credentialService.List(ctx)
	if err != nil {
		return nil, err
	}

	var matchingCreds []*model.Credential
	for _, cred := range allCreds {
		if cred.Type == credType && cred.IsActive() {
			// Check if credential has the required tag
			if tag == "" || cred.HasTag(tag) {
				matchingCreds = append(matchingCreds, cred)
			}
		}
	}

	return matchingCreds, nil
}

// decryptCredentialValue decrypts a credential value using the shared encryption utility
func (ga *GitAuthenticator) decryptCredentialValue(cred *model.Credential) (string, error) {
	return ga.decryptor.DecryptValue(cred.EncryptedValue, cred.EncryptionIV, cred.KeyDerivationSalt)
}

// StoreGitCredential stores a Git credential in the encrypted credential store
func (ga *GitAuthenticator) StoreGitCredential(ctx context.Context, name, repoURL, credentialValue string, credType model.CredentialType) (*model.Credential, error) {
	// Determine provider based on repository URL
	provider := model.ProviderCustom // Use custom provider for Git repositories

	// Create credential request
	req := &model.CredentialCreateRequest{
		Name:        name,
		Type:        credType,
		Provider:    provider,
		Description: fmt.Sprintf("Git credential for repository: %s", repoURL),
		Value:       credentialValue,
		Tags:        []string{"git", "repository"},
	}

	return ga.credentialService.Create(ctx, req)
}

// ClearAuthCache clears the authentication cache
func (ga *GitAuthenticator) ClearAuthCache() {
	ga.credentialCache = make(map[string]*CachedCredential)
}

// GetCacheStatus returns information about cached credentials
func (ga *GitAuthenticator) GetCacheStatus() map[string]time.Time {
	status := make(map[string]time.Time)
	for key, cached := range ga.credentialCache {
		status[key] = cached.ExpiresAt
	}
	return status
}

// ValidateRepositoryAccess validates that we can access a repository with current credentials
func (ga *GitAuthenticator) ValidateRepositoryAccess(ctx context.Context, repoURL string, authType coremodels.PayloadRepositoryAuthType) error {
	auth, err := ga.GetAuthentication(ctx, repoURL, authType)
	if err != nil {
		return fmt.Errorf("failed to get authentication: %w", err)
	}

	// This would typically involve a git ls-remote operation to test access
	// For now, we'll just validate that we have appropriate authentication
	if authType != coremodels.PayloadRepositoryAuthTypeNone && auth == nil {
		return fmt.Errorf("authentication required but none available for repository: %s", repoURL)
	}

	return nil
}

// Helper types for credential management

// GitCredentialInfo represents information about Git credentials
type GitCredentialInfo struct {
	ID           uuid.UUID                             `json:"id"`
	Name         string                                `json:"name"`
	Type         model.CredentialType                  `json:"type"`
	Provider     model.Provider                        `json:"provider"`
	AuthType     coremodels.PayloadRepositoryAuthType `json:"auth_type"`
	Description  string                                `json:"description"`
	Tags         []string                              `json:"tags"`
	CreatedAt    time.Time                             `json:"created_at"`
	LastUsed     *time.Time                            `json:"last_used,omitempty"`
}

// ListGitCredentials returns all Git-related credentials
func (ga *GitAuthenticator) ListGitCredentials(ctx context.Context) ([]*GitCredentialInfo, error) {
	allCreds, err := ga.credentialService.List(ctx)
	if err != nil {
		return nil, err
	}

	var gitCreds []*GitCredentialInfo
	for _, cred := range allCreds {
		if cred.HasTag("git") || cred.HasTag("repository") {
			authType := coremodels.PayloadRepositoryAuthTypeHTTPS
			if cred.Type == model.CredentialTypeCustom && cred.HasTag("ssh") {
				authType = coremodels.PayloadRepositoryAuthTypeSSH
			}

			gitCreds = append(gitCreds, &GitCredentialInfo{
				ID:          cred.ID,
				Name:        cred.Name,
				Type:        cred.Type,
				Provider:    cred.Provider,
				AuthType:    authType,
				Description: cred.Description,
				Tags:        cred.Tags,
				CreatedAt:   cred.CreatedAt,
				LastUsed:    cred.LastUsed,
			})
		}
	}

	return gitCreds, nil
}