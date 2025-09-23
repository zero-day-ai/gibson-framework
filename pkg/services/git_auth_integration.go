// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"fmt"
	"os"

	"github.com/go-git/go-git/v5/plumbing/transport"
	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/internal/model"
)

// GitServiceWithAuth extends GitService with authentication capabilities
type GitServiceWithAuth struct {
	*GitService
	authenticator *GitAuthenticator
}

// NewGitServiceWithAuth creates a GitService enhanced with authentication
func NewGitServiceWithAuth(gitService *GitService, authenticator *GitAuthenticator) *GitServiceWithAuth {
	return &GitServiceWithAuth{
		GitService:    gitService,
		authenticator: authenticator,
	}
}

// CloneWithAuth clones a repository using the authentication system
func (gs *GitServiceWithAuth) CloneWithAuth(ctx context.Context, repoURL, localPath string, options GitCloneOptions) error {
	// Determine auth method based on options or auto-detect
	authType := options.AuthType
	if authType == "" {
		if options.SSHKeyPath != "" {
			authType = coremodels.PayloadRepositoryAuthTypeSSH
		} else if options.Token != "" || options.Password != "" {
			authType = coremodels.PayloadRepositoryAuthTypeHTTPS
		} else {
			authType = coremodels.PayloadRepositoryAuthTypeNone
		}
	}

	// Get authentication method
	auth, err := gs.authenticator.GetAuthentication(ctx, repoURL, authType)
	if err != nil {
		return fmt.Errorf("failed to get authentication for repository %s: %w", repoURL, err)
	}

	// Update clone options with authentication
	updatedOptions := options
	updatedOptions.URL = repoURL
	updatedOptions.LocalPath = localPath

	// Use the GitService's existing clone method with our authentication
	return gs.cloneWithTransportAuth(ctx, updatedOptions, auth)
}

// cloneWithTransportAuth is a helper to clone with go-git transport auth
func (gs *GitServiceWithAuth) cloneWithTransportAuth(ctx context.Context, options GitCloneOptions, auth transport.AuthMethod) error {
	// This would integrate with the existing GitService.Clone method
	// For now, we'll provide the interface for the integration

	// In a real implementation, you would:
	// 1. Create a git.CloneOptions struct
	// 2. Set the Auth field to our auth method
	// 3. Call git.PlainClone or git.PlainCloneContext

	return fmt.Errorf("integration with GitService.Clone method needs to be implemented")
}

// PullWithAuth pulls changes from a repository using authentication
func (gs *GitServiceWithAuth) PullWithAuth(ctx context.Context, repoPath, repoURL string, authType coremodels.PayloadRepositoryAuthType) error {
	auth, err := gs.authenticator.GetAuthentication(ctx, repoURL, authType)
	if err != nil {
		return fmt.Errorf("failed to get authentication for pull: %w", err)
	}

	// Integration point with GitService.Pull method
	_ = auth // Use auth in the pull operation
	return fmt.Errorf("integration with GitService.Pull method needs to be implemented")
}

// ValidateAccess validates that we can access a repository
func (gs *GitServiceWithAuth) ValidateAccess(ctx context.Context, repoURL string, authType coremodels.PayloadRepositoryAuthType) error {
	return gs.authenticator.ValidateRepositoryAccess(ctx, repoURL, authType)
}

// GetCredentialInfo returns information about available Git credentials
func (gs *GitServiceWithAuth) GetCredentialInfo(ctx context.Context) ([]*GitCredentialInfo, error) {
	return gs.authenticator.ListGitCredentials(ctx)
}

// AuthenticationHelper provides convenience methods for Git authentication
type AuthenticationHelper struct {
	authenticator *GitAuthenticator
}

// NewAuthenticationHelper creates a new authentication helper
func NewAuthenticationHelper(authenticator *GitAuthenticator) *AuthenticationHelper {
	return &AuthenticationHelper{
		authenticator: authenticator,
	}
}

// SetupSSHKey configures SSH key authentication
func (ah *AuthenticationHelper) SetupSSHKey(ctx context.Context, name, keyContent, repoURL string) error {
	// Store SSH private key as a credential
	_, err := ah.authenticator.StoreGitCredential(ctx, name, repoURL, keyContent, model.CredentialTypeCustom)
	if err != nil {
		return fmt.Errorf("failed to store SSH key: %w", err)
	}

	return nil
}

// SetupPersonalAccessToken configures PAT authentication
func (ah *AuthenticationHelper) SetupPersonalAccessToken(ctx context.Context, name, token, repoURL string) error {
	_, err := ah.authenticator.StoreGitCredential(ctx, name, repoURL, token, model.CredentialTypeBearer)
	if err != nil {
		return fmt.Errorf("failed to store personal access token: %w", err)
	}

	return nil
}

// SetupBasicAuth configures username/password authentication
func (ah *AuthenticationHelper) SetupBasicAuth(ctx context.Context, name, username, password, repoURL string) error {
	credentials := fmt.Sprintf("%s:%s", username, password)
	_, err := ah.authenticator.StoreGitCredential(ctx, name, repoURL, credentials, model.CredentialTypeBasic)
	if err != nil {
		return fmt.Errorf("failed to store basic auth credentials: %w", err)
	}

	return nil
}

// TestAuthentication tests if authentication works for a given repository
func (ah *AuthenticationHelper) TestAuthentication(ctx context.Context, repoURL string, authType coremodels.PayloadRepositoryAuthType) (*GitAuthenticationResult, error) {
	result, err := ah.authenticator.GetAuthenticationWithDetails(ctx, repoURL, authType)
	if err != nil {
		return nil, err
	}

	// Additional validation could be performed here
	// such as attempting a git ls-remote operation

	return result, nil
}

// GetAuthenticationStatus returns the current authentication status for repositories
func (ah *AuthenticationHelper) GetAuthenticationStatus(ctx context.Context) map[string]interface{} {
	status := make(map[string]interface{})

	// Cache status
	cacheStatus := ah.authenticator.GetCacheStatus()
	status["cache"] = map[string]interface{}{
		"entries": len(cacheStatus),
		"details": cacheStatus,
	}

	// SSH key discovery status
	sshKeys := getDefaultSSHKeyPaths()
	discoveredKeys := make([]string, 0)
	for _, keyPath := range sshKeys {
		if _, err := os.Stat(keyPath); err == nil {
			discoveredKeys = append(discoveredKeys, keyPath)
		}
	}
	status["ssh_keys"] = map[string]interface{}{
		"searched_paths": sshKeys,
		"discovered":     discoveredKeys,
	}

	// Credential count
	if creds, err := ah.authenticator.ListGitCredentials(ctx); err == nil {
		status["stored_credentials"] = map[string]interface{}{
			"count": len(creds),
		}
	}

	return status
}