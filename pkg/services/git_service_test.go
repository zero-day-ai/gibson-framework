// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGitService(t *testing.T) {
	tests := []struct {
		name     string
		config   GitServiceConfig
		expected GitServiceConfig
	}{
		{
			name:   "default config",
			config: GitServiceConfig{},
			expected: GitServiceConfig{
				DefaultDepth:  1,
				DefaultBranch: "main",
				BaseDir:       "/tmp/gibson-repos",
			},
		},
		{
			name: "custom config",
			config: GitServiceConfig{
				DefaultDepth:  5,
				DefaultBranch: "develop",
				BaseDir:       "/custom/path",
			},
			expected: GitServiceConfig{
				DefaultDepth:  5,
				DefaultBranch: "develop",
				BaseDir:       "/custom/path",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewGitService(tt.config)
			assert.Equal(t, tt.expected.DefaultDepth, service.config.DefaultDepth)
			assert.Equal(t, tt.expected.DefaultBranch, service.config.DefaultBranch)
			assert.Equal(t, tt.expected.BaseDir, service.config.BaseDir)
		})
	}
}

func TestGitService_ValidateURL(t *testing.T) {
	service := NewGitService(GetDefaultConfig())

	tests := []struct {
		name      string
		url       string
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid HTTPS URL",
			url:  "https://github.com/user/repo.git",
		},
		{
			name: "valid HTTP URL",
			url:  "http://github.com/user/repo.git",
		},
		{
			name: "valid SSH URL",
			url:  "git@github.com:user/repo.git",
		},
		{
			name: "valid SSH URL with protocol",
			url:  "ssh://git@github.com/user/repo.git",
		},
		{
			name:      "empty URL",
			url:       "",
			expectErr: true,
			errMsg:    "URL cannot be empty",
		},
		{
			name:      "invalid protocol",
			url:       "ftp://github.com/user/repo.git",
			expectErr: true,
			errMsg:    "URL must start with",
		},
		{
			name:      "invalid SSH format",
			url:       "git@github.com",
			expectErr: true,
			errMsg:    "SSH URL must be in format git@hostname:path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.ValidateURL(tt.url)

			if tt.expectErr {
				assert.True(t, result.IsErr())
				assert.Contains(t, result.Error().Error(), tt.errMsg)
			} else {
				assert.True(t, result.IsOk())
				assert.True(t, result.Unwrap())
			}
		})
	}
}

func TestGitService_Clone_ValidationErrors(t *testing.T) {
	service := NewGitService(GetDefaultConfig())
	ctx := context.Background()

	tests := []struct {
		name      string
		opts      GitCloneOptions
		expectErr string
	}{
		{
			name:      "empty URL",
			opts:      GitCloneOptions{LocalPath: "/tmp/test"},
			expectErr: "URL cannot be empty",
		},
		{
			name:      "empty local path",
			opts:      GitCloneOptions{URL: "https://github.com/user/repo.git"},
			expectErr: "local path cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.Clone(ctx, tt.opts)
			assert.True(t, result.IsErr())
			assert.Contains(t, result.Error().Error(), tt.expectErr)
		})
	}
}

func TestGitService_Pull_ValidationErrors(t *testing.T) {
	service := NewGitService(GetDefaultConfig())
	ctx := context.Background()

	t.Run("empty local path", func(t *testing.T) {
		result := service.Pull(ctx, GitPullOptions{})
		assert.True(t, result.IsErr())
		assert.Contains(t, result.Error().Error(), "local path cannot be empty")
	})

	t.Run("non-existent repository", func(t *testing.T) {
		result := service.Pull(ctx, GitPullOptions{
			LocalPath: "/tmp/non-existent-repo",
		})
		assert.True(t, result.IsErr())
		assert.Contains(t, result.Error().Error(), "Repository not found")
	})
}

func TestGitService_Validate(t *testing.T) {
	service := NewGitService(GetDefaultConfig())

	t.Run("non-existent path", func(t *testing.T) {
		result := service.Validate("/tmp/non-existent-path")
		assert.True(t, result.IsOk())

		validation := result.Unwrap()
		assert.False(t, validation.IsValid)
		assert.False(t, validation.IsGitRepo)
		assert.Contains(t, validation.Errors, "path does not exist")
	})

	t.Run("non-git directory", func(t *testing.T) {
		// Create a temporary directory
		tmpDir, err := os.MkdirTemp("", "git-test-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		result := service.Validate(tmpDir)
		assert.True(t, result.IsOk())

		validation := result.Unwrap()
		assert.False(t, validation.IsValid)
		assert.False(t, validation.IsGitRepo)
		assert.True(t, len(validation.Errors) > 0)
		assert.Contains(t, validation.Errors[0], "not a git repository")
	})
}

func TestGitService_GetAuthentication(t *testing.T) {
	service := NewGitService(GetDefaultConfig())

	tests := []struct {
		name      string
		authType  models.PayloadRepositoryAuthType
		opts      authOptions
		expectErr bool
		errMsg    string
	}{
		{
			name:     "no authentication",
			authType: models.PayloadRepositoryAuthTypeNone,
			opts:     authOptions{},
		},
		{
			name:     "HTTPS with credentials",
			authType: models.PayloadRepositoryAuthTypeHTTPS,
			opts: authOptions{
				Username: "testuser",
				Password: "testpass",
			},
		},
		{
			name:      "HTTPS without credentials",
			authType:  models.PayloadRepositoryAuthTypeHTTPS,
			opts:      authOptions{},
			expectErr: true,
			errMsg:    "username and password required",
		},
		{
			name:     "Token authentication",
			authType: models.PayloadRepositoryAuthTypeToken,
			opts: authOptions{
				Token: "ghp_testtoken123",
			},
		},
		{
			name:      "Token authentication without token",
			authType:  models.PayloadRepositoryAuthTypeToken,
			opts:      authOptions{},
			expectErr: true,
			errMsg:    "token required",
		},
		{
			name:      "SSH without key or agent",
			authType:  models.PayloadRepositoryAuthTypeSSH,
			opts:      authOptions{},
			expectErr: true, // Will fail since no SSH agent or key file
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := service.getAuthentication(tt.authType, tt.opts)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				if tt.authType == models.PayloadRepositoryAuthTypeNone {
					assert.Nil(t, auth)
				} else {
					assert.NotNil(t, auth)
				}
			}
		})
	}
}

func TestGetDefaultConfig(t *testing.T) {
	config := GetDefaultConfig()

	assert.Equal(t, 1, config.DefaultDepth)
	assert.Equal(t, "main", config.DefaultBranch)
	assert.Equal(t, "/tmp/gibson-repos", config.BaseDir)
	assert.NotEmpty(t, config.SSHKeyPath)
	assert.NotEmpty(t, config.SSHKnownHostsPath)
}

func TestGitCloneOptions_Defaults(t *testing.T) {
	service := NewGitService(GetDefaultConfig())
	ctx := context.Background()

	// Test that defaults are applied correctly
	opts := GitCloneOptions{
		URL:       "https://github.com/user/repo.git",
		LocalPath: "/tmp/test-repo",
		// Depth and Branch not set - should use defaults
	}

	// We expect this to fail because it's not a real repo, but we can check
	// that the validation passes and the error is about the actual git operation
	result := service.Clone(ctx, opts)
	assert.True(t, result.IsErr())
	// Should not be validation errors
	assert.NotContains(t, result.Error().Error(), "required")
}

func TestProgressWriter(t *testing.T) {
	var messages []string
	callback := func(msg string) {
		messages = append(messages, msg)
	}

	pw := &progressWriter{callback: callback}

	// Test writing progress
	msg := "Cloning repository...\n"
	n, err := pw.Write([]byte(msg))
	assert.NoError(t, err)
	assert.Equal(t, len(msg), n) // Length of the written bytes

	assert.Len(t, messages, 1)
	assert.Equal(t, "Cloning repository...", messages[0])

	// Test empty message (should not call callback)
	n, err = pw.Write([]byte("   \n"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Len(t, messages, 1) // No new message
}

// Integration test that would require a real Git repository
// This test is skipped by default but can be enabled for manual testing
func TestGitService_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test requires internet access and a real repository
	// It's mainly for manual testing during development
	service := NewGitService(GetDefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "git-integration-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	repoPath := filepath.Join(tmpDir, "test-repo")

	// Test cloning a public repository
	result := service.Clone(ctx, GitCloneOptions{
		URL:       "https://github.com/octocat/Hello-World.git",
		LocalPath: repoPath,
		AuthType:  models.PayloadRepositoryAuthTypeNone,
		Depth:     1,
	})

	if result.IsErr() {
		t.Logf("Clone failed (expected in CI): %v", result.Error())
		t.Skip("Skipping rest of integration test due to clone failure")
		return
	}

	// Validate the cloned repository
	validation := service.Validate(repoPath)
	assert.True(t, validation.IsOk())

	validationResult := validation.Unwrap()
	assert.True(t, validationResult.IsValid)
	assert.True(t, validationResult.IsGitRepo)
	assert.True(t, validationResult.HasRemote)
}

func TestGitService_GetRemoteInfo_NonExistentRepo(t *testing.T) {
	service := NewGitService(GetDefaultConfig())

	result := service.GetRemoteInfo("/tmp/non-existent-repo")
	assert.True(t, result.IsErr())
	assert.Contains(t, result.Error().Error(), "failed to open repository")
}