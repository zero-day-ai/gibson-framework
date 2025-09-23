// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

//go:build integration
// +build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGitService_Initialization tests basic GitService functionality without network calls
func TestGitService_Initialization(t *testing.T) {
	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	assert.NotNil(t, service)
}

// TestGitService_ValidationLocalOnly tests validation of local repositories
func TestGitService_ValidationLocalOnly(t *testing.T) {
	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	// Test validation of non-existent directory
	result := service.Validate(filepath.Join(tempDir, "nonexistent"))
	require.True(t, result.IsOk(), "Validation should not fail: %v", result.Error())

	validation := result.Unwrap()
	assert.False(t, validation.IsValid)
	assert.False(t, validation.IsGitRepo)
	assert.False(t, validation.HasRemote)
}

// TestGitService_InvalidInputs tests handling of invalid inputs
func TestGitService_InvalidInputs(t *testing.T) {
	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	// Test clone with invalid URL
	ctx := context.Background()
	opts := services.GitCloneOptions{
		URL:       "not-a-valid-url",
		LocalPath: filepath.Join(tempDir, "invalid"),
		Depth:     1,
		AuthType:  models.PayloadRepositoryAuthTypeNone,
	}

	result := service.Clone(ctx, opts)
	assert.True(t, result.IsErr(), "Should fail with invalid URL")

	err := result.Error()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "URL", "Error should mention URL validation")
}

// TestGitService_FileSystemOperations tests file system related operations
func TestGitService_FileSystemOperations(t *testing.T) {
	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	// Create a regular directory (not a git repo)
	regularDir := filepath.Join(tempDir, "regular-dir")
	err := os.MkdirAll(regularDir, 0755)
	require.NoError(t, err)

	// Test validation of regular directory
	result := service.Validate(regularDir)
	require.True(t, result.IsOk(), "Validation should succeed: %v", result.Error())

	validation := result.Unwrap()
	assert.False(t, validation.IsGitRepo, "Regular directory should not be detected as Git repo")
	assert.False(t, validation.HasRemote, "Regular directory should not have remote")
}

// TestGitService_ConfigurationOptions tests various configuration scenarios
func TestGitService_ConfigurationOptions(t *testing.T) {
	tests := []struct {
		name   string
		config services.GitServiceConfig
	}{
		{
			name: "minimal config",
			config: services.GitServiceConfig{
				BaseDir: t.TempDir(),
			},
		},
		{
			name: "full config",
			config: services.GitServiceConfig{
				DefaultDepth:      10,
				DefaultBranch:     "develop",
				BaseDir:           t.TempDir(),
				SSHKeyPath:        "~/.ssh/test_key",
				SSHKnownHostsPath: "~/.ssh/known_hosts",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := services.NewGitService(tt.config)
			assert.NotNil(t, service, "Service should be created with any valid config")
		})
	}
}