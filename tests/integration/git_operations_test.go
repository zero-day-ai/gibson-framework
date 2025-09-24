// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

//go:build integration
// +build integration

package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/zero-day-ai/gibson-framework/pkg/services"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRepoURL = "https://github.com/gibson-sec/test-payloads.git"
	testSSHURL  = "git@github.com:gibson-sec/test-payloads.git"
)

// TestGitService_NewGitService tests GitService initialization
func TestGitService_NewGitService(t *testing.T) {
	tests := []struct {
		name     string
		config   services.GitServiceConfig
		expected services.GitServiceConfig
	}{
		{
			name:   "default configuration",
			config: services.GitServiceConfig{},
			expected: services.GitServiceConfig{
				DefaultDepth:  1,
				DefaultBranch: "main",
				BaseDir:       "/tmp/gibson-repos",
			},
		},
		{
			name: "custom configuration",
			config: services.GitServiceConfig{
				DefaultDepth:      5,
				DefaultBranch:     "develop",
				BaseDir:           "/custom/path",
				SSHKeyPath:        "~/.ssh/id_rsa",
				SSHKnownHostsPath: "~/.ssh/known_hosts",
			},
			expected: services.GitServiceConfig{
				DefaultDepth:      5,
				DefaultBranch:     "develop",
				BaseDir:           "/custom/path",
				SSHKeyPath:        "~/.ssh/id_rsa",
				SSHKnownHostsPath: "~/.ssh/known_hosts",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := services.NewGitService(tt.config)
			assert.NotNil(t, service)
		})
	}
}

// TestGitService_Clone tests Git cloning functionality
func TestGitService_Clone(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	tests := []struct {
		name        string
		opts        services.GitCloneOptions
		shouldError bool
		errorContains string
	}{
		{
			name: "successful shallow clone",
			opts: services.GitCloneOptions{
				URL:       testRepoURL,
				LocalPath: filepath.Join(tempDir, "test-shallow"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			shouldError: false,
		},
		{
			name: "successful full clone",
			opts: services.GitCloneOptions{
				URL:       testRepoURL,
				LocalPath: filepath.Join(tempDir, "test-full"),
				Full:      true,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			shouldError: false,
		},
		{
			name: "invalid URL",
			opts: services.GitCloneOptions{
				URL:       "not-a-valid-url",
				LocalPath: filepath.Join(tempDir, "test-invalid"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			shouldError:   true,
			errorContains: "invalid URL",
		},
		{
			name: "nonexistent repository",
			opts: services.GitCloneOptions{
				URL:       "https://github.com/nonexistent/repository.git",
				LocalPath: filepath.Join(tempDir, "test-nonexistent"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			shouldError:   true,
			errorContains: "repository not found",
		},
		{
			name: "clone with progress callback",
			opts: services.GitCloneOptions{
				URL:       testRepoURL,
				LocalPath: filepath.Join(tempDir, "test-progress"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
				Progress: func(message string) {
					t.Logf("Progress: %s", message)
				},
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result := service.Clone(ctx, tt.opts)

			if tt.shouldError {
				assert.True(t, result.IsErr(), "Expected error but clone succeeded")
				if tt.errorContains != "" {
					err := result.Error()
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errorContains))
				}
			} else {
				require.True(t, result.IsOk(), "Clone failed: %v", result.Error())
				clonePath := result.Unwrap()

				// Verify repository was cloned
				assert.DirExists(t, clonePath)
				assert.DirExists(t, filepath.Join(clonePath, ".git"))

				// Verify depth setting for shallow clone
				if tt.opts.Depth > 0 && !tt.opts.Full {
					repo, err := git.PlainOpen(clonePath)
					require.NoError(t, err)

					// Count commits to verify shallow clone
					ref, err := repo.Head()
					require.NoError(t, err)

					cIter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
					require.NoError(t, err)

					commitCount := 0
					err = cIter.ForEach(func(c *object.Commit) error {
						commitCount++
						return nil
					})
					require.NoError(t, err)

					if tt.opts.Depth == 1 {
						assert.LessOrEqual(t, commitCount, 2, "Shallow clone should have limited commits")
					}
				}
			}
		})
	}
}

// TestGitService_Pull tests Git pull functionality
func TestGitService_Pull(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	// First clone a repository
	clonePath := filepath.Join(tempDir, "test-pull")
	cloneOpts := services.GitCloneOptions{
		URL:       testRepoURL,
		LocalPath: clonePath,
		Depth:     1,
		AuthType:  models.PayloadRepositoryAuthTypeNone,
	}

	ctx := context.Background()
	cloneResult := service.Clone(ctx, cloneOpts)
	require.True(t, cloneResult.IsOk(), "Initial clone failed: %v", cloneResult.Error())

	tests := []struct {
		name          string
		opts          services.GitPullOptions
		shouldError   bool
		errorContains string
	}{
		{
			name: "successful pull",
			opts: services.GitPullOptions{
				LocalPath: clonePath,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			shouldError: false,
		},
		{
			name: "pull nonexistent directory",
			opts: services.GitPullOptions{
				LocalPath: filepath.Join(tempDir, "nonexistent"),
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			shouldError:   true,
			errorContains: "not found",
		},
		{
			name: "pull with progress callback",
			opts: services.GitPullOptions{
				LocalPath: clonePath,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
				Progress: func(message string) {
					t.Logf("Pull Progress: %s", message)
				},
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			result := service.Pull(ctx, tt.opts)

			if tt.shouldError {
				assert.True(t, result.IsErr(), "Expected error but pull succeeded")
				if tt.errorContains != "" {
					err := result.Error()
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errorContains))
				}
			} else {
				assert.True(t, result.IsOk(), "Pull failed: %v", result.Error())
			}
		})
	}
}

// TestGitService_Validate tests Git repository validation
func TestGitService_Validate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	// Create a valid git repository
	validRepoPath := filepath.Join(tempDir, "valid-repo")
	cloneOpts := services.GitCloneOptions{
		URL:       testRepoURL,
		LocalPath: validRepoPath,
		Depth:     1,
		AuthType:  models.PayloadRepositoryAuthTypeNone,
	}

	ctx := context.Background()
	cloneResult := service.Clone(ctx, cloneOpts)
	require.True(t, cloneResult.IsOk(), "Clone failed: %v", cloneResult.Error())

	// Create a non-git directory
	nonGitPath := filepath.Join(tempDir, "not-git")
	err := os.MkdirAll(nonGitPath, 0755)
	require.NoError(t, err)

	tests := []struct {
		name         string
		path         string
		expectValid  bool
		expectGitRepo bool
		expectRemote bool
	}{
		{
			name:         "valid git repository",
			path:         validRepoPath,
			expectValid:  true,
			expectGitRepo: true,
			expectRemote: true,
		},
		{
			name:         "non-git directory",
			path:         nonGitPath,
			expectValid:  false,
			expectGitRepo: false,
			expectRemote: false,
		},
		{
			name:         "nonexistent directory",
			path:         filepath.Join(tempDir, "nonexistent"),
			expectValid:  false,
			expectGitRepo: false,
			expectRemote: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.Validate(tt.path)
			require.True(t, result.IsOk(), "Validation failed: %v", result.Error())

			validation := result.Unwrap()
			assert.Equal(t, tt.expectValid, validation.IsValid)
			assert.Equal(t, tt.expectGitRepo, validation.IsGitRepo)
			assert.Equal(t, tt.expectRemote, validation.HasRemote)

			if validation.HasRemote {
				assert.NotEmpty(t, validation.RemoteURL)
			}

			t.Logf("Validation result: %+v", validation)
		})
	}
}

// TestGitService_Authentication tests authentication scenarios
func TestGitService_Authentication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	tests := []struct {
		name          string
		opts          services.GitCloneOptions
		shouldError   bool
		errorContains string
		skipCondition func() bool
	}{
		{
			name: "HTTPS with invalid token",
			opts: services.GitCloneOptions{
				URL:       "https://github.com/private/repository.git",
				LocalPath: filepath.Join(tempDir, "test-https-invalid"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeToken,
				Token:     "invalid-token",
			},
			shouldError:   true,
			errorContains: "authentication",
		},
		{
			name: "SSH without key",
			opts: services.GitCloneOptions{
				URL:       testSSHURL,
				LocalPath: filepath.Join(tempDir, "test-ssh-no-key"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeSSH,
			},
			shouldError:   true,
			errorContains: "authentication",
			skipCondition: func() bool {
				// Skip if SSH key exists (would make test pass)
				sshKeyPath := filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
				_, err := os.Stat(sshKeyPath)
				return err == nil
			},
		},
		{
			name: "public repository with no auth",
			opts: services.GitCloneOptions{
				URL:       testRepoURL,
				LocalPath: filepath.Join(tempDir, "test-public"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipCondition != nil && tt.skipCondition() {
				t.Skip("Skipping test due to skip condition")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result := service.Clone(ctx, tt.opts)

			if tt.shouldError {
				assert.True(t, result.IsErr(), "Expected authentication error but clone succeeded")
				if tt.errorContains != "" {
					err := result.Error()
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errorContains))
				}
			} else {
				assert.True(t, result.IsOk(), "Clone failed: %v", result.Error())
			}
		})
	}
}

// TestGitService_NetworkFailures tests network failure scenarios
func TestGitService_NetworkFailures(t *testing.T) {
	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	tests := []struct {
		name          string
		opts          services.GitCloneOptions
		errorContains string
	}{
		{
			name: "invalid hostname",
			opts: services.GitCloneOptions{
				URL:       "https://nonexistent-domain-12345.com/repo.git",
				LocalPath: filepath.Join(tempDir, "test-invalid-host"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			errorContains: "no such host",
		},
		{
			name: "connection refused",
			opts: services.GitCloneOptions{
				URL:       "https://localhost:99999/repo.git",
				LocalPath: filepath.Join(tempDir, "test-refused"),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			},
			errorContains: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := service.Clone(ctx, tt.opts)

			assert.True(t, result.IsErr(), "Expected network error but clone succeeded")
			err := result.Error()
			// Network errors can vary, so we check for common patterns
			errStr := strings.ToLower(err.Error())
			containsExpected := strings.Contains(errStr, strings.ToLower(tt.errorContains)) ||
				strings.Contains(errStr, "network") ||
				strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "connection") ||
				strings.Contains(errStr, "unexpected") ||
				strings.Contains(errStr, "corruption")
			// Log actual error for debugging
			t.Logf("Actual error: %s", err.Error())
			assert.True(t, containsExpected, "Error %q should contain network-related message", err.Error())
		})
	}
}

// TestGitService_ConcurrentOperations tests concurrent Git operations
func TestGitService_ConcurrentOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	const numConcurrent = 3
	results := make(chan models.Result[string], numConcurrent)

	// Start concurrent clone operations
	for i := 0; i < numConcurrent; i++ {
		go func(index int) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			opts := services.GitCloneOptions{
				URL:       testRepoURL,
				LocalPath: filepath.Join(tempDir, fmt.Sprintf("concurrent-%d", index)),
				Depth:     1,
				AuthType:  models.PayloadRepositoryAuthTypeNone,
			}

			result := service.Clone(ctx, opts)
			results <- result
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numConcurrent; i++ {
		result := <-results
		if result.IsOk() {
			successCount++
			// Verify each clone was successful
			clonePath := result.Unwrap()
			assert.DirExists(t, clonePath)
			assert.DirExists(t, filepath.Join(clonePath, ".git"))
		} else {
			t.Logf("Concurrent clone %d failed: %v", i, result.Error())
		}
	}

	// All concurrent operations should succeed
	assert.Equal(t, numConcurrent, successCount, "All concurrent clones should succeed")
}

// TestGitService_ContextCancellation tests context cancellation behavior
func TestGitService_ContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	opts := services.GitCloneOptions{
		URL:       testRepoURL,
		LocalPath: filepath.Join(tempDir, "test-cancelled"),
		Depth:     1,
		AuthType:  models.PayloadRepositoryAuthTypeNone,
	}

	result := service.Clone(ctx, opts)

	assert.True(t, result.IsErr(), "Expected cancellation error")
	err := result.Error()
	errStr := strings.ToLower(err.Error())
	containsCancellation := strings.Contains(errStr, "context") ||
		strings.Contains(errStr, "canceled") ||
		strings.Contains(errStr, "cancelled") ||
		strings.Contains(errStr, "timeout")
	assert.True(t, containsCancellation, "Error should indicate context cancellation: %v", err)
}

// createTestRepo creates a test Git repository for testing
func createTestRepo(t *testing.T, path string) {
	t.Helper()

	// Initialize repository
	repo, err := git.PlainInit(path, false)
	require.NoError(t, err)

	// Create some test files
	testFiles := map[string]string{
		"README.md":             "# Test Repository\nThis is a test repository for Gibson Framework.",
		"payloads/xss.yaml":     "category: interface\npayload: \"<script>alert('xss')</script>\"",
		"payloads/sqli.yaml":    "category: data\npayload: \"'; DROP TABLE users; --\"",
		"model/jailbreak.yaml":  "category: model\npayload: \"Ignore previous instructions\"",
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(path, filename)
		err := os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err)

		err = os.WriteFile(filePath, []byte(content), 0644)
		require.NoError(t, err)
	}

	// Add files to git
	worktree, err := repo.Worktree()
	require.NoError(t, err)

	for filename := range testFiles {
		_, err = worktree.Add(filename)
		require.NoError(t, err)
	}

	// Commit changes
	signature := &object.Signature{
		Name:  "Test User",
		Email: "test@gibson.sec",
		When:  time.Now(),
	}

	_, err = worktree.Commit("Initial commit", &git.CommitOptions{
		Author:    signature,
		Committer: signature,
	})
	require.NoError(t, err)
}

// setupMockGitServer creates a mock Git server for testing
func setupMockGitServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-repo.git")

	// Create bare repository
	_, err := git.PlainInit(repoPath, true)
	require.NoError(t, err)

	// Create HTTP server that serves the repository
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple implementation for testing
		// In real scenarios, this would be much more complex
		if strings.HasSuffix(r.URL.Path, "/info/refs") {
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			w.WriteHeader(http.StatusOK)
			// Minimal git protocol response
			fmt.Fprintf(w, "001e# service=git-upload-pack\n0000")
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	server := httptest.NewServer(handler)
	return server, repoPath
}

// benchmarkCloneOperation benchmarks clone operations
func BenchmarkGitService_Clone(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	tempDir := b.TempDir()

	service := services.NewGitService(services.GitServiceConfig{
		BaseDir: tempDir,
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		clonePath := filepath.Join(tempDir, fmt.Sprintf("bench-clone-%d", i))
		b.StartTimer()

		ctx := context.Background()
		opts := services.GitCloneOptions{
			URL:       testRepoURL,
			LocalPath: clonePath,
			Depth:     1,
			AuthType:  models.PayloadRepositoryAuthTypeNone,
		}

		result := service.Clone(ctx, opts)
		if result.IsErr() {
			b.Fatalf("Clone failed: %v", result.Error())
		}
	}
}