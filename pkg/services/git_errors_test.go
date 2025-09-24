// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	// "time"

	"github.com/go-git/go-git/v5"
	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

func TestWrapGitError(t *testing.T) {
	tests := []struct {
		name           string
		operation      string
		originalErr    error
		context        GitErrorContext
		expectedCode   string
		expectRecovery bool
	}{
		{
			name:        "authentication error",
			operation:   "clone",
			originalErr: errors.New("authentication failed: access denied"),
			context: GitErrorContext{
				RepositoryURL: "git@github.com:user/repo.git",
				AuthType:      coremodels.PayloadRepositoryAuthTypeSSH,
			},
			expectedCode:   "AUTH_FAILED",
			expectRecovery: false,
		},
		{
			name:        "network timeout",
			operation:   "clone",
			originalErr: &net.OpError{Op: "dial", Err: errors.New("timeout")},
			context: GitErrorContext{
				RepositoryURL: "https://github.com/user/repo.git",
				AuthType:      coremodels.PayloadRepositoryAuthTypeHTTPS,
			},
			expectedCode:   "TIMEOUT",
			expectRecovery: true,
		},
		{
			name:        "repository not found",
			operation:   "clone",
			originalErr: errors.New("repository not found: 404"),
			context: GitErrorContext{
				RepositoryURL: "https://github.com/user/nonexistent.git",
			},
			expectedCode:   "REPO_NOT_FOUND",
			expectRecovery: false,
		},
		{
			name:        "permission denied",
			operation:   "clone",
			originalErr: &os.PathError{Op: "mkdir", Path: "/root/test", Err: syscall.EACCES},
			context: GitErrorContext{
				LocalPath: "/root/test",
			},
			expectedCode:   "PERMISSION_DENIED",
			expectRecovery: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitErr := WrapGitError(tt.operation, tt.originalErr, tt.context)

			if gitErr.Operation != tt.operation {
				t.Errorf("Expected operation %s, got %s", tt.operation, gitErr.Operation)
			}

			if gitErr.ErrorCode != tt.expectedCode {
				t.Errorf("Expected error code %s, got %s", tt.expectedCode, gitErr.ErrorCode)
			}

			if gitErr.IsRecoverable != tt.expectRecovery {
				t.Errorf("Expected recoverable %v, got %v", tt.expectRecovery, gitErr.IsRecoverable)
			}

			if gitErr.UserMessage == "" {
				t.Error("Expected non-empty user message")
			}

			if len(gitErr.Suggestions) == 0 {
				t.Error("Expected at least one suggestion")
			}
		})
	}
}

func TestGitErrorDetailing(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		expectCode  string
		expectSuggestions bool
	}{
		{
			name:        "SSH key error",
			err:         errors.New("ssh: handshake failed: ssh: unable to authenticate"),
			expectCode:  "SSH_KEY_ERROR",
			expectSuggestions: true,
		},
		{
			name:        "timeout error",
			err:         errors.New("context deadline exceeded"),
			expectCode:  "TIMEOUT",
			expectSuggestions: true,
		},
		{
			name:        "disk space error",
			err:         &os.PathError{Op: "write", Path: "/tmp/test", Err: syscall.ENOSPC},
			expectCode:  "DISK_FULL",
			expectSuggestions: true,
		},
		{
			name:        "certificate error",
			err:         errors.New("x509: certificate verification failed"),
			expectCode:  "CERT_ERROR",
			expectSuggestions: true,
		},
		{
			name:        "repository exists",
			err:         git.ErrRepositoryAlreadyExists,
			expectCode:  "REPO_EXISTS",
			expectSuggestions: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitErr := WrapGitError("test", tt.err, GitErrorContext{})

			if gitErr.ErrorCode != tt.expectCode {
				t.Errorf("Expected error code %s, got %s", tt.expectCode, gitErr.ErrorCode)
			}

			if tt.expectSuggestions && len(gitErr.Suggestions) == 0 {
				t.Error("Expected suggestions but got none")
			}
		})
	}
}

func TestNewCloneError(t *testing.T) {
	err := errors.New("clone failed: authentication required")
	url := "git@github.com:user/repo.git"
	localPath := "/tmp/repo"
	authType := coremodels.PayloadRepositoryAuthTypeSSH
	branch := "main"
	depth := 1

	gitErr := NewCloneError(err, url, localPath, authType, branch, depth)

	if gitErr.Operation != "clone" {
		t.Errorf("Expected operation 'clone', got %s", gitErr.Operation)
	}

	if gitErr.RepositoryURL != url {
		t.Errorf("Expected URL %s, got %s", url, gitErr.RepositoryURL)
	}

	if gitErr.LocalPath != localPath {
		t.Errorf("Expected local path %s, got %s", localPath, gitErr.LocalPath)
	}

	if gitErr.AuthType != authType {
		t.Errorf("Expected auth type %s, got %s", authType, gitErr.AuthType)
	}

	if gitErr.Branch != branch {
		t.Errorf("Expected branch %s, got %s", branch, gitErr.Branch)
	}

	if gitErr.Depth != depth {
		t.Errorf("Expected depth %d, got %d", depth, gitErr.Depth)
	}
}

func TestNewAuthError(t *testing.T) {
	authType := coremodels.PayloadRepositoryAuthTypeSSH
	url := "git@github.com:user/repo.git"
	details := "SSH key not found"

	gitErr := NewAuthError(authType, url, details)

	if gitErr.Operation != "authentication" {
		t.Errorf("Expected operation 'authentication', got %s", gitErr.Operation)
	}

	if gitErr.ErrorCode != "AUTH_FAILED" {
		t.Errorf("Expected error code 'AUTH_FAILED', got %s", gitErr.ErrorCode)
	}

	if gitErr.AuthType != authType {
		t.Errorf("Expected auth type %s, got %s", authType, gitErr.AuthType)
	}

	if gitErr.RepositoryURL != url {
		t.Errorf("Expected URL %s, got %s", url, gitErr.RepositoryURL)
	}

	if !strings.Contains(gitErr.TechDetails, details) {
		t.Errorf("Expected tech details to contain %s, got %s", details, gitErr.TechDetails)
	}

	if gitErr.IsRecoverable {
		t.Error("Authentication errors should not be recoverable")
	}
}

func TestGetDetailedMessage(t *testing.T) {
	gitErr := &GitError{
		Operation:    "clone",
		ErrorCode:    "AUTH_FAILED",
		UserMessage:  "Authentication failed",
		TechDetails:  "SSH key not found",
		RepositoryURL: "git@github.com:user/repo.git",
		AuthType:     coremodels.PayloadRepositoryAuthTypeSSH,
		Suggestions: []string{
			"Check SSH key configuration",
			"Verify key is added to Git provider",
		},
		KnownSolutions: []string{
			"Generate new SSH key",
			"Add key to SSH agent",
		},
		NextSteps: []string{
			"Test SSH connection",
			"Update credentials",
		},
		References: []string{
			"SSH Setup Guide: https://docs.github.com/ssh",
		},
		IsRecoverable: false,
	}

	message := gitErr.GetDetailedMessage()

	// Check that all sections are included
	expectedSections := []string{
		"Git Clone Operation Failed",
		"Error: Authentication failed",
		"Code: AUTH_FAILED",
		"Repository: git@github.com:user/repo.git",
		"Auth Type: ssh",
		"Technical Details:",
		"SSH key not found",
		"Troubleshooting Steps:",
		"Check SSH key configuration",
		"Known Solutions:",
		"Generate new SSH key",
		"Recommended Next Steps:",
		"Test SSH connection",
		"Additional Resources:",
		"SSH Setup Guide",
		"Recovery: This error requires manual intervention",
	}

	for _, section := range expectedSections {
		if !strings.Contains(message, section) {
			t.Errorf("Expected message to contain '%s', but it was missing", section)
		}
	}
}

func TestSSHSetupGuidance(t *testing.T) {
	guidance := GetSSHSetupGuidance()

	if len(guidance) == 0 {
		t.Error("Expected SSH setup guidance but got none")
	}

	expectedSteps := []string{
		"ssh-keygen",
		"ssh-add",
		"cat ~/.ssh",
		"ssh -T git@github.com",
	}

	guidanceText := strings.Join(guidance, " ")
	for _, step := range expectedSteps {
		if !strings.Contains(guidanceText, step) {
			t.Errorf("Expected SSH guidance to contain '%s'", step)
		}
	}
}

func TestTokenSetupGuidance(t *testing.T) {
	guidance := GetTokenSetupGuidance()

	if len(guidance) == 0 {
		t.Error("Expected token setup guidance but got none")
	}

	expectedSteps := []string{
		"personal access token",
		"GitHub",
		"gibson credential add",
	}

	guidanceText := strings.Join(guidance, " ")
	for _, step := range expectedSteps {
		if !strings.Contains(guidanceText, step) {
			t.Errorf("Expected token guidance to contain '%s'", step)
		}
	}
}

func TestRecoverableErrors(t *testing.T) {
	recoverableErrors := []error{
		&net.OpError{Op: "dial", Err: errors.New("timeout")},
		errors.New("network unreachable"),
		errors.New("corrupt object"),
	}

	nonRecoverableErrors := []error{
		errors.New("authentication failed"),
		errors.New("repository not found"),
		&os.PathError{Op: "mkdir", Path: "/root", Err: syscall.EACCES},
	}

	for _, err := range recoverableErrors {
		gitErr := WrapGitError("test", err, GitErrorContext{})
		if !gitErr.IsRecoverable {
			t.Errorf("Expected error to be recoverable: %v", err)
		}
	}

	for _, err := range nonRecoverableErrors {
		gitErr := WrapGitError("test", err, GitErrorContext{})
		if gitErr.IsRecoverable {
			t.Errorf("Expected error to not be recoverable: %v", err)
		}
	}
}

func TestErrorCodes(t *testing.T) {
	testCases := map[string]string{
		"authentication failed": "AUTH_FAILED",
		"network unreachable": "NETWORK_ERROR",
		"repository not found": "REPO_NOT_FOUND",
		"permission denied": "PERMISSION_DENIED",
		"ssh key error": "SSH_KEY_ERROR",
		"timeout": "TIMEOUT",
		"no space left": "DISK_FULL",
		"corrupt": "REPO_CORRUPT",
		"branch not found": "BRANCH_NOT_FOUND",
		"invalid url": "INVALID_URL",
		"certificate": "CERT_ERROR",
		"proxy": "PROXY_ERROR",
	}

	for errMsg, expectedCode := range testCases {
		err := errors.New(errMsg)
		gitErr := WrapGitError("test", err, GitErrorContext{})

		if gitErr.ErrorCode != expectedCode {
			t.Errorf("Error '%s' expected code '%s', got '%s'", errMsg, expectedCode, gitErr.ErrorCode)
		}
	}
}

// Benchmark the error wrapping performance
func BenchmarkWrapGitError(b *testing.B) {
	err := errors.New("authentication failed: access denied")
	context := GitErrorContext{
		RepositoryURL: "git@github.com:user/repo.git",
		LocalPath:     "/tmp/repo",
		AuthType:      coremodels.PayloadRepositoryAuthTypeSSH,
		Branch:        "main",
		Depth:         1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WrapGitError("clone", err, context)
	}
}

// Test that error messages don't expose sensitive information
func TestNoSensitiveDataExposure(t *testing.T) {
	sensitiveData := []string{
		"password123",
		"secret_token",
		"private_key_content",
	}

	for _, sensitive := range sensitiveData {
		err := errors.New("authentication failed with " + sensitive)
		gitErr := WrapGitError("test", err, GitErrorContext{})

		// Check that sensitive data is not in user-facing message
		if strings.Contains(gitErr.UserMessage, sensitive) {
			t.Errorf("User message should not contain sensitive data: %s", sensitive)
		}

		// Technical details may contain it (for debugging) but suggestions should not
		for _, suggestion := range gitErr.Suggestions {
			if strings.Contains(suggestion, sensitive) {
				t.Errorf("Suggestion should not contain sensitive data: %s", sensitive)
			}
		}
	}
}