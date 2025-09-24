// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson-framework/pkg/services"
)

func TestNewGitErrorHandler(t *testing.T) {
	tests := []struct {
		name      string
		detailed  bool
		noColor   bool
		expected  ErrorDisplayMode
	}{
		{
			name:     "simple mode",
			detailed: false,
			noColor:  false,
			expected: ErrorDisplaySimple,
		},
		{
			name:     "detailed mode",
			detailed: true,
			noColor:  false,
			expected: ErrorDisplayDetailed,
		},
		{
			name:     "no color mode",
			detailed: false,
			noColor:  true,
			expected: ErrorDisplaySimple,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewGitErrorHandler(tt.detailed, tt.noColor)
			if handler.Mode != tt.expected {
				t.Errorf("Expected mode %d, got %d", tt.expected, handler.Mode)
			}
			if handler.NoColor != tt.noColor {
				t.Errorf("Expected NoColor %v, got %v", tt.noColor, handler.NoColor)
			}
		})
	}
}

func TestHandleError(t *testing.T) {
	// Capture stderr for testing
	originalStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	defer func() {
		os.Stderr = originalStderr
		w.Close()
	}()

	handler := NewGitErrorHandler(false, true) // Simple mode, no color

	// Test GitError handling
	gitErr := &services.GitError{
		Operation:   "clone",
		ErrorCode:   "AUTH_FAILED",
		UserMessage: "Authentication failed",
		Suggestions: []string{
			"Check SSH key",
			"Verify credentials",
			"Test connection",
		},
		IsRecoverable: false,
	}

	handler.HandleError(gitErr, "clone")

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify output contains expected elements
	expectedElements := []string{
		"Error: Authentication failed",
		"Quick fixes:",
		"Check SSH key",
		"This error may be temporary", // Should NOT appear (not recoverable)
		"For detailed troubleshooting",
	}

	for i, element := range expectedElements {
		if i == 3 { // "This error may be temporary" should NOT appear
			if strings.Contains(output, element) {
				t.Errorf("Output should not contain '%s' for non-recoverable error", element)
			}
		} else {
			if !strings.Contains(output, element) {
				t.Errorf("Output should contain '%s'", element)
			}
		}
	}
}

func TestHandleGenericError(t *testing.T) {
	// Capture stderr for testing
	originalStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	defer func() {
		os.Stderr = originalStderr
		w.Close()
	}()

	handler := NewGitErrorHandler(false, true) // Simple mode, no color

	genericErr := errors.New("generic error message")
	handler.HandleError(genericErr, "test")

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Error: test operation failed: generic error message") {
		t.Errorf("Expected generic error format, got: %s", output)
	}
}

func TestGitErrorHelpers(t *testing.T) {
	helpers := NewGitErrorHelpers(false, true) // Not detailed, no color

	// Test with nil error (should not panic)
	helpers.HandleCloneError(nil, "test-repo", "https://github.com/test/repo.git")
	helpers.HandlePullError(nil, "test-repo", "/tmp/repo")
	helpers.HandleAuthError(nil, "ssh")

	// Test with actual errors (we can't easily capture stderr in this test,
	// but we can ensure no panics occur)
	gitErr := &services.GitError{
		Operation:   "clone",
		ErrorCode:   "AUTH_FAILED",
		UserMessage: "Authentication failed",
	}

	helpers.HandleCloneError(gitErr, "test-repo", "https://github.com/test/repo.git")
	helpers.HandlePullError(gitErr, "test-repo", "/tmp/repo")
	helpers.HandleAuthError(gitErr, "ssh")
}

func TestValidateRepositoryURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectError bool
		errorCode   string
	}{
		{
			name:        "empty URL",
			url:         "",
			expectError: true,
			errorCode:   "VALIDATION_FAILED",
		},
		{
			name:        "valid HTTPS URL",
			url:         "https://github.com/user/repo.git",
			expectError: false,
		},
		{
			name:        "valid SSH URL",
			url:         "git@github.com:user/repo.git",
			expectError: false,
		},
		{
			name:        "valid SSH protocol URL",
			url:         "ssh://git@github.com/user/repo.git",
			expectError: false,
		},
		{
			name:        "invalid URL format",
			url:         "invalid-url-format",
			expectError: true,
			errorCode:   "INVALID_URL_FORMAT",
		},
		{
			name:        "FTP URL (not supported)",
			url:         "ftp://example.com/repo.git",
			expectError: true,
			errorCode:   "INVALID_URL_FORMAT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRepositoryURL(tt.url)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}

				if gitErr, ok := err.(*services.GitError); ok {
					if gitErr.ErrorCode != tt.errorCode {
						t.Errorf("Expected error code %s, got %s", tt.errorCode, gitErr.ErrorCode)
					}
				} else {
					t.Error("Expected GitError type")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestNewValidationError(t *testing.T) {
	field := "repository URL"
	value := "invalid-url"
	reason := "URL format is invalid"

	err := NewValidationError(field, value, reason)

	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	gitErr, ok := err.(*services.GitError)
	if !ok {
		t.Fatal("Expected GitError type")
	}

	if gitErr.Operation != "validation" {
		t.Errorf("Expected operation 'validation', got %s", gitErr.Operation)
	}

	if gitErr.ErrorCode != "VALIDATION_FAILED" {
		t.Errorf("Expected error code 'VALIDATION_FAILED', got %s", gitErr.ErrorCode)
	}

	expectedMessage := "Invalid repository URL: URL format is invalid"
	if gitErr.UserMessage != expectedMessage {
		t.Errorf("Expected user message '%s', got '%s'", expectedMessage, gitErr.UserMessage)
	}

	if !strings.Contains(gitErr.TechDetails, field) {
		t.Errorf("Expected tech details to contain field '%s'", field)
	}

	if !strings.Contains(gitErr.TechDetails, value) {
		t.Errorf("Expected tech details to contain value '%s'", value)
	}

	if len(gitErr.Suggestions) == 0 {
		t.Error("Expected suggestions but got none")
	}

	if gitErr.IsRecoverable {
		t.Error("Validation errors should not be recoverable")
	}
}

func TestIsRecoverableError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectRecoverable bool
	}{
		{
			name: "recoverable GitError",
			err: &services.GitError{
				IsRecoverable: true,
			},
			expectRecoverable: true,
		},
		{
			name: "non-recoverable GitError",
			err: &services.GitError{
				IsRecoverable: false,
			},
			expectRecoverable: false,
		},
		{
			name:              "generic error",
			err:               errors.New("generic error"),
			expectRecoverable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRecoverableError(tt.err)
			if result != tt.expectRecoverable {
				t.Errorf("Expected recoverable %v, got %v", tt.expectRecoverable, result)
			}
		})
	}
}

func TestGetRetryDelay(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectCanRetry bool
		expectDelay    int
	}{
		{
			name: "recoverable with delay",
			err: &services.GitError{
				IsRecoverable: true,
				MaxRetries:    3,
				RetryDelay:    30 * 1000000000, // 30 seconds in nanoseconds
			},
			expectCanRetry: true,
			expectDelay:    30,
		},
		{
			name: "recoverable without retries",
			err: &services.GitError{
				IsRecoverable: true,
				MaxRetries:    0,
			},
			expectCanRetry: false,
			expectDelay:    0,
		},
		{
			name: "non-recoverable",
			err: &services.GitError{
				IsRecoverable: false,
			},
			expectCanRetry: false,
			expectDelay:    0,
		},
		{
			name:           "generic error",
			err:            errors.New("generic error"),
			expectCanRetry: false,
			expectDelay:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canRetry, delay := GetRetryDelay(tt.err)

			if canRetry != tt.expectCanRetry {
				t.Errorf("Expected canRetry %v, got %v", tt.expectCanRetry, canRetry)
			}

			if delay != tt.expectDelay {
				t.Errorf("Expected delay %d, got %d", tt.expectDelay, delay)
			}
		})
	}
}

func TestShowErrorSummary(t *testing.T) {
	// Capture stderr for testing
	originalStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	defer func() {
		os.Stderr = originalStderr
		w.Close()
	}()

	helpers := NewGitErrorHelpers(false, true) // Not detailed, no color

	errors := []error{
		&services.GitError{ErrorCode: "AUTH_FAILED"},
		&services.GitError{ErrorCode: "NETWORK_ERROR"},
		&services.GitError{ErrorCode: "AUTH_FAILED"},
		errors.New("generic error"),
	}

	helpers.ShowErrorSummary(errors, "sync")

	// Close writer and read output
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	expectedElements := []string{
		"4 errors occurred during sync operation",
		"2 authentication errors",
		"1 network errors",
		"1 other errors",
		"Run with --verbose",
	}

	for _, element := range expectedElements {
		if !strings.Contains(output, element) {
			t.Errorf("Output should contain '%s'", element)
		}
	}

	// Test with empty errors
	helpers.ShowErrorSummary([]error{}, "test")
	// Should not output anything for empty errors
}

func TestColorFunctions(t *testing.T) {
	// Test with colors enabled
	handlerWithColor := NewGitErrorHandler(false, false)
	colorFunc := handlerWithColor.colorFunc(0) // Any color attribute
	result := colorFunc("test")

	// Should return non-empty string (we can't easily test exact color codes)
	if result == "" {
		t.Error("Expected non-empty result from color function")
	}

	// Test with colors disabled
	handlerNoColor := NewGitErrorHandler(false, true)
	noColorFunc := handlerNoColor.colorFunc(0)
	resultNoColor := noColorFunc("test")

	if resultNoColor != "test" {
		t.Errorf("Expected 'test' from no-color function, got '%s'", resultNoColor)
	}
}

// Test specific error guidance functions
func TestProvideCloneGuidance(t *testing.T) {
	// We can't easily capture stderr output in this context,
	// but we can test that the function doesn't panic
	helpers := NewGitErrorHelpers(false, true)

	authError := &services.GitError{ErrorCode: "AUTH_FAILED"}
	repoError := &services.GitError{ErrorCode: "REPO_NOT_FOUND"}
	networkError := &services.GitError{ErrorCode: "NETWORK_ERROR"}

	// These should not panic
	helpers.provideCloneGuidance(authError, "https://github.com/user/repo.git")
	helpers.provideCloneGuidance(repoError, "https://github.com/user/repo.git")
	helpers.provideCloneGuidance(networkError, "https://github.com/user/repo.git")
}

func TestProvidePullGuidance(t *testing.T) {
	helpers := NewGitErrorHelpers(false, true)

	localError := &services.GitError{ErrorCode: "LOCAL_REPO_NOT_EXISTS"}
	corruptError := &services.GitError{ErrorCode: "REPO_CORRUPT"}

	// These should not panic
	helpers.providePullGuidance(localError, "/tmp/repo")
	helpers.providePullGuidance(corruptError, "/tmp/repo")
}

func TestProvideAuthGuidance(t *testing.T) {
	helpers := NewGitErrorHelpers(false, true)

	authError := &services.GitError{ErrorCode: "AUTH_FAILED"}

	// This should not panic
	helpers.provideAuthGuidance(authError)
}