// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package utils

import (
	"errors"
	"net/url"
	"strings"
)

// ValidateGitURL validates a Git repository URL, supporting both HTTPS and SSH formats
func ValidateGitURL(gitURL string) error {
	if gitURL == "" {
		return errors.New("URL cannot be empty")
	}

	// Handle SSH URLs (git@hostname:path format)
	if strings.HasPrefix(gitURL, "git@") {
		return validateSSHURL(gitURL)
	}

	// Handle ssh:// URLs
	if strings.HasPrefix(gitURL, "ssh://") {
		return validateSSHSchemeURL(gitURL)
	}

	// Handle HTTPS/HTTP URLs using standard URL parsing
	if strings.HasPrefix(gitURL, "http://") || strings.HasPrefix(gitURL, "https://") {
		return validateHTTPURL(gitURL)
	}

	return errors.New("URL must start with http://, https://, git@, or ssh://")
}

// validateSSHURL validates SSH URLs in the format git@hostname:path
func validateSSHURL(gitURL string) error {
	// Remove git@ prefix
	withoutPrefix := strings.TrimPrefix(gitURL, "git@")

	// Must contain a colon to separate hostname from path
	if !strings.Contains(withoutPrefix, ":") {
		return errors.New("SSH URL must be in format git@hostname:path")
	}

	parts := strings.SplitN(withoutPrefix, ":", 2)
	if len(parts) != 2 {
		return errors.New("SSH URL must be in format git@hostname:path")
	}

	hostname := parts[0]
	path := parts[1]

	// Validate hostname is not empty
	if hostname == "" {
		return errors.New("SSH URL hostname cannot be empty")
	}

	// Validate path is not empty
	if path == "" {
		return errors.New("SSH URL path cannot be empty")
	}

	// Basic hostname validation (simple check for valid characters)
	if strings.Contains(hostname, " ") || strings.Contains(hostname, "\t") {
		return errors.New("SSH URL hostname contains invalid characters")
	}

	return nil
}

// validateSSHSchemeURL validates SSH URLs with ssh:// scheme
func validateSSHSchemeURL(gitURL string) error {
	parsed, err := url.Parse(gitURL)
	if err != nil {
		return err
	}

	if parsed.Scheme != "ssh" {
		return errors.New("SSH scheme URL must use ssh:// scheme")
	}

	if parsed.Host == "" {
		return errors.New("SSH scheme URL must have a hostname")
	}

	if parsed.Path == "" {
		return errors.New("SSH scheme URL must have a path")
	}

	return nil
}

// validateHTTPURL validates HTTP/HTTPS URLs using standard URL parsing
func validateHTTPURL(gitURL string) error {
	parsed, err := url.Parse(gitURL)
	if err != nil {
		return err
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("HTTP URL must use http:// or https:// scheme")
	}

	if parsed.Host == "" {
		return errors.New("HTTP URL must have a hostname")
	}

	if parsed.Path == "" || parsed.Path == "/" {
		return errors.New("HTTP URL must have a repository path")
	}

	return nil
}

// IsSSHURL returns true if the URL is an SSH Git URL
func IsSSHURL(gitURL string) bool {
	return strings.HasPrefix(gitURL, "git@") || strings.HasPrefix(gitURL, "ssh://")
}

// IsHTTPURL returns true if the URL is an HTTP/HTTPS Git URL
func IsHTTPURL(gitURL string) bool {
	return strings.HasPrefix(gitURL, "http://") || strings.HasPrefix(gitURL, "https://")
}

// NormalizeGitURL normalizes a Git URL to a consistent format
func NormalizeGitURL(gitURL string) string {
	// Remove trailing .git if present
	if strings.HasSuffix(gitURL, ".git") {
		gitURL = strings.TrimSuffix(gitURL, ".git")
	}

	// Remove trailing slash
	gitURL = strings.TrimSuffix(gitURL, "/")

	return gitURL
}