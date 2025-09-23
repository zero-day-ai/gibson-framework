// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PayloadRepositoryService provides utility functions for payload repository management
type PayloadRepositoryService struct{}

// NewPayloadRepositoryService creates a new payload repository service
func NewPayloadRepositoryService() *PayloadRepositoryService {
	return &PayloadRepositoryService{}
}

// GenerateLocalPath generates a local path for a repository under ~/.gibson/repositories/{name}
// This ensures each repository has a unique local path for cloning and syncing
func (s *PayloadRepositoryService) GenerateLocalPath(name string) (string, error) {
	// Get Gibson home directory
	gibsonHome, err := s.getGibsonHome()
	if err != nil {
		return "", fmt.Errorf("failed to get Gibson home directory: %w", err)
	}

	// Sanitize repository name for filesystem use
	sanitizedName := s.sanitizeRepositoryName(name)
	if sanitizedName == "" {
		return "", fmt.Errorf("repository name '%s' cannot be sanitized for filesystem use", name)
	}

	// Create repositories directory path
	repositoriesDir := filepath.Join(gibsonHome, "repositories")
	localPath := filepath.Join(repositoriesDir, sanitizedName)

	// Ensure repositories directory exists
	if err := os.MkdirAll(repositoriesDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create repositories directory: %w", err)
	}

	// Check if path already exists and handle conflicts
	if _, err := os.Stat(localPath); err == nil {
		// Path exists, generate a unique name by appending a suffix
		counter := 1
		for {
			uniquePath := fmt.Sprintf("%s-%d", localPath, counter)
			if _, err := os.Stat(uniquePath); os.IsNotExist(err) {
				localPath = uniquePath
				break
			}
			counter++
			// Safety check to prevent infinite loop
			if counter > 1000 {
				return "", fmt.Errorf("unable to generate unique path for repository '%s'", name)
			}
		}
	}

	return localPath, nil
}

// getGibsonHome returns the Gibson home directory (~/.gibson)
func (s *PayloadRepositoryService) getGibsonHome() (string, error) {
	// Check for GIBSON_HOME environment variable first
	if gibsonHome := os.Getenv("GIBSON_HOME"); gibsonHome != "" {
		return gibsonHome, nil
	}

	// Fall back to ~/.gibson
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	return filepath.Join(homeDir, ".gibson"), nil
}

// sanitizeRepositoryName sanitizes a repository name for filesystem use
// Removes or replaces characters that are not safe for filesystem paths
func (s *PayloadRepositoryService) sanitizeRepositoryName(name string) string {
	// Remove leading/trailing whitespace
	name = strings.TrimSpace(name)

	// Replace invalid filesystem characters with hyphens
	// Invalid characters: / \ : * ? " < > |
	invalidChars := regexp.MustCompile(`[/\\:*?"<>|]`)
	name = invalidChars.ReplaceAllString(name, "-")

	// Replace multiple consecutive hyphens with single hyphen
	multiHyphens := regexp.MustCompile(`-+`)
	name = multiHyphens.ReplaceAllString(name, "-")

	// Remove leading/trailing hyphens
	name = strings.Trim(name, "-")

	// Ensure name is not empty and not reserved names
	if name == "" || name == "." || name == ".." {
		return ""
	}

	// Limit length to prevent filesystem issues
	if len(name) > 100 {
		name = name[:100]
		// Remove trailing hyphen if truncation created one
		name = strings.TrimSuffix(name, "-")
	}

	return name
}

// ValidateLocalPath validates that a local path is within the Gibson repositories directory
func (s *PayloadRepositoryService) ValidateLocalPath(localPath string) error {
	gibsonHome, err := s.getGibsonHome()
	if err != nil {
		return fmt.Errorf("failed to get Gibson home directory: %w", err)
	}

	repositoriesDir := filepath.Join(gibsonHome, "repositories")

	// Clean and resolve paths to handle symlinks and relative paths
	cleanLocalPath := filepath.Clean(localPath)
	cleanRepositoriesDir := filepath.Clean(repositoriesDir)

	// Check if the local path is within the repositories directory
	relPath, err := filepath.Rel(cleanRepositoriesDir, cleanLocalPath)
	if err != nil || strings.HasPrefix(relPath, "..") {
		return fmt.Errorf("local path '%s' must be within Gibson repositories directory '%s'", localPath, repositoriesDir)
	}

	return nil
}

// EnsureRepositoriesDirectory ensures the repositories directory exists
func (s *PayloadRepositoryService) EnsureRepositoriesDirectory() error {
	gibsonHome, err := s.getGibsonHome()
	if err != nil {
		return fmt.Errorf("failed to get Gibson home directory: %w", err)
	}

	repositoriesDir := filepath.Join(gibsonHome, "repositories")
	return os.MkdirAll(repositoriesDir, 0755)
}