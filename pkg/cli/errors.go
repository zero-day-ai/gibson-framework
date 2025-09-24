// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/zero-day-ai/gibson-framework/pkg/services"
	"github.com/zero-day-ai/gibson-framework/pkg/core/utils"
	"github.com/fatih/color"
)

// ErrorDisplayMode controls how errors are displayed
type ErrorDisplayMode int

const (
	// ErrorDisplaySimple shows just the error message
	ErrorDisplaySimple ErrorDisplayMode = iota
	// ErrorDisplayDetailed shows full troubleshooting information
	ErrorDisplayDetailed
	// ErrorDisplayJSON shows error in JSON format
	ErrorDisplayJSON
)

// GitErrorHandler handles Git errors for CLI commands
type GitErrorHandler struct {
	Mode    ErrorDisplayMode
	NoColor bool
}

// NewGitErrorHandler creates a new Git error handler
func NewGitErrorHandler(detailed bool, noColor bool) *GitErrorHandler {
	mode := ErrorDisplaySimple
	if detailed {
		mode = ErrorDisplayDetailed
	}

	return &GitErrorHandler{
		Mode:    mode,
		NoColor: noColor,
	}
}

// HandleError formats and displays a Git error
func (h *GitErrorHandler) HandleError(err error, operation string) {
	if err == nil {
		return
	}

	// Check if it's a GitError with detailed information
	if gitErr, ok := err.(*services.GitError); ok {
		h.handleGitError(gitErr)
		return
	}

	// Handle regular errors
	h.handleGenericError(err, operation)
}

// handleGitError handles GitError types with full troubleshooting
func (h *GitErrorHandler) handleGitError(gitErr *services.GitError) {
	switch h.Mode {
	case ErrorDisplayDetailed:
		h.displayDetailedError(gitErr)
	case ErrorDisplayJSON:
		h.displayJSONError(gitErr)
	default:
		h.displaySimpleError(gitErr)
	}
}

// displaySimpleError shows a brief error message with key suggestions
func (h *GitErrorHandler) displaySimpleError(gitErr *services.GitError) {
	// Color functions
	red := h.colorFunc(color.FgRed)
	yellow := h.colorFunc(color.FgYellow)
	cyan := h.colorFunc(color.FgCyan)

	fmt.Fprintf(os.Stderr, "%s %s\n", red("Error:"), gitErr.UserMessage)

	if gitErr.RepositoryURL != "" {
		fmt.Fprintf(os.Stderr, "Repository: %s\n", gitErr.RepositoryURL)
	}

	// Show top 3 suggestions
	if len(gitErr.Suggestions) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s\n", yellow("Quick fixes:"))
		maxSuggestions := 3
		if len(gitErr.Suggestions) < maxSuggestions {
			maxSuggestions = len(gitErr.Suggestions)
		}
		for i := 0; i < maxSuggestions; i++ {
			fmt.Fprintf(os.Stderr, "  • %s\n", gitErr.Suggestions[i])
		}
	}

	// Show recovery information if applicable
	if gitErr.IsRecoverable {
		fmt.Fprintf(os.Stderr, "\n%s This error may be temporary. You can retry the operation.\n",
			cyan("Info:"))
	}

	// Suggest detailed help
	fmt.Fprintf(os.Stderr, "\nFor detailed troubleshooting, run the command with --verbose or --help-errors\n")
}

// displayDetailedError shows complete troubleshooting information
func (h *GitErrorHandler) displayDetailedError(gitErr *services.GitError) {
	fmt.Fprintf(os.Stderr, "%s\n", gitErr.GetDetailedMessage())
}

// displayJSONError shows error in JSON format
func (h *GitErrorHandler) displayJSONError(gitErr *services.GitError) {
	// TODO: Implement JSON serialization of GitError
	h.displaySimpleError(gitErr)
}

// handleGenericError handles non-GitError types
func (h *GitErrorHandler) handleGenericError(err error, operation string) {
	red := h.colorFunc(color.FgRed)

	if operation != "" {
		fmt.Fprintf(os.Stderr, "%s %s operation failed: %v\n", red("Error:"), operation, err)
	} else {
		fmt.Fprintf(os.Stderr, "%s %v\n", red("Error:"), err)
	}
}

// colorFunc returns a color function or identity function if colors are disabled
func (h *GitErrorHandler) colorFunc(attr color.Attribute) func(...interface{}) string {
	if h.NoColor {
		return func(a ...interface{}) string {
			return fmt.Sprint(a...)
		}
	}
	return color.New(attr).SprintFunc()
}

// GitErrorHelpers provides helper functions for specific Git operations
type GitErrorHelpers struct {
	handler *GitErrorHandler
}

// NewGitErrorHelpers creates a new Git error helpers instance
func NewGitErrorHelpers(detailed bool, noColor bool) *GitErrorHelpers {
	return &GitErrorHelpers{
		handler: NewGitErrorHandler(detailed, noColor),
	}
}

// HandleCloneError handles errors from Git clone operations
func (h *GitErrorHelpers) HandleCloneError(err error, repoName, url string) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "Failed to clone repository '%s'\n", repoName)
	h.handler.HandleError(err, "clone")

	// Provide specific guidance for clone errors
	if gitErr, ok := err.(*services.GitError); ok {
		h.provideCloneGuidance(gitErr, url)
	}
}

// HandlePullError handles errors from Git pull operations
func (h *GitErrorHelpers) HandlePullError(err error, repoName, localPath string) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "Failed to sync repository '%s'\n", repoName)
	h.handler.HandleError(err, "pull")

	// Provide specific guidance for pull errors
	if gitErr, ok := err.(*services.GitError); ok {
		h.providePullGuidance(gitErr, localPath)
	}
}

// HandleAuthError handles authentication-specific errors
func (h *GitErrorHelpers) HandleAuthError(err error, authType string) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "Authentication failed for %s\n", authType)
	h.handler.HandleError(err, "authentication")

	// Provide auth-specific guidance
	if gitErr, ok := err.(*services.GitError); ok {
		h.provideAuthGuidance(gitErr)
	}
}

// provideCloneGuidance provides specific guidance for clone errors
func (h *GitErrorHelpers) provideCloneGuidance(gitErr *services.GitError, url string) {
	yellow := h.handler.colorFunc(color.FgYellow)

	switch gitErr.ErrorCode {
	case "AUTH_FAILED":
		fmt.Fprintf(os.Stderr, "\n%s Repository authentication setup:\n", yellow("Next steps:"))
		if strings.Contains(url, "github.com") {
			fmt.Fprintf(os.Stderr, "  • Set up GitHub authentication: https://docs.github.com/en/authentication\n")
		} else if strings.Contains(url, "gitlab.com") {
			fmt.Fprintf(os.Stderr, "  • Set up GitLab authentication: https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html\n")
		}

	case "REPO_NOT_FOUND":
		fmt.Fprintf(os.Stderr, "\n%s Repository verification:\n", yellow("Next steps:"))
		fmt.Fprintf(os.Stderr, "  • Verify the repository exists: %s\n", url)
		fmt.Fprintf(os.Stderr, "  • Check if you have access permissions\n")

	case "NETWORK_ERROR":
		fmt.Fprintf(os.Stderr, "\n%s Network troubleshooting:\n", yellow("Next steps:"))
		fmt.Fprintf(os.Stderr, "  • Test connectivity: ping github.com\n")
		fmt.Fprintf(os.Stderr, "  • Check proxy settings if behind firewall\n")
	}
}

// providePullGuidance provides specific guidance for pull errors
func (h *GitErrorHelpers) providePullGuidance(gitErr *services.GitError, localPath string) {
	yellow := h.handler.colorFunc(color.FgYellow)

	switch gitErr.ErrorCode {
	case "LOCAL_REPO_NOT_EXISTS":
		fmt.Fprintf(os.Stderr, "\n%s Repository recovery:\n", yellow("Next steps:"))
		fmt.Fprintf(os.Stderr, "  • Repository may need to be re-cloned\n")
		fmt.Fprintf(os.Stderr, "  • Check local path: %s\n", localPath)

	case "REPO_CORRUPT":
		fmt.Fprintf(os.Stderr, "\n%s Repository recovery:\n", yellow("Next steps:"))
		fmt.Fprintf(os.Stderr, "  • Remove and re-clone: rm -rf %s\n", localPath)
		fmt.Fprintf(os.Stderr, "  • Then run sync again\n")
	}
}

// provideAuthGuidance provides authentication-specific guidance
func (h *GitErrorHelpers) provideAuthGuidance(gitErr *services.GitError) {
	cyan := h.handler.colorFunc(color.FgCyan)

	fmt.Fprintf(os.Stderr, "\n%s Credential management:\n", cyan("Gibson commands:"))
	fmt.Fprintf(os.Stderr, "  • List credentials: gibson credential list\n")
	fmt.Fprintf(os.Stderr, "  • Add credential: gibson credential add\n")
	fmt.Fprintf(os.Stderr, "  • Update credential: gibson credential update\n")
}

// ShowErrorSummary displays a summary of errors encountered during operations
func (h *GitErrorHelpers) ShowErrorSummary(errors []error, operation string) {
	if len(errors) == 0 {
		return
	}

	red := h.handler.colorFunc(color.FgRed)
	yellow := h.handler.colorFunc(color.FgYellow)

	fmt.Fprintf(os.Stderr, "\n%s %d errors occurred during %s operation:\n",
		red("Summary:"), len(errors), operation)

	// Categorize errors
	authErrors := 0
	networkErrors := 0
	permissionErrors := 0
	otherErrors := 0

	for _, err := range errors {
		if gitErr, ok := err.(*services.GitError); ok {
			switch {
			case strings.Contains(gitErr.ErrorCode, "AUTH"):
				authErrors++
			case strings.Contains(gitErr.ErrorCode, "NETWORK"):
				networkErrors++
			case strings.Contains(gitErr.ErrorCode, "PERMISSION"):
				permissionErrors++
			default:
				otherErrors++
			}
		} else {
			otherErrors++
		}
	}

	if authErrors > 0 {
		fmt.Fprintf(os.Stderr, "  • %d authentication errors\n", authErrors)
	}
	if networkErrors > 0 {
		fmt.Fprintf(os.Stderr, "  • %d network errors\n", networkErrors)
	}
	if permissionErrors > 0 {
		fmt.Fprintf(os.Stderr, "  • %d permission errors\n", permissionErrors)
	}
	if otherErrors > 0 {
		fmt.Fprintf(os.Stderr, "  • %d other errors\n", otherErrors)
	}

	fmt.Fprintf(os.Stderr, "\n%s Run with --verbose for detailed error information\n",
		yellow("Tip:"))
}

// ShowCloneError displays clone error guidance without requiring an error object
// This provides general troubleshooting information for clone operations
func (h *GitErrorHelpers) ShowCloneError(repoName, url string) {
	red := h.handler.colorFunc(color.FgRed)
	yellow := h.handler.colorFunc(color.FgYellow)
	cyan := h.handler.colorFunc(color.FgCyan)
	green := h.handler.colorFunc(color.FgGreen)

	fmt.Fprintf(os.Stderr, "%s Failed to clone repository '%s'\n", red("Error:"), repoName)
	fmt.Fprintf(os.Stderr, "Repository URL: %s\n", url)

	fmt.Fprintf(os.Stderr, "\n%s\n", yellow("Common clone issues and solutions:"))

	// Authentication issues
	fmt.Fprintf(os.Stderr, "\n%s Authentication Issues:\n", cyan("1."))
	fmt.Fprintf(os.Stderr, "   • Check if repository requires authentication\n")
	fmt.Fprintf(os.Stderr, "   • Verify credentials are correct and not expired\n")
	fmt.Fprintf(os.Stderr, "   • For private repos, ensure you have access permissions\n")
	fmt.Fprintf(os.Stderr, "   • %s Add --auth-type flag (ssh, https, token)\n", green("Solution:"))

	// Network issues
	fmt.Fprintf(os.Stderr, "\n%s Network Issues:\n", cyan("2."))
	fmt.Fprintf(os.Stderr, "   • Check internet connectivity\n")
	fmt.Fprintf(os.Stderr, "   • Verify repository URL is correct and accessible\n")
	fmt.Fprintf(os.Stderr, "   • Check if firewall is blocking Git operations\n")
	fmt.Fprintf(os.Stderr, "   • %s Test with: git clone %s\n", green("Solution:"), url)

	// Repository issues
	fmt.Fprintf(os.Stderr, "\n%s Repository Issues:\n", cyan("3."))
	fmt.Fprintf(os.Stderr, "   • Repository might not exist or be deleted\n")
	fmt.Fprintf(os.Stderr, "   • Branch might not exist (check --branch flag)\n")
	fmt.Fprintf(os.Stderr, "   • Repository might be empty\n")
	fmt.Fprintf(os.Stderr, "   • %s Verify URL and branch: gibson payload repository add %s %s --branch main\n", green("Solution:"), repoName, url)

	// Local issues
	fmt.Fprintf(os.Stderr, "\n%s Local Issues:\n", cyan("4."))
	fmt.Fprintf(os.Stderr, "   • Insufficient disk space\n")
	fmt.Fprintf(os.Stderr, "   • Permission issues with local directory\n")
	fmt.Fprintf(os.Stderr, "   • Local path already exists with conflicts\n")
	fmt.Fprintf(os.Stderr, "   • %s Use --force flag to overwrite existing repository\n", green("Solution:"))

	// Troubleshooting steps
	fmt.Fprintf(os.Stderr, "\n%s\n", yellow("Troubleshooting steps:"))
	fmt.Fprintf(os.Stderr, "   1. Test repository access: %s\n", cyan("gibson payload repository add test-repo "+url+" --force"))
	fmt.Fprintf(os.Stderr, "   2. Check with verbose output: %s\n", cyan("gibson payload repository add "+repoName+" "+url+" --verbose"))
	fmt.Fprintf(os.Stderr, "   3. Try different authentication: %s\n", cyan("gibson payload repository add "+repoName+" "+url+" --auth-type ssh"))
	fmt.Fprintf(os.Stderr, "   4. Use shallow clone: %s\n", cyan("gibson payload repository add "+repoName+" "+url+" --depth 1"))

	if h.handler.Mode == ErrorDisplayDetailed {
		fmt.Fprintf(os.Stderr, "\n%s\n", yellow("Advanced troubleshooting:"))
		fmt.Fprintf(os.Stderr, "   • Check Git configuration: git config --list\n")
		fmt.Fprintf(os.Stderr, "   • Verify SSH keys: ssh -T git@github.com (for GitHub)\n")
		fmt.Fprintf(os.Stderr, "   • Test HTTPS access: curl -I %s\n", url)
		fmt.Fprintf(os.Stderr, "   • Check proxy settings if behind corporate firewall\n")
	}

	fmt.Fprintf(os.Stderr, "\n%s Use --help-errors for more detailed troubleshooting guidance\n", yellow("Tip:"))
}

// IsRecoverableError checks if an error is automatically recoverable
func IsRecoverableError(err error) bool {
	if gitErr, ok := err.(*services.GitError); ok {
		return gitErr.IsRecoverable
	}
	return false
}

// GetRetryDelay returns the suggested retry delay for an error
func GetRetryDelay(err error) (bool, int) {
	if gitErr, ok := err.(*services.GitError); ok {
		if gitErr.IsRecoverable && gitErr.MaxRetries > 0 {
			return true, int(gitErr.RetryDelay.Seconds())
		}
	}
	return false, 0
}

// Common error patterns for CLI validation

// NewValidationError creates a validation error for CLI commands
func NewValidationError(field, value, reason string) error {
	return &services.GitError{
		Operation:   "validation",
		ErrorCode:   "VALIDATION_FAILED",
		UserMessage: fmt.Sprintf("Invalid %s: %s", field, reason),
		TechDetails: fmt.Sprintf("Field '%s' with value '%s' failed validation: %s", field, value, reason),
		Suggestions: []string{
			fmt.Sprintf("Check the %s format and try again", field),
			"Refer to documentation for correct format",
		},
		IsRecoverable: false,
	}
}

// ValidateRepositoryURL validates a repository URL and returns a user-friendly error
func ValidateRepositoryURL(url string) error {
	// Handle empty URL case with specific error code for backward compatibility
	if url == "" {
		return &services.GitError{
			Operation:   "validation",
			ErrorCode:   "VALIDATION_FAILED",
			UserMessage: "Repository URL cannot be empty",
			Suggestions: []string{
				"Provide a valid Git repository URL",
				"Examples: https://github.com/user/repo.git or git@github.com:user/repo.git",
			},
			IsRecoverable: false,
		}
	}

	// Use our improved Git URL validation for non-empty URLs
	if err := utils.ValidateGitURL(url); err != nil {
		return &services.GitError{
			Operation:   "validation",
			ErrorCode:   "INVALID_URL_FORMAT",
			UserMessage: "Invalid repository URL format",
			TechDetails: fmt.Sprintf("URL validation failed: %s", err.Error()),
			Suggestions: []string{
				"Use HTTPS format: https://github.com/user/repo.git",
				"Use SSH format: git@github.com:user/repo.git",
				"Use SSH scheme: ssh://git@github.com/user/repo.git",
				"Ensure the URL is complete and properly formatted",
			},
			References: []string{
				"Git URL formats: https://git-scm.com/docs/git-clone#_git_urls",
			},
			IsRecoverable: false,
		}
	}

	return nil
}