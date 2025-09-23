// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"errors"
	"fmt"
	"net"
	// "net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-git/go-git/v5"
	// "github.com/go-git/go-git/v5/plumbing/transport"
	// "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
)

// GitError represents a detailed Git operation error with troubleshooting guidance
type GitError struct {
	// Core error information
	Operation    string // The Git operation that failed (clone, pull, push, etc.)
	OriginalErr  error  // The original underlying error
	ErrorCode    string // Categorized error code for programmatic handling
	UserMessage  string // Human-readable error message
	TechDetails  string // Technical details for debugging

	// Context information
	RepositoryURL string                                 // The repository URL being accessed
	LocalPath     string                                 // Local path involved in the operation
	AuthType      coremodels.PayloadRepositoryAuthType  // Authentication method being used
	Branch        string                                 // Git branch involved
	Depth         int                                    // Clone depth if applicable

	// Troubleshooting guidance
	Suggestions     []string // Actionable troubleshooting steps
	KnownSolutions  []string // Known solutions for this specific error
	References      []string // Documentation links and references
	NextSteps       []string // What the user should try next

	// Recovery information
	IsRecoverable   bool     // Whether this error can be automatically retried
	RetryDelay      time.Duration // Suggested delay before retry
	MaxRetries      int      // Maximum number of retries recommended
}

// Error implements the error interface
func (ge *GitError) Error() string {
	return fmt.Sprintf("Git %s failed: %s", ge.Operation, ge.UserMessage)
}

// GetDetailedMessage returns a comprehensive error message with troubleshooting
func (ge *GitError) GetDetailedMessage() string {
	var msg strings.Builder

	msg.WriteString(fmt.Sprintf("Git %s Operation Failed\n", strings.Title(ge.Operation)))
	msg.WriteString(strings.Repeat("=", 50) + "\n\n")

	// Error summary
	msg.WriteString(fmt.Sprintf("Error: %s\n", ge.UserMessage))
	if ge.ErrorCode != "" {
		msg.WriteString(fmt.Sprintf("Code: %s\n", ge.ErrorCode))
	}
	msg.WriteString("\n")

	// Context information
	msg.WriteString("Context:\n")
	if ge.RepositoryURL != "" {
		msg.WriteString(fmt.Sprintf("  Repository: %s\n", ge.RepositoryURL))
	}
	if ge.LocalPath != "" {
		msg.WriteString(fmt.Sprintf("  Local Path: %s\n", ge.LocalPath))
	}
	if ge.AuthType != "" {
		msg.WriteString(fmt.Sprintf("  Auth Type: %s\n", ge.AuthType))
	}
	if ge.Branch != "" {
		msg.WriteString(fmt.Sprintf("  Branch: %s\n", ge.Branch))
	}
	msg.WriteString("\n")

	// Technical details
	if ge.TechDetails != "" {
		msg.WriteString("Technical Details:\n")
		msg.WriteString(fmt.Sprintf("  %s\n\n", ge.TechDetails))
	}

	// Troubleshooting suggestions
	if len(ge.Suggestions) > 0 {
		msg.WriteString("Troubleshooting Steps:\n")
		for i, suggestion := range ge.Suggestions {
			msg.WriteString(fmt.Sprintf("  %d. %s\n", i+1, suggestion))
		}
		msg.WriteString("\n")
	}

	// Known solutions
	if len(ge.KnownSolutions) > 0 {
		msg.WriteString("Known Solutions:\n")
		for i, solution := range ge.KnownSolutions {
			msg.WriteString(fmt.Sprintf("  %d. %s\n", i+1, solution))
		}
		msg.WriteString("\n")
	}

	// Next steps
	if len(ge.NextSteps) > 0 {
		msg.WriteString("Recommended Next Steps:\n")
		for i, step := range ge.NextSteps {
			msg.WriteString(fmt.Sprintf("  %d. %s\n", i+1, step))
		}
		msg.WriteString("\n")
	}

	// References
	if len(ge.References) > 0 {
		msg.WriteString("Additional Resources:\n")
		for _, ref := range ge.References {
			msg.WriteString(fmt.Sprintf("  - %s\n", ref))
		}
		msg.WriteString("\n")
	}

	// Recovery information
	if ge.IsRecoverable {
		msg.WriteString("Recovery: This error may be temporary and could be retried.\n")
		if ge.MaxRetries > 0 {
			msg.WriteString(fmt.Sprintf("  Maximum retries: %d\n", ge.MaxRetries))
		}
		if ge.RetryDelay > 0 {
			msg.WriteString(fmt.Sprintf("  Suggested delay: %v\n", ge.RetryDelay))
		}
	} else {
		msg.WriteString("Recovery: This error requires manual intervention.\n")
	}

	return msg.String()
}

// WrapGitError analyzes a Git error and wraps it with detailed troubleshooting information
func WrapGitError(operation string, err error, context GitErrorContext) *GitError {
	if err == nil {
		return nil
	}

	// Check if it's already a GitError
	if gitErr, ok := err.(*GitError); ok {
		return gitErr
	}

	gitError := &GitError{
		Operation:     operation,
		OriginalErr:   err,
		RepositoryURL: context.RepositoryURL,
		LocalPath:     context.LocalPath,
		AuthType:      context.AuthType,
		Branch:        context.Branch,
		Depth:         context.Depth,
		TechDetails:   err.Error(),
	}

	// Analyze the error and provide specific guidance
	analyzeError(gitError)

	return gitError
}

// GitErrorContext provides context for error analysis
type GitErrorContext struct {
	RepositoryURL string
	LocalPath     string
	AuthType      coremodels.PayloadRepositoryAuthType
	Branch        string
	Depth         int
}

// analyzeError examines the error and provides specific troubleshooting guidance
func analyzeError(gitError *GitError) {
	err := gitError.OriginalErr
	errStr := err.Error()

	// Check specific errors first before general categories
	// Order matters - more specific checks must come before general ones

	// Timeout errors (specific check before network errors)
	if isTimeoutError(err) {
		handleTimeoutError(gitError)
		return
	}

	// SSH key errors (specific check before authentication errors)
	if isSSHKeyError(err) {
		handleSSHKeyError(gitError)
		return
	}

	// Permission errors (specific check before authentication errors)
	if isPermissionError(err) {
		handlePermissionError(gitError)
		return
	}

	// Branch/reference errors (specific check before repository errors)
	if isBranchError(err) {
		handleBranchError(gitError)
		return
	}

	// URL format errors (specific check before corruption errors)
	if isURLFormatError(err) {
		handleURLFormatError(gitError)
		return
	}

	// Disk space errors (specific filesystem error)
	if isDiskSpaceError(err) {
		handleDiskSpaceError(gitError)
		return
	}

	// Authentication errors (general authentication category)
	if isAuthenticationError(err) {
		handleAuthenticationError(gitError)
		return
	}

	// Network/connectivity errors (general network category)
	if isNetworkError(err) {
		handleNetworkError(gitError)
		return
	}

	// Repository not found errors
	if isRepositoryNotFoundError(err) {
		handleRepositoryNotFoundError(gitError)
		return
	}

	// Repository corruption errors
	if isRepositoryCorruptionError(err) {
		handleRepositoryCorruptionError(gitError)
		return
	}

	// Git configuration errors
	if isGitConfigError(err) {
		handleGitConfigError(gitError)
		return
	}

	// Branch/reference errors
	if isBranchError(err) {
		handleBranchError(gitError)
		return
	}

	// URL format errors
	if isURLFormatError(err) {
		handleURLFormatError(gitError)
		return
	}

	// Path/filesystem errors
	if isPathError(err) {
		handlePathError(gitError)
		return
	}

	// Check for specific go-git errors
	if errors.Is(err, git.ErrRepositoryAlreadyExists) {
		handleRepositoryAlreadyExistsError(gitError)
		return
	}

	if errors.Is(err, git.ErrRepositoryNotExists) {
		handleRepositoryNotExistsError(gitError)
		return
	}

	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		handleAlreadyUpToDateError(gitError)
		return
	}

	// Generic patterns
	if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") {
		handleCertificateError(gitError)
		return
	}

	if strings.Contains(errStr, "proxy") {
		handleProxyError(gitError)
		return
	}

	// Default handling for unrecognized errors
	handleGenericError(gitError)
}

// Authentication error handlers

func isAuthenticationError(err error) bool {
	// Only match general authentication errors, not specific permission/SSH errors
	// that are handled by other functions
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "authentication") ||
		   strings.Contains(errStr, "access denied") ||
		   strings.Contains(errStr, "invalid credentials") ||
		   strings.Contains(errStr, "unauthorized")
		   // Note: "permission denied", "public key", "ssh key" are handled by specific functions
}

func handleAuthenticationError(gitError *GitError) {
	gitError.ErrorCode = "AUTH_FAILED"
	gitError.UserMessage = "Git authentication failed - Unable to authenticate with the repository"

	switch gitError.AuthType {
	case coremodels.PayloadRepositoryAuthTypeSSH:
		gitError.Suggestions = []string{
			"Verify that your SSH key is properly configured",
			"Check that your SSH key is added to your Git provider (GitHub, GitLab, etc.)",
			"Ensure the SSH key has the correct permissions (600 for private key)",
			"Test SSH connection with: ssh -T git@github.com (for GitHub)",
			"Verify the repository URL uses the correct SSH format (git@host:user/repo.git)",
		}
		gitError.KnownSolutions = []string{
			"Add your public key to your Git provider's SSH keys settings",
			"Generate a new SSH key if the current one is invalid: ssh-keygen -t ed25519 -C 'your_email@example.com'",
			"Check SSH agent is running: eval $(ssh-agent -s) && ssh-add ~/.ssh/id_rsa",
			"Verify SSH key fingerprint matches your provider's records",
		}
		gitError.NextSteps = []string{
			"Run 'gibson credential add' to store SSH key credentials",
			"Check SSH key permissions with: ls -la ~/.ssh/",
			"Test repository access with git ls-remote",
		}
		gitError.References = []string{
			"SSH Key Setup: https://docs.github.com/en/authentication/connecting-to-github-with-ssh",
			"Troubleshooting SSH: https://docs.github.com/en/authentication/troubleshooting-ssh",
		}

	case coremodels.PayloadRepositoryAuthTypeHTTPS, coremodels.PayloadRepositoryAuthTypeToken:
		gitError.Suggestions = []string{
			"Verify your personal access token is valid and not expired",
			"Check that the token has the required repository permissions",
			"Ensure the username is correct (use token for GitHub username)",
			"Verify the repository URL is accessible and correct",
			"Check if two-factor authentication is enabled and configured properly",
		}
		gitError.KnownSolutions = []string{
			"Generate a new personal access token with appropriate scopes",
			"Use 'git' or your username as the username field",
			"Store credentials securely with: gibson credential add",
			"Clear cached credentials and re-authenticate",
		}
		gitError.NextSteps = []string{
			"Create a new personal access token from your Git provider",
			"Update stored credentials with: gibson credential update",
			"Test repository access with git ls-remote",
		}
		gitError.References = []string{
			"GitHub Personal Access Tokens: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token",
			"GitLab Access Tokens: https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html",
		}
	}

	gitError.IsRecoverable = false // Requires manual credential fix
}

// Network error handlers

func isNetworkError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "network") ||
		   strings.Contains(errStr, "connection") ||
		   strings.Contains(errStr, "dial") ||
		   strings.Contains(errStr, "dns") ||
		   strings.Contains(errStr, "timeout") ||
		   strings.Contains(errStr, "unreachable")
}

func handleNetworkError(gitError *GitError) {
	gitError.ErrorCode = "NETWORK_ERROR"
	gitError.UserMessage = "Network connectivity issue - Unable to reach the Git repository"

	gitError.Suggestions = []string{
		"Check your internet connection",
		"Verify the repository URL is correct and accessible",
		"Try accessing the repository in a web browser",
		"Check if you're behind a firewall or proxy",
		"Verify DNS resolution: nslookup github.com",
		"Test network connectivity: ping github.com",
	}

	gitError.KnownSolutions = []string{
		"Configure proxy settings if behind a corporate firewall",
		"Use VPN if accessing private networks",
		"Switch to a different network connection",
		"Configure Git to use proxy: git config --global http.proxy http://proxy:port",
	}

	gitError.NextSteps = []string{
		"Wait a few minutes and retry the operation",
		"Check the Git provider's status page for outages",
		"Try using a different network connection",
	}

	gitError.References = []string{
		"Git Proxy Configuration: https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpproxy",
		"GitHub Status: https://www.githubstatus.com/",
	}

	gitError.IsRecoverable = true
	gitError.RetryDelay = 30 * time.Second
	gitError.MaxRetries = 3
}

// Repository not found error handlers

func isRepositoryNotFoundError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "not found") ||
		   strings.Contains(errStr, "404") ||
		   strings.Contains(errStr, "repository does not exist")
}

func handleRepositoryNotFoundError(gitError *GitError) {
	gitError.ErrorCode = "REPO_NOT_FOUND"
	gitError.UserMessage = "Repository not found - The specified Git repository does not exist or is not accessible"

	gitError.Suggestions = []string{
		"Verify the repository URL is correct",
		"Check that the repository exists and you have access to it",
		"Ensure the repository name and organization/username are correct",
		"Verify you have the necessary permissions to access the repository",
		"Check if the repository is private and requires authentication",
	}

	gitError.KnownSolutions = []string{
		"Double-check the repository URL in your Git provider's web interface",
		"Ensure you have been granted access to private repositories",
		"Use the correct case for repository names (some providers are case-sensitive)",
		"Verify the repository hasn't been moved or renamed",
	}

	gitError.NextSteps = []string{
		"Confirm the repository exists by accessing it in a web browser",
		"Check with the repository owner for access permissions",
		"Verify the URL format matches your Git provider's requirements",
	}

	gitError.IsRecoverable = false // Requires URL/permission correction
}

// Permission error handlers

func isPermissionError(err error) bool {
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err == syscall.EACCES || pathErr.Err == syscall.EPERM
	}

	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "permission") ||
		   strings.Contains(errStr, "access is denied") ||
		   strings.Contains(errStr, "operation not permitted")
}

func handlePermissionError(gitError *GitError) {
	gitError.ErrorCode = "PERMISSION_DENIED"
	gitError.UserMessage = "File system permission denied - Unable to access or modify local files"

	gitError.Suggestions = []string{
		"Check file and directory permissions",
		"Ensure you have write access to the target directory",
		"Verify the directory is not read-only",
		"Check if files are being used by another process",
		"Run with appropriate user permissions",
	}

	gitError.KnownSolutions = []string{
		fmt.Sprintf("Change directory permissions: chmod 755 %s", filepath.Dir(gitError.LocalPath)),
		fmt.Sprintf("Change ownership: chown $USER %s", filepath.Dir(gitError.LocalPath)),
		"Close any applications that might be using the files",
		"Run the command with sudo (if appropriate)",
	}

	gitError.NextSteps = []string{
		"Check current directory permissions",
		"Ensure the parent directory is writable",
		"Free up any file locks on the target directory",
	}

	gitError.IsRecoverable = false // Requires permission fix
}

// Additional error handlers for SSH, timeout, disk space, etc.

func isSSHKeyError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "ssh") &&
		   (strings.Contains(errStr, "key") ||
			strings.Contains(errStr, "host key") ||
			strings.Contains(errStr, "known_hosts") ||
			strings.Contains(errStr, "handshake failed") ||
			strings.Contains(errStr, "unable to authenticate"))
}

func handleSSHKeyError(gitError *GitError) {
	gitError.ErrorCode = "SSH_KEY_ERROR"
	gitError.UserMessage = "SSH key configuration issue - Problem with SSH key setup or host verification"

	gitError.Suggestions = []string{
		"Verify SSH key exists and has correct permissions (600)",
		"Check known_hosts file for host key verification",
		"Ensure SSH agent is running and key is loaded",
		"Test SSH connection to the Git provider",
		"Verify the SSH key format is correct",
	}

	gitError.KnownSolutions = []string{
		"Add host to known_hosts: ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts",
		"Load SSH key into agent: ssh-add ~/.ssh/id_rsa",
		"Generate new SSH key: ssh-keygen -t ed25519 -C 'email@example.com'",
		"Fix key permissions: chmod 600 ~/.ssh/id_rsa",
	}

	gitError.NextSteps = []string{
		"Test SSH connection: ssh -T git@github.com",
		"Check SSH configuration: ssh -vvv git@github.com",
		"Regenerate SSH keys if necessary",
	}

	gitError.References = []string{
		"SSH Troubleshooting: https://docs.github.com/en/authentication/troubleshooting-ssh",
	}

	gitError.IsRecoverable = false
}

func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded")
}

func handleTimeoutError(gitError *GitError) {
	gitError.ErrorCode = "TIMEOUT"
	gitError.UserMessage = "Operation timed out - The Git operation took too long to complete"

	gitError.Suggestions = []string{
		"Check your internet connection speed",
		"Try using a smaller clone depth for large repositories",
		"Consider using --depth 1 for shallow clones",
		"Retry during off-peak hours",
		"Check for network congestion or proxy issues",
	}

	gitError.KnownSolutions = []string{
		"Use shallow clone: --depth 1",
		"Increase Git timeout: git config --global http.postBuffer 524288000",
		"Use SSH instead of HTTPS for better performance",
		"Clone in multiple steps (fetch specific branches)",
	}

	gitError.NextSteps = []string{
		"Retry with shallow clone option",
		"Check network stability",
		"Try during different time periods",
	}

	gitError.IsRecoverable = true
	gitError.RetryDelay = 60 * time.Second
	gitError.MaxRetries = 2
}

func isDiskSpaceError(err error) bool {
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err == syscall.ENOSPC
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "no space") || strings.Contains(errStr, "disk full")
}

func handleDiskSpaceError(gitError *GitError) {
	gitError.ErrorCode = "DISK_FULL"
	gitError.UserMessage = "Insufficient disk space - Not enough space available to complete the operation"

	gitError.Suggestions = []string{
		"Free up disk space on your system",
		"Check available space: df -h",
		"Clean up temporary files and caches",
		"Consider using a different target directory with more space",
		"Use shallow clone (--depth 1) to reduce space requirements",
	}

	gitError.NextSteps = []string{
		"Clean up unnecessary files",
		"Move to a directory with more available space",
		"Use shallow clone to reduce repository size",
	}

	gitError.IsRecoverable = false
}

// Continue with remaining error handlers...

func isRepositoryCorruptionError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "corrupt") ||
		   strings.Contains(errStr, "invalid") ||
		   strings.Contains(errStr, "malformed")
}

func handleRepositoryCorruptionError(gitError *GitError) {
	gitError.ErrorCode = "REPO_CORRUPT"
	gitError.UserMessage = "Repository corruption detected - The local or remote repository appears to be corrupted"

	gitError.Suggestions = []string{
		"Remove the local repository and re-clone",
		"Check the remote repository status",
		"Verify network connection integrity",
		"Try cloning to a different location",
	}

	gitError.KnownSolutions = []string{
		"Delete local repository and clone fresh copy",
		"Use git fsck to check repository integrity",
		"Contact repository administrator if remote is corrupted",
	}

	gitError.IsRecoverable = true // Can re-clone
	gitError.MaxRetries = 1
}

func isGitConfigError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "config") || strings.Contains(errStr, "configuration")
}

func handleGitConfigError(gitError *GitError) {
	gitError.ErrorCode = "CONFIG_ERROR"
	gitError.UserMessage = "Git configuration issue - Problem with Git configuration settings"

	gitError.Suggestions = []string{
		"Check Git configuration: git config --list",
		"Verify user name and email are set",
		"Check for invalid configuration values",
		"Reset configuration if necessary",
	}

	gitError.IsRecoverable = false
}

func isBranchError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "branch") ||
		   strings.Contains(errStr, "reference not found") ||
		   strings.Contains(errStr, "ref not found")
}

func handleBranchError(gitError *GitError) {
	gitError.ErrorCode = "BRANCH_NOT_FOUND"
	gitError.UserMessage = fmt.Sprintf("Branch '%s' not found - The specified branch does not exist", gitError.Branch)

	gitError.Suggestions = []string{
		"Verify the branch name is correct",
		"Check available branches: git branch -r",
		"Use 'main' or 'master' if unsure of default branch",
		"Check if the branch has been renamed or deleted",
	}

	gitError.IsRecoverable = false
}

func isURLFormatError(err error) bool {
	errStr := strings.ToLower(err.Error())
	// More specific URL format detection - combine URL keywords with format issues
	return (strings.Contains(errStr, "url") &&
		   (strings.Contains(errStr, "invalid") || strings.Contains(errStr, "malformed"))) ||
		   strings.Contains(errStr, "invalid url")
}

func handleURLFormatError(gitError *GitError) {
	gitError.ErrorCode = "INVALID_URL"
	gitError.UserMessage = "Invalid repository URL format"

	gitError.Suggestions = []string{
		"Check URL format: https://github.com/user/repo.git",
		"For SSH: git@github.com:user/repo.git",
		"Ensure no typos in the URL",
		"Verify the Git provider's URL format requirements",
	}

	gitError.IsRecoverable = false
}

func isPathError(err error) bool {
	_, ok := err.(*os.PathError)
	return ok
}

func handlePathError(gitError *GitError) {
	gitError.ErrorCode = "PATH_ERROR"
	gitError.UserMessage = "File system path issue"

	gitError.Suggestions = []string{
		"Check that the path exists and is accessible",
		"Verify directory permissions",
		"Ensure the path is not too long",
		"Check for invalid characters in the path",
	}

	gitError.IsRecoverable = false
}

// Specific go-git error handlers

func handleRepositoryAlreadyExistsError(gitError *GitError) {
	gitError.ErrorCode = "REPO_EXISTS"
	gitError.UserMessage = "Repository already exists at the target location"

	gitError.Suggestions = []string{
		"Use a different target directory",
		"Remove the existing directory first",
		"Use --force flag to overwrite if supported",
	}

	gitError.IsRecoverable = false
}

func handleRepositoryNotExistsError(gitError *GitError) {
	gitError.ErrorCode = "LOCAL_REPO_NOT_EXISTS"
	gitError.UserMessage = "Local repository does not exist"

	gitError.Suggestions = []string{
		"Initialize the repository first",
		"Clone the repository before performing this operation",
		"Check that you're in the correct directory",
	}

	gitError.IsRecoverable = false
}

func handleAlreadyUpToDateError(gitError *GitError) {
	gitError.ErrorCode = "UP_TO_DATE"
	gitError.UserMessage = "Repository is already up to date"

	// This is not really an error
	gitError.IsRecoverable = true
}

func handleCertificateError(gitError *GitError) {
	gitError.ErrorCode = "CERT_ERROR"
	gitError.UserMessage = "SSL/TLS certificate verification failed"

	gitError.Suggestions = []string{
		"Check system time and date accuracy",
		"Update CA certificates",
		"Verify the server's SSL certificate",
		"Check for corporate firewall certificate injection",
	}

	gitError.KnownSolutions = []string{
		"Disable SSL verification temporarily: git config --global http.sslVerify false",
		"Update CA bundle",
		"Configure corporate certificates if behind corporate firewall",
	}

	gitError.IsRecoverable = false
}

func handleProxyError(gitError *GitError) {
	gitError.ErrorCode = "PROXY_ERROR"
	gitError.UserMessage = "Proxy configuration issue"

	gitError.Suggestions = []string{
		"Check proxy settings",
		"Configure Git proxy settings",
		"Verify proxy authentication",
		"Test proxy connectivity",
	}

	gitError.KnownSolutions = []string{
		"Set Git proxy: git config --global http.proxy http://proxy:port",
		"Set proxy authentication: git config --global http.proxy http://user:pass@proxy:port",
		"Bypass proxy for specific hosts: git config --global http.proxy.*.noproxy true",
	}

	gitError.IsRecoverable = false
}

func handleGenericError(gitError *GitError) {
	gitError.ErrorCode = "UNKNOWN"
	gitError.UserMessage = "An unexpected error occurred during the Git operation"

	gitError.Suggestions = []string{
		"Check the error details for specific issues",
		"Verify all prerequisites are met",
		"Try the operation again",
		"Check Git and system logs for more information",
	}

	gitError.NextSteps = []string{
		"Review the technical details below",
		"Search for the specific error message online",
		"Contact support if the issue persists",
	}

	gitError.IsRecoverable = true
	gitError.MaxRetries = 1
}

// Helper functions for creating common error scenarios

// NewCloneError creates a GitError for clone operations
func NewCloneError(err error, url, localPath string, authType coremodels.PayloadRepositoryAuthType, branch string, depth int) *GitError {
	return WrapGitError("clone", err, GitErrorContext{
		RepositoryURL: url,
		LocalPath:     localPath,
		AuthType:      authType,
		Branch:        branch,
		Depth:         depth,
	})
}

// NewPullError creates a GitError for pull operations
func NewPullError(err error, localPath string, authType coremodels.PayloadRepositoryAuthType) *GitError {
	return WrapGitError("pull", err, GitErrorContext{
		LocalPath: localPath,
		AuthType:  authType,
	})
}

// NewAuthError creates a GitError for authentication failures
func NewAuthError(authType coremodels.PayloadRepositoryAuthType, url string, details string) *GitError {
	gitError := &GitError{
		Operation:     "authentication",
		ErrorCode:     "AUTH_FAILED",
		UserMessage:   "Authentication failed",
		TechDetails:   details,
		RepositoryURL: url,
		AuthType:      authType,
		IsRecoverable: false,
	}

	handleAuthenticationError(gitError)
	return gitError
}

// NewValidationError creates a GitError for validation failures
func NewValidationError(field, value, reason string) *GitError {
	return &GitError{
		Operation:     "validation",
		ErrorCode:     "VALIDATION_FAILED",
		UserMessage:   fmt.Sprintf("Invalid %s: %s", field, reason),
		TechDetails:   fmt.Sprintf("Field '%s' with value '%s' failed validation: %s", field, value, reason),
		IsRecoverable: false,
		Suggestions: []string{
			fmt.Sprintf("Check the %s format and try again", field),
			"Refer to documentation for correct format",
		},
	}
}

// Helper function to generate SSH setup guidance
func GetSSHSetupGuidance() []string {
	return []string{
		"Generate SSH key: ssh-keygen -t ed25519 -C 'your_email@example.com'",
		"Add key to SSH agent: eval $(ssh-agent -s) && ssh-add ~/.ssh/id_ed25519",
		"Copy public key: cat ~/.ssh/id_ed25519.pub",
		"Add public key to your Git provider's SSH keys settings",
		"Test connection: ssh -T git@github.com",
	}
}

// Helper function to generate token setup guidance
func GetTokenSetupGuidance() []string {
	return []string{
		"Generate personal access token from your Git provider",
		"For GitHub: Settings > Developer settings > Personal access tokens",
		"Select required scopes (repo for private repositories)",
		"Copy the token immediately (it won't be shown again)",
		"Store securely with: gibson credential add",
	}
}