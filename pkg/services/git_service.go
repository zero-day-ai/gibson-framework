// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/pkg/core/utils"
)

// GitServiceConfig holds configuration for Git operations
type GitServiceConfig struct {
	// Default clone depth (0 means full clone)
	DefaultDepth int
	// Default branch to clone
	DefaultBranch string
	// Base directory for cloning repositories
	BaseDir string
	// SSH private key path for SSH authentication
	SSHKeyPath string
	// SSH known hosts file path
	SSHKnownHostsPath string
	// Use system git command for SSH operations
	UseSystemGit bool
}

// GitCloneOptions holds options for cloning operations
type GitCloneOptions struct {
	URL           string
	LocalPath     string
	Depth         int
	Branch        string
	AuthType      models.PayloadRepositoryAuthType
	Username      string
	Password      string
	Token         string
	SSHKeyPath    string
	Progress      func(string)
	Full          bool // Override depth to do full clone
}

// GitPullOptions holds options for pull operations
type GitPullOptions struct {
	LocalPath     string
	AuthType      models.PayloadRepositoryAuthType
	Username      string
	Password      string
	Token         string
	SSHKeyPath    string
	Progress      func(string)
}

// GitValidationResult holds validation results
type GitValidationResult struct {
	IsValid       bool
	IsGitRepo     bool
	HasRemote     bool
	RemoteURL     string
	CurrentBranch string
	IsDirty       bool
	LastCommit    string
	Errors        []string
}

// GitService provides Git operations using go-git library
type GitService struct {
	config GitServiceConfig
}

// NewGitService creates a new GitService instance
func NewGitService(cfg GitServiceConfig) *GitService {
	// Set defaults
	if cfg.DefaultDepth == 0 {
		cfg.DefaultDepth = 1 // Default to shallow clone
	}
	if cfg.DefaultBranch == "" {
		cfg.DefaultBranch = "main"
	}
	if cfg.BaseDir == "" {
		cfg.BaseDir = "/tmp/gibson-repos"
	}

	return &GitService{
		config: cfg,
	}
}

// Clone clones a Git repository with the specified options
// Requirement 1.1: Repository Management, 1.3: Default depth=1, 4.1: SSH auth, 4.2: HTTPS auth
func (gs *GitService) Clone(ctx context.Context, opts GitCloneOptions) models.Result[string] {
	// Use system git for SSH operations to leverage SSH agent and system configuration
	if opts.AuthType == models.PayloadRepositoryAuthTypeSSH || strings.HasPrefix(opts.URL, "git@") {
		return gs.cloneWithSystemGit(ctx, opts)
	}
	// Validate options
	if opts.URL == "" {
		return models.Err[string](NewValidationError("repository URL", opts.URL, "URL cannot be empty"))
	}
	if opts.LocalPath == "" {
		return models.Err[string](NewValidationError("local path", opts.LocalPath, "local path cannot be empty"))
	}

	// Validate URL format
	urlValidation := gs.ValidateURL(opts.URL)
	if urlValidation.IsErr() {
		return models.Err[string](NewValidationError("repository URL", opts.URL, urlValidation.Error().Error()))
	}

	// Set defaults
	if opts.Depth == 0 && !opts.Full {
		opts.Depth = gs.config.DefaultDepth
	}
	if opts.Full {
		opts.Depth = 0 // Full clone
	}
	if opts.Branch == "" {
		opts.Branch = gs.config.DefaultBranch
	}

	// Prepare clone options
	cloneOpts := &git.CloneOptions{
		URL:      opts.URL,
		Progress: nil,
	}

	// Set depth for shallow clone (Requirement 1.3)
	if opts.Depth > 0 {
		cloneOpts.Depth = opts.Depth
	}

	// Set branch
	cloneOpts.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", opts.Branch))
	cloneOpts.SingleBranch = true

	// Set progress callback
	if opts.Progress != nil {
		cloneOpts.Progress = &progressWriter{callback: opts.Progress}
	}

	// Configure authentication (Requirements 4.1 and 4.2)
	auth, err := gs.getAuthentication(opts.AuthType, authOptions{
		Username:   opts.Username,
		Password:   opts.Password,
		Token:      opts.Token,
		SSHKeyPath: opts.SSHKeyPath,
	})
	if err != nil {
		return models.Err[string](NewAuthError(opts.AuthType, opts.URL, err.Error()))
	}
	cloneOpts.Auth = auth

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(opts.LocalPath), 0755); err != nil {
		return models.Err[string](WrapGitError("clone", err, GitErrorContext{
			RepositoryURL: opts.URL,
			LocalPath:     opts.LocalPath,
			AuthType:      opts.AuthType,
			Branch:        opts.Branch,
			Depth:         opts.Depth,
		}))
	}

	// Remove existing directory if it exists
	if _, err := os.Stat(opts.LocalPath); err == nil {
		if err := os.RemoveAll(opts.LocalPath); err != nil {
			return models.Err[string](WrapGitError("clone", err, GitErrorContext{
				RepositoryURL: opts.URL,
				LocalPath:     opts.LocalPath,
				AuthType:      opts.AuthType,
				Branch:        opts.Branch,
				Depth:         opts.Depth,
			}))
		}
	}

	// Clone the repository
	_, err = git.PlainCloneContext(ctx, opts.LocalPath, false, cloneOpts)
	if err != nil {
		// Clean up on failure
		os.RemoveAll(opts.LocalPath)
		return models.Err[string](NewCloneError(err, opts.URL, opts.LocalPath, opts.AuthType, opts.Branch, opts.Depth))
	}

	return models.Ok(opts.LocalPath)
}

// cloneWithSystemGit uses system git command for SSH operations
func (gs *GitService) cloneWithSystemGit(ctx context.Context, opts GitCloneOptions) models.Result[string] {
	// Validate options
	if opts.URL == "" {
		return models.Err[string](NewValidationError("repository URL", opts.URL, "URL cannot be empty"))
	}
	if opts.LocalPath == "" {
		return models.Err[string](NewValidationError("local path", opts.LocalPath, "local path cannot be empty"))
	}

	// Validate URL format
	urlValidation := gs.ValidateURL(opts.URL)
	if urlValidation.IsErr() {
		return models.Err[string](NewValidationError("repository URL", opts.URL, urlValidation.Error().Error()))
	}

	// Set defaults
	if opts.Depth == 0 && !opts.Full {
		opts.Depth = gs.config.DefaultDepth
	}
	if opts.Full {
		opts.Depth = 0 // Full clone
	}
	if opts.Branch == "" {
		opts.Branch = gs.config.DefaultBranch
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(opts.LocalPath), 0755); err != nil {
		return models.Err[string](WrapGitError("clone", err, GitErrorContext{
			RepositoryURL: opts.URL,
			LocalPath:     opts.LocalPath,
			AuthType:      opts.AuthType,
			Branch:        opts.Branch,
			Depth:         opts.Depth,
		}))
	}

	// Remove existing directory if it exists
	if _, err := os.Stat(opts.LocalPath); err == nil {
		if err := os.RemoveAll(opts.LocalPath); err != nil {
			return models.Err[string](WrapGitError("clone", err, GitErrorContext{
				RepositoryURL: opts.URL,
				LocalPath:     opts.LocalPath,
				AuthType:      opts.AuthType,
				Branch:        opts.Branch,
				Depth:         opts.Depth,
			}))
		}
	}

	// Build git clone command
	args := []string{"clone"}

	// Add depth for shallow clone
	if opts.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", opts.Depth))
	}

	// Add branch
	if opts.Branch != "" {
		args = append(args, "--branch", opts.Branch)
	}

	// Add single branch flag for shallow clones
	if opts.Depth > 0 {
		args = append(args, "--single-branch")
	}

	// Add URL and local path
	args = append(args, opts.URL, opts.LocalPath)

	// Create command
	cmd := exec.CommandContext(ctx, "git", args...)

	// Set environment to include SSH agent and system configuration
	cmd.Env = os.Environ()

	// Set working directory to parent of local path
	cmd.Dir = filepath.Dir(opts.LocalPath)

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Clean up on failure
		os.RemoveAll(opts.LocalPath)

		// Create detailed error with output
		errorMsg := fmt.Sprintf("git clone failed: %v\nOutput: %s", err, string(output))
		return models.Err[string](NewCloneError(errors.New(errorMsg), opts.URL, opts.LocalPath, opts.AuthType, opts.Branch, opts.Depth))
	}

	// Report progress if callback provided
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Successfully cloned %s to %s", opts.URL, opts.LocalPath))
	}

	return models.Ok(opts.LocalPath)
}

// Pull performs a git pull operation on an existing repository
// Requirement 1.1: Repository Management
func (gs *GitService) Pull(ctx context.Context, opts GitPullOptions) models.Result[string] {
	// Use system git for SSH operations to leverage SSH agent and system configuration
	if opts.AuthType == models.PayloadRepositoryAuthTypeSSH {
		return gs.pullWithSystemGit(ctx, opts)
	}
	// Validate options
	if opts.LocalPath == "" {
		return models.Err[string](NewValidationError("local path", opts.LocalPath, "local path cannot be empty"))
	}

	// Open existing repository
	repo, err := git.PlainOpen(opts.LocalPath)
	if err != nil {
		return models.Err[string](NewPullError(err, opts.LocalPath, opts.AuthType))
	}

	// Get working tree
	workTree, err := repo.Worktree()
	if err != nil {
		return models.Err[string](NewPullError(err, opts.LocalPath, opts.AuthType))
	}

	// Configure authentication
	auth, err := gs.getAuthentication(opts.AuthType, authOptions{
		Username:   opts.Username,
		Password:   opts.Password,
		Token:      opts.Token,
		SSHKeyPath: opts.SSHKeyPath,
	})
	if err != nil {
		return models.Err[string](NewAuthError(opts.AuthType, "", err.Error()))
	}

	// Prepare pull options
	pullOpts := &git.PullOptions{
		Auth: auth,
	}

	// Set progress callback
	if opts.Progress != nil {
		pullOpts.Progress = &progressWriter{callback: opts.Progress}
	}

	// Perform pull
	err = workTree.PullContext(ctx, pullOpts)
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return models.Err[string](NewPullError(err, opts.LocalPath, opts.AuthType))
	}

	// Get current HEAD commit
	head, err := repo.Head()
	if err != nil {
		return models.Err[string](NewPullError(err, opts.LocalPath, opts.AuthType))
	}

	return models.Ok(head.Hash().String())
}

// pullWithSystemGit uses system git command for SSH operations
func (gs *GitService) pullWithSystemGit(ctx context.Context, opts GitPullOptions) models.Result[string] {
	// Validate options
	if opts.LocalPath == "" {
		return models.Err[string](NewValidationError("local path", opts.LocalPath, "local path cannot be empty"))
	}

	// Check if directory exists and is a git repository
	if _, err := os.Stat(filepath.Join(opts.LocalPath, ".git")); os.IsNotExist(err) {
		return models.Err[string](NewPullError(errors.New("not a git repository"), opts.LocalPath, opts.AuthType))
	}

	// Build git pull command
	args := []string{"pull", "origin"}

	// Create command
	cmd := exec.CommandContext(ctx, "git", args...)

	// Set environment to include SSH agent and system configuration
	cmd.Env = os.Environ()

	// Set working directory to repository path
	cmd.Dir = opts.LocalPath

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's "already up to date" which is not really an error
		if strings.Contains(string(output), "up to date") || strings.Contains(string(output), "up-to-date") {
			// Get current HEAD commit hash
			hashCmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
			hashCmd.Dir = opts.LocalPath
			hashCmd.Env = os.Environ()
			hashOutput, hashErr := hashCmd.Output()
			if hashErr == nil {
				return models.Ok(strings.TrimSpace(string(hashOutput)))
			}
			return models.Ok("up-to-date")
		}

		// Create detailed error with output
		errorMsg := fmt.Sprintf("git pull failed: %v\nOutput: %s", err, string(output))
		return models.Err[string](NewPullError(errors.New(errorMsg), opts.LocalPath, opts.AuthType))
	}

	// Report progress if callback provided
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Successfully pulled updates to %s", opts.LocalPath))
	}

	// Get current HEAD commit hash
	hashCmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	hashCmd.Dir = opts.LocalPath
	hashCmd.Env = os.Environ()
	hashOutput, err := hashCmd.Output()
	if err != nil {
		return models.Err[string](NewPullError(err, opts.LocalPath, opts.AuthType))
	}

	return models.Ok(strings.TrimSpace(string(hashOutput)))
}

// Validate validates a Git repository and returns detailed information
// Requirement 1.1: Repository Management
func (gs *GitService) Validate(localPath string) models.Result[GitValidationResult] {
	result := GitValidationResult{
		IsValid:   true,
		IsGitRepo: false,
		HasRemote: false,
		IsDirty:   false,
		Errors:    []string{},
	}

	// Check if path exists
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		result.IsValid = false
		result.Errors = append(result.Errors, "path does not exist")
		return models.Ok(result)
	}

	// Try to open as git repository
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("not a git repository: %v", err))
		return models.Ok(result)
	}

	result.IsGitRepo = true

	// Check for remotes
	remotes, err := repo.Remotes()
	if err == nil && len(remotes) > 0 {
		result.HasRemote = true
		if len(remotes[0].Config().URLs) > 0 {
			result.RemoteURL = remotes[0].Config().URLs[0]
		}
	}

	// Get current branch
	head, err := repo.Head()
	if err == nil {
		if head.Name().IsBranch() {
			result.CurrentBranch = head.Name().Short()
		}
		result.LastCommit = head.Hash().String()
	}

	// Check if working tree is dirty
	workTree, err := repo.Worktree()
	if err == nil {
		status, err := workTree.Status()
		if err == nil {
			result.IsDirty = !status.IsClean()
		}
	}

	return models.Ok(result)
}

// authOptions holds authentication configuration
type authOptions struct {
	Username   string
	Password   string
	Token      string
	SSHKeyPath string
}

// getAuthentication configures authentication based on the auth type
// Requirements 4.1: SSH auth, 4.2: HTTPS auth
func (gs *GitService) getAuthentication(authType models.PayloadRepositoryAuthType, opts authOptions) (transport.AuthMethod, error) {
	switch authType {
	case models.PayloadRepositoryAuthTypeNone:
		return nil, nil

	case models.PayloadRepositoryAuthTypeHTTPS:
		if opts.Username == "" || opts.Password == "" {
			return nil, errors.New("username and password required for HTTPS authentication")
		}
		return &http.BasicAuth{
			Username: opts.Username,
			Password: opts.Password,
		}, nil

	case models.PayloadRepositoryAuthTypeToken:
		if opts.Token == "" {
			return nil, errors.New("token required for token authentication")
		}
		return &http.BasicAuth{
			Username: "git", // or any non-empty string
			Password: opts.Token,
		}, nil

	case models.PayloadRepositoryAuthTypeSSH:
		// Use SSH key path from options or fallback to config
		keyPath := opts.SSHKeyPath
		if keyPath == "" {
			keyPath = gs.config.SSHKeyPath
		}

		if keyPath != "" {
			// Use SSH key file
			auth, err := ssh.NewPublicKeysFromFile("git", keyPath, "")
			if err != nil {
				return nil, fmt.Errorf("failed to load SSH key from %s: %w", keyPath, err)
			}

			// Set known hosts if configured
			if gs.config.SSHKnownHostsPath != "" {
				callback, err := ssh.NewKnownHostsCallback(gs.config.SSHKnownHostsPath)
				if err == nil {
					auth.HostKeyCallback = callback
				}
			}

			return auth, nil
		}

		// Try SSH agent
		auth, err := ssh.NewSSHAgentAuth("git")
		if err != nil {
			return nil, fmt.Errorf("SSH authentication failed: no key file specified and SSH agent not available: %w", err)
		}
		return auth, nil

	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", authType)
	}
}

// progressWriter wraps a progress callback function
type progressWriter struct {
	callback func(string)
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	if pw.callback != nil {
		// Clean up the progress message
		msg := strings.TrimSpace(string(p))
		if msg != "" {
			pw.callback(msg)
		}
	}
	return len(p), nil
}

// GetDefaultConfig returns a default GitServiceConfig
func GetDefaultConfig() GitServiceConfig {
	homeDir, _ := os.UserHomeDir()
	return GitServiceConfig{
		DefaultDepth:      1, // Shallow clone by default (Requirement 1.3)
		DefaultBranch:     "main",
		BaseDir:           "/tmp/gibson-repos",
		SSHKeyPath:        filepath.Join(homeDir, ".ssh", "id_rsa"),
		SSHKnownHostsPath: filepath.Join(homeDir, ".ssh", "known_hosts"),
		UseSystemGit:      true, // Use system git for better SSH support
	}
}

// ValidateURL validates a Git repository URL
func (gs *GitService) ValidateURL(url string) models.Result[bool] {
	if err := utils.ValidateGitURL(url); err != nil {
		return models.Err[bool](err)
	}
	return models.Ok(true)
}

// GetRemoteInfo gets information about the remote repository
func (gs *GitService) GetRemoteInfo(localPath string) models.Result[map[string]string] {
	repo, err := git.PlainOpen(localPath)
	if err != nil {
		return models.Err[map[string]string](fmt.Errorf("failed to open repository: %w", err))
	}

	remotes, err := repo.Remotes()
	if err != nil {
		return models.Err[map[string]string](fmt.Errorf("failed to get remotes: %w", err))
	}

	remoteInfo := make(map[string]string)
	for _, remote := range remotes {
		config := remote.Config()
		if len(config.URLs) > 0 {
			remoteInfo[config.Name] = config.URLs[0]
		}
	}

	return models.Ok(remoteInfo)
}