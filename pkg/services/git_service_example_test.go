// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/zero-day-ai/gibson-framework/pkg/services"
)

func ExampleGitService_Clone() {
	// Create a new GitService with default configuration
	gitService := services.NewGitService(services.GetDefaultConfig())

	// Prepare clone options
	opts := services.GitCloneOptions{
		URL:       "https://github.com/octocat/Hello-World.git",
		LocalPath: "/tmp/example-repo",
		Depth:     1, // Shallow clone (default)
		Branch:    "main",
		AuthType:  models.PayloadRepositoryAuthTypeNone, // Public repository
		Progress: func(msg string) {
			fmt.Printf("Progress: %s\n", msg)
		},
	}

	// Clone the repository
	ctx := context.Background()
	result := gitService.Clone(ctx, opts)

	if result.IsOk() {
		fmt.Printf("Repository cloned successfully to: %s\n", result.Unwrap())
	} else {
		fmt.Printf("Clone failed: %v\n", result.Error())
	}

	// Clean up
	os.RemoveAll("/tmp/example-repo")
}

func ExampleGitService_Clone_sshAuth() {
	// Create a GitService with custom SSH configuration
	config := services.GetDefaultConfig()
	config.SSHKeyPath = "/home/user/.ssh/id_rsa"
	config.SSHKnownHostsPath = "/home/user/.ssh/known_hosts"
	gitService := services.NewGitService(config)

	// Clone with SSH authentication
	opts := services.GitCloneOptions{
		URL:       "git@github.com:user/private-repo.git",
		LocalPath: "/tmp/private-repo",
		Depth:     0, // Full clone
		AuthType:  models.PayloadRepositoryAuthTypeSSH,
	}

	ctx := context.Background()
	result := gitService.Clone(ctx, opts)

	if result.IsOk() {
		fmt.Printf("Private repository cloned successfully\n")
	} else {
		fmt.Printf("Clone failed: %v\n", result.Error())
	}
}

func ExampleGitService_Clone_tokenAuth() {
	gitService := services.NewGitService(services.GetDefaultConfig())

	// Clone with GitHub token authentication
	opts := services.GitCloneOptions{
		URL:       "https://github.com/user/private-repo.git",
		LocalPath: "/tmp/private-repo-token",
		Depth:     1,
		AuthType:  models.PayloadRepositoryAuthTypeToken,
		Token:     "ghp_your_github_token_here",
	}

	ctx := context.Background()
	result := gitService.Clone(ctx, opts)

	if result.IsOk() {
		fmt.Printf("Repository cloned with token auth\n")
	} else {
		fmt.Printf("Clone failed: %v\n", result.Error())
	}
}

func ExampleGitService_Pull() {
	gitService := services.NewGitService(services.GetDefaultConfig())

	// Pull latest changes from an existing repository
	opts := services.GitPullOptions{
		LocalPath: "/tmp/existing-repo",
		AuthType:  models.PayloadRepositoryAuthTypeNone,
		Progress: func(msg string) {
			fmt.Printf("Pull progress: %s\n", msg)
		},
	}

	ctx := context.Background()
	result := gitService.Pull(ctx, opts)

	if result.IsOk() {
		fmt.Printf("Repository updated. Latest commit: %s\n", result.Unwrap())
	} else {
		fmt.Printf("Pull failed: %v\n", result.Error())
	}
}

func ExampleGitService_Validate() {
	gitService := services.NewGitService(services.GetDefaultConfig())

	// Validate a local repository
	result := gitService.Validate("/path/to/local/repo")

	if result.IsOk() {
		validation := result.Unwrap()

		fmt.Printf("Repository validation results:\n")
		fmt.Printf("  Is valid: %t\n", validation.IsValid)
		fmt.Printf("  Is Git repo: %t\n", validation.IsGitRepo)
		fmt.Printf("  Has remote: %t\n", validation.HasRemote)
		fmt.Printf("  Remote URL: %s\n", validation.RemoteURL)
		fmt.Printf("  Current branch: %s\n", validation.CurrentBranch)
		fmt.Printf("  Is dirty: %t\n", validation.IsDirty)
		fmt.Printf("  Last commit: %s\n", validation.LastCommit)

		if len(validation.Errors) > 0 {
			fmt.Printf("  Errors: %v\n", validation.Errors)
		}
	} else {
		fmt.Printf("Validation failed: %v\n", result.Error())
	}
}

func ExampleGitService_ValidateURL() {
	gitService := services.NewGitService(services.GetDefaultConfig())

	// Validate different types of Git URLs
	urls := []string{
		"https://github.com/user/repo.git",
		"git@github.com:user/repo.git",
		"ssh://git@gitlab.com/user/repo.git",
		"invalid-url",
	}

	for _, url := range urls {
		result := gitService.ValidateURL(url)
		if result.IsOk() {
			fmt.Printf("✓ %s is valid\n", url)
		} else {
			fmt.Printf("✗ %s is invalid: %v\n", url, result.Error())
		}
	}
}

func ExampleGitService_GetRemoteInfo() {
	gitService := services.NewGitService(services.GetDefaultConfig())

	// Get remote information from a local repository
	result := gitService.GetRemoteInfo("/path/to/local/repo")

	if result.IsOk() {
		remotes := result.Unwrap()
		fmt.Printf("Remote repositories:\n")
		for name, url := range remotes {
			fmt.Printf("  %s: %s\n", name, url)
		}
	} else {
		fmt.Printf("Failed to get remote info: %v\n", result.Error())
	}
}

// Example workflow demonstrating a complete Git workflow
func ExampleGitService_workflow() {
	gitService := services.NewGitService(services.GetDefaultConfig())
	ctx := context.Background()

	repoPath := "/tmp/gibson-payload-repo"

	// Step 1: Validate URL
	url := "https://github.com/user/payload-repo.git"
	if result := gitService.ValidateURL(url); result.IsErr() {
		log.Fatalf("Invalid URL: %v", result.Error())
	}

	// Step 2: Clone repository with shallow clone (default)
	cloneResult := gitService.Clone(ctx, services.GitCloneOptions{
		URL:       url,
		LocalPath: repoPath,
		AuthType:  models.PayloadRepositoryAuthTypeToken,
		Token:     os.Getenv("GITHUB_TOKEN"),
		Progress: func(msg string) {
			fmt.Printf("Clone: %s\n", msg)
		},
	})

	if cloneResult.IsErr() {
		log.Fatalf("Clone failed: %v", cloneResult.Error())
	}

	// Step 3: Validate the cloned repository
	validation := gitService.Validate(repoPath)
	if validation.IsOk() {
		info := validation.Unwrap()
		fmt.Printf("Cloned repository info:\n")
		fmt.Printf("  Branch: %s\n", info.CurrentBranch)
		fmt.Printf("  Last commit: %s\n", info.LastCommit)
		fmt.Printf("  Clean: %t\n", !info.IsDirty)
	}

	// Step 4: Get remote information
	if remoteResult := gitService.GetRemoteInfo(repoPath); remoteResult.IsOk() {
		remotes := remoteResult.Unwrap()
		for name, remoteURL := range remotes {
			fmt.Printf("Remote %s: %s\n", name, remoteURL)
		}
	}

	// Step 5: Pull latest changes (if repository is already up to date)
	pullResult := gitService.Pull(ctx, services.GitPullOptions{
		LocalPath: repoPath,
		AuthType:  models.PayloadRepositoryAuthTypeToken,
		Token:     os.Getenv("GITHUB_TOKEN"),
	})

	if pullResult.IsOk() {
		fmt.Printf("Repository is up to date. Head: %s\n", pullResult.Unwrap())
	}

	// Clean up
	defer os.RemoveAll(repoPath)
}

// Example showing how to handle different authentication methods
func ExampleGitService_authenticationMethods() {
	gitService := services.NewGitService(services.GetDefaultConfig())
	ctx := context.Background()

	baseDir := "/tmp/auth-examples"
	os.MkdirAll(baseDir, 0755)
	defer os.RemoveAll(baseDir)

	// Public repository - no authentication needed
	publicResult := gitService.Clone(ctx, services.GitCloneOptions{
		URL:       "https://github.com/octocat/Hello-World.git",
		LocalPath: filepath.Join(baseDir, "public"),
		AuthType:  models.PayloadRepositoryAuthTypeNone,
	})

	if publicResult.IsOk() {
		fmt.Println("✓ Public repository cloned successfully")
	}

	// Private repository with token authentication
	tokenResult := gitService.Clone(ctx, services.GitCloneOptions{
		URL:       "https://github.com/user/private-repo.git",
		LocalPath: filepath.Join(baseDir, "private-token"),
		AuthType:  models.PayloadRepositoryAuthTypeToken,
		Token:     "ghp_your_token_here",
	})

	if tokenResult.IsOk() {
		fmt.Println("✓ Private repository cloned with token")
	} else {
		fmt.Printf("Token auth failed: %v\n", tokenResult.Error())
	}

	// Private repository with HTTPS basic auth
	httpsResult := gitService.Clone(ctx, services.GitCloneOptions{
		URL:       "https://github.com/user/private-repo.git",
		LocalPath: filepath.Join(baseDir, "private-https"),
		AuthType:  models.PayloadRepositoryAuthTypeHTTPS,
		Username:  "your-username",
		Password:  "your-password-or-token",
	})

	if httpsResult.IsOk() {
		fmt.Println("✓ Private repository cloned with HTTPS auth")
	} else {
		fmt.Printf("HTTPS auth failed: %v\n", httpsResult.Error())
	}

	// Private repository with SSH authentication
	sshResult := gitService.Clone(ctx, services.GitCloneOptions{
		URL:       "git@github.com:user/private-repo.git",
		LocalPath: filepath.Join(baseDir, "private-ssh"),
		AuthType:  models.PayloadRepositoryAuthTypeSSH,
		SSHKeyPath: "/home/user/.ssh/id_rsa",
	})

	if sshResult.IsOk() {
		fmt.Println("✓ Private repository cloned with SSH")
	} else {
		fmt.Printf("SSH auth failed: %v\n", sshResult.Error())
	}
}