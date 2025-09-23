# Gibson Services

This package provides core services for the Gibson security testing framework.

## GitService

The `GitService` provides comprehensive Git operations using the go-git library, specifically designed for managing payload repositories.

### Features

- **Clone Operations** (Requirement 1.1, 1.3)
  - Default shallow clone with depth=1
  - Support for `--depth` and `--full` flags
  - Single branch cloning for efficiency
  - Progress callbacks for UI feedback

- **Authentication Support** (Requirements 4.1, 4.2)
  - SSH key authentication (4.1)
  - HTTPS basic authentication (4.2)
  - GitHub token authentication
  - SSH agent support
  - No authentication for public repositories

- **Repository Management** (Requirement 1.1)
  - Pull operations for existing repositories
  - Repository validation and health checks
  - Remote information retrieval
  - Working tree status checking

- **Error Handling**
  - Uses Gibson's Result[T] pattern for functional error handling
  - Comprehensive error messages
  - Graceful fallbacks and cleanup

### Quick Start

```go
// Create service with default configuration
gitService := services.NewGitService(services.GetDefaultConfig())

// Clone a public repository with shallow clone (default)
result := gitService.Clone(context.Background(), services.GitCloneOptions{
    URL:       "https://github.com/user/repo.git",
    LocalPath: "/tmp/repo",
    AuthType:  models.PayloadRepositoryAuthTypeNone,
})

if result.IsOk() {
    fmt.Printf("Cloned to: %s\n", result.Unwrap())
}
```

### Configuration

```go
config := services.GitServiceConfig{
    DefaultDepth:      1,                           // Shallow clone depth
    DefaultBranch:     "main",                      // Default branch to clone
    BaseDir:           "/tmp/gibson-repos",         // Base directory for repos
    SSHKeyPath:        "/home/user/.ssh/id_rsa",    // SSH private key
    SSHKnownHostsPath: "/home/user/.ssh/known_hosts", // SSH known hosts
}
```

### Authentication Types

- `PayloadRepositoryAuthTypeNone`: Public repositories
- `PayloadRepositoryAuthTypeHTTPS`: Username/password authentication
- `PayloadRepositoryAuthTypeToken`: Token-based authentication (GitHub, GitLab)
- `PayloadRepositoryAuthTypeSSH`: SSH key or SSH agent authentication

### Key Methods

- `Clone(ctx, opts)`: Clone a repository with specified options
- `Pull(ctx, opts)`: Pull latest changes from remote
- `Validate(path)`: Validate and get repository information
- `ValidateURL(url)`: Validate a Git repository URL
- `GetRemoteInfo(path)`: Get remote repository information

### Requirements Implementation

- **1.1 Repository Management**: Full CRUD operations for Git repositories
- **1.3 Default Shallow Clone**: All clones default to depth=1 unless `--full` flag is used
- **4.1 SSH Authentication**: Support for SSH key files and SSH agent
- **4.2 HTTPS Authentication**: Basic auth and token-based authentication

### Testing

The service includes comprehensive tests covering:
- Unit tests for all major functionality
- Error condition testing
- Authentication method validation
- URL validation
- Integration tests (with network access)

Run tests:
```bash
go test ./pkg/services -v -short
```

For integration tests with real repositories:
```bash
go test ./pkg/services -v
```

### Error Handling

All methods return `models.Result[T]` types for consistent error handling:

```go
result := gitService.Clone(ctx, opts)
if result.IsErr() {
    log.Printf("Clone failed: %v", result.Error())
    return
}

path := result.Unwrap()
fmt.Printf("Successfully cloned to: %s\n", path)
```

### Examples

See `git_service_example_test.go` for comprehensive usage examples including:
- Basic cloning operations
- Different authentication methods
- Complete Git workflows
- Error handling patterns