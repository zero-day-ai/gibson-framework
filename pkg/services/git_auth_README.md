# Git Authentication Helper

The Git Authentication Helper provides secure credential management and authentication for Git repositories in the Gibson Framework. It supports both SSH and HTTPS authentication methods while integrating with Gibson's existing encrypted credential storage system.

## Features

### Authentication Methods
- **SSH Key Authentication**: Auto-discovery of SSH keys from standard locations (`~/.ssh/`)
- **HTTPS Personal Access Tokens**: Support for GitHub, GitLab, and other Git hosting services
- **Basic Authentication**: Username/password authentication for HTTPS repositories
- **Auto-Detection**: Automatic authentication method selection based on repository URL

### Security
- **AES-256-GCM Encryption**: Leverages Gibson's existing credential encryption system
- **Secure Key Derivation**: Uses scrypt for key derivation with per-credential salts
- **Credential Caching**: Session-based credential caching with configurable timeouts
- **No Plaintext Storage**: All credentials are encrypted at rest

### Integration
- **Gibson Credential System**: Seamless integration with existing credential management
- **GitService Compatibility**: Designed to work with existing Git operations
- **Plugin Architecture**: Extensible for custom authentication methods

## Usage

### Basic Setup

```go
import (
    "context"
    "github.com/zero-day-ai/gibson-framework/pkg/services"
    "github.com/zero-day-ai/gibson-framework/internal/service"
)

// Initialize with service factory and encryption key
serviceFactory := service.NewServiceFactory(repo, logger, encryptionKey)
gitAuth := services.NewGitAuthenticator(serviceFactory, encryptionKey, nil)
```

### SSH Key Authentication

```go
// Auto-discovery (recommended)
auth, err := gitAuth.GetAuthentication(ctx, "git@github.com:user/repo.git",
    coremodels.PayloadRepositoryAuthTypeSSH)

// Manual SSH key storage
helper := services.NewAuthenticationHelper(gitAuth)
err := helper.SetupSSHKey(ctx, "my-ssh-key", sshKeyContent, "git@github.com:user/repo.git")
```

### HTTPS Token Authentication

```go
// Store personal access token
helper := services.NewAuthenticationHelper(gitAuth)
err := helper.SetupPersonalAccessToken(ctx, "github-pat", "ghp_xxxxx", "https://github.com")

// Use for repository access
auth, err := gitAuth.GetAuthentication(ctx, "https://github.com/user/private-repo.git",
    coremodels.PayloadRepositoryAuthTypeHTTPS)
```

### Basic Authentication

```go
// Store username/password
helper := services.NewAuthenticationHelper(gitAuth)
err := helper.SetupBasicAuth(ctx, "git-basic", "username", "password", "https://git.example.com")
```

### Repository Access Validation

```go
// Test repository access
err := gitAuth.ValidateRepositoryAccess(ctx, repoURL, authType)
if err != nil {
    log.Printf("Repository access failed: %v", err)
}

// Detailed authentication testing
result, err := helper.TestAuthentication(ctx, repoURL, authType)
if result.Success {
    log.Printf("Authentication successful using: %s", result.Method)
}
```

## Configuration

### GitAuthConfig

```go
config := &services.GitAuthConfig{
    SSHKeyPaths: []string{
        "/home/user/.ssh/id_rsa",
        "/home/user/.ssh/id_ed25519",
    },
    CacheTimeout: 15 * time.Minute,
    KnownHostsPath: "/home/user/.ssh/known_hosts",
}

gitAuth := services.NewGitAuthenticator(serviceFactory, encryptionKey, config)
```

### Default SSH Key Locations

The system automatically searches for SSH keys in:
- `~/.ssh/id_rsa`
- `~/.ssh/id_ed25519`
- `~/.ssh/id_ecdsa`
- `~/.ssh/id_dsa`

## Integration with GitService

```go
// Create enhanced GitService with authentication
gitService := services.NewGitService(config)
gitServiceWithAuth := services.NewGitServiceWithAuth(gitService, gitAuth)

// Clone with authentication
err := gitServiceWithAuth.CloneWithAuth(ctx, repoURL, localPath, options)

// Pull with authentication
err := gitServiceWithAuth.PullWithAuth(ctx, repoPath, repoURL, authType)
```

## Credential Management

### Listing Git Credentials

```go
credentials, err := gitAuth.ListGitCredentials(ctx)
for _, cred := range credentials {
    fmt.Printf("Name: %s, Type: %s, Auth: %s\n",
        cred.Name, cred.Type, cred.AuthType)
}
```

### Cache Management

```go
// Clear authentication cache
gitAuth.ClearAuthCache()

// Get cache status
status := gitAuth.GetCacheStatus()
for key, expiry := range status {
    fmt.Printf("Cached: %s, Expires: %s\n", key, expiry)
}
```

### Authentication Status

```go
helper := services.NewAuthenticationHelper(gitAuth)
status := helper.GetAuthenticationStatus(ctx)

// Shows cache status, discovered SSH keys, and stored credentials
fmt.Printf("Authentication Status: %+v\n", status)
```

## Security Best Practices

### Credential Storage
- All credentials are encrypted using AES-256-GCM equivalent encryption
- Each credential uses a unique salt for key derivation
- Private keys and tokens are never stored in plaintext

### SSH Key Management
- Use SSH agent when available for better security
- Rotate SSH keys regularly
- Restrict SSH key permissions (`chmod 600`)

### Token Management
- Use personal access tokens instead of passwords
- Limit token scopes to minimum required permissions
- Rotate tokens regularly using Gibson's credential rotation features

### Network Security
- Verify SSH host keys (known_hosts)
- Use HTTPS for token-based authentication
- Validate repository access before operations

## Error Handling

### Common Error Scenarios

```go
auth, err := gitAuth.GetAuthentication(ctx, repoURL, authType)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "no SSH keys found"):
        // Guide user to set up SSH keys
        fmt.Println("Setup SSH keys or use HTTPS authentication")

    case strings.Contains(err.Error(), "no suitable HTTPS credentials"):
        // Guide user to add personal access token
        fmt.Println("Add a personal access token for HTTPS authentication")

    default:
        // Generic error handling
        fmt.Printf("Authentication error: %v\n", err)
    }
}
```

### Troubleshooting Authentication

1. **SSH Authentication Issues**
   - Verify SSH keys exist in standard locations
   - Check SSH key permissions and format
   - Ensure SSH agent is running if using agent authentication

2. **HTTPS Authentication Issues**
   - Verify personal access token is valid and not expired
   - Check token permissions for repository access
   - Ensure repository URL uses HTTPS protocol

3. **Credential Decryption Issues**
   - Verify encryption key is available and correct
   - Check Gibson database connectivity
   - Ensure credential hasn't been corrupted

## Architecture

### Components

1. **GitAuthenticator**: Main authentication coordinator
2. **CredentialDecryptor**: Handles credential encryption/decryption
3. **AuthenticationHelper**: High-level convenience functions
4. **GitServiceWithAuth**: Enhanced GitService with authentication

### Authentication Flow

1. **Request**: Application requests authentication for repository URL
2. **Cache Check**: System checks for cached authentication
3. **Credential Lookup**: Searches credential store for matching credentials
4. **Key Discovery**: Falls back to SSH key auto-discovery if needed
5. **Authentication**: Creates go-git transport auth method
6. **Caching**: Caches successful authentication for session duration

### Integration Points

- **Credential Service**: Uses Gibson's encrypted credential storage
- **Service Factory**: Integrates with Gibson's dependency injection
- **Git Operations**: Compatible with existing GitService operations
- **CLI Commands**: Can be integrated with repository management commands

## Future Enhancements

### Planned Features
- SSH agent integration for better security
- Advanced credential rotation for Git credentials
- Repository-specific credential policies
- Integration with external credential providers (e.g., cloud key management)
- Support for Git credential helpers

### Extension Points
- Custom authentication method plugins
- External credential provider interfaces
- Advanced caching strategies
- Audit logging for credential usage

## Requirements

### Dependencies
- go-git/v5 for Git transport authentication
- golang.org/x/crypto/ssh for SSH key handling
- Gibson's existing credential and service infrastructure

### Permissions
- Read access to SSH key directories (`~/.ssh/`)
- Access to Gibson's credential database
- Network access for repository operations

### Compatibility
- Supports Git over SSH and HTTPS protocols
- Compatible with GitHub, GitLab, and custom Git servers
- Works with existing Gibson Framework architecture