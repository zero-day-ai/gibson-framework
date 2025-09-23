# Payload Repository Commands

The payload repository commands allow you to manage Git repositories containing security payloads. These commands have been enhanced with improved error handling, automatic LocalPath generation, and robust synchronization.

## Table of Contents

- [Overview](#overview)
- [Commands](#commands)
  - [add](#add)
  - [list](#list)
  - [sync](#sync)
  - [remove](#remove)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)

## Overview

Payload repositories are Git repositories that contain security testing payloads. Gibson automatically manages cloning, synchronization, and payload discovery from these repositories.

### Key Features

- **Automatic LocalPath Generation**: Repositories are automatically cloned to `~/.gibson/repositories/{name}`
- **Checksum-based Change Detection**: Payloads are tracked with checksums for efficient updates
- **Flexible Authentication**: Support for HTTPS, SSH, and token-based authentication
- **Shallow and Full Cloning**: Configurable clone depth for performance optimization
- **Automatic Sync**: Optional automatic synchronization on schedules

## Commands

### add

Add a new Git repository as a payload source.

#### Syntax

```bash
gibson payload repository add [NAME] [URL] [flags]
```

#### Arguments

- `NAME` - Repository name (required)
- `URL` - Git repository URL (required)

#### Flags

- `--depth INT` - Clone depth (default: 1 for shallow clone)
- `--full` - Perform full clone instead of shallow
- `--branch STRING` - Branch to clone (default: "main")
- `--auth-type STRING` - Authentication type: none, ssh, https, token (default: "https")
- `--auto-sync` - Enable automatic synchronization
- `--description STRING` - Repository description
- `--tags STRINGS` - Repository tags
- `--force` - Overwrite existing repository
- `--verbose` - Show detailed output
- `--help-errors` - Show error troubleshooting guidance
- `--output STRING` - Output format: table, json, yaml (default: "table")

#### Enhanced Features

- **Automatic LocalPath Generation**: Each repository gets a unique local path under `~/.gibson/repositories/`
- **URL Validation**: Repository URLs are validated before attempting to clone
- **Conflict Resolution**: Duplicate names are handled with unique path generation
- **Enhanced Error Messages**: Detailed troubleshooting guidance for common issues

#### Examples

```bash
# Add a public repository with shallow clone
gibson payload repository add payloads-basic https://github.com/example/payloads.git

# Add with full clone for complete history
gibson payload repository add payloads-full https://github.com/example/payloads.git --full

# Add with specific branch and depth
gibson payload repository add payloads-dev https://github.com/example/payloads.git --branch development --depth 5

# Add private repository with SSH authentication
gibson payload repository add private-payloads git@github.com:example/private-payloads.git --auth-type ssh

# Add with auto-sync enabled
gibson payload repository add auto-payloads https://github.com/example/payloads.git --auto-sync --description "Auto-synced payloads"

# Force overwrite existing repository
gibson payload repository add existing-repo https://github.com/example/new-payloads.git --force
```

### list

List all configured payload repositories with their status.

#### Syntax

```bash
gibson payload repository list [flags]
```

#### Flags

- `--tags STRINGS` - Filter by tags
- `--show-status` - Show detailed sync status
- `--output STRING` - Output format: table, json, yaml (default: "table")

#### Enhanced Features

- **LocalPath Display**: Shows the local path where each repository is cloned
- **Sync Status**: Displays last sync time, status, and payload count
- **Size Information**: Shows repository size and payload statistics

#### Examples

```bash
# List all repositories
gibson payload repository list

# List with detailed sync status
gibson payload repository list --show-status

# List repositories with specific tags
gibson payload repository list --tags web,injection

# Output as JSON
gibson payload repository list --output json
```

### sync

Synchronize repositories with their remote sources.

#### Syntax

```bash
gibson payload repository sync [NAMES...] [flags]
```

#### Arguments

- `NAMES` - Repository names to sync (optional, defaults to all)

#### Flags

- `--force` - Force sync even if up-to-date
- `--progress` - Show sync progress
- `--verbose` - Show detailed output
- `--help-errors` - Show error troubleshooting guidance
- `--output STRING` - Output format: table, json, yaml (default: "table")

#### Enhanced Features

- **Automatic LocalPath Repair**: Generates LocalPath for repositories missing it
- **Smart Sync Detection**: Only syncs repositories that need updates (unless --force)
- **Clone vs Pull Logic**: Automatically determines whether to clone or pull
- **Progress Tracking**: Real-time sync progress with --progress flag
- **Error Recovery**: Robust error handling with recovery suggestions

#### Examples

```bash
# Sync all repositories
gibson payload repository sync

# Sync specific repositories
gibson payload repository sync payloads-basic payloads-dev

# Force sync with progress
gibson payload repository sync --force --progress

# Sync with verbose output for troubleshooting
gibson payload repository sync payloads-basic --verbose
```

### remove

Remove payload repositories.

#### Syntax

```bash
gibson payload repository remove [NAMES...] [flags]
```

#### Arguments

- `NAMES` - Repository names to remove (required)

#### Flags

- `--force` - Skip confirmation prompt
- `--purge-payloads` - Also remove associated payloads from database
- `--output STRING` - Output format: table, json, yaml (default: "table")

#### Examples

```bash
# Remove a repository (with confirmation)
gibson payload repository remove old-payloads

# Remove multiple repositories
gibson payload repository remove repo1 repo2 repo3

# Force removal without confirmation
gibson payload repository remove old-payloads --force

# Remove repository and all its payloads
gibson payload repository remove old-payloads --purge-payloads
```

## Configuration

### Authentication

Repositories support multiple authentication methods:

#### HTTPS (Default)
```bash
gibson payload repository add repo https://github.com/user/repo.git --auth-type https
```

#### SSH
```bash
gibson payload repository add repo git@github.com:user/repo.git --auth-type ssh
```

#### Token-based
```bash
gibson payload repository add repo https://github.com/user/repo.git --auth-type token
```

### Clone Configuration

#### Shallow Clone (Default)
Clones only the latest commit for faster downloads:
```bash
gibson payload repository add repo URL --depth 1
```

#### Full Clone
Clones complete history:
```bash
gibson payload repository add repo URL --full
```

#### Custom Depth
Clones specific number of commits:
```bash
gibson payload repository add repo URL --depth 10
```

## Troubleshooting

### Common Issues and Solutions

#### 1. "no such table: payload_repositories"

**Problem**: Database schema is missing the payload_repositories table.

**Solution**:
```bash
# Run gibson init to ensure all migrations are applied
gibson init

# Or check database status
gibson status --check-database
```

#### 2. Repository Sync Failures

**Problem**: Repository fails to sync with "empty LocalPath" error.

**Solution**:
```bash
# Sync will automatically generate LocalPath for existing repositories
gibson payload repository sync repo-name --verbose

# Or force sync all repositories
gibson payload repository sync --force
```

#### 3. Authentication Failures

**Problem**: Git operations fail with authentication errors.

**Solutions**:

For HTTPS repositories:
```bash
# Ensure credentials are configured
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# For private repositories, use personal access tokens
gibson payload repository add repo https://token@github.com/user/repo.git
```

For SSH repositories:
```bash
# Ensure SSH key is configured
ssh-keygen -t ed25519 -C "your.email@example.com"
ssh-add ~/.ssh/id_ed25519

# Test SSH connection
ssh -T git@github.com
```

#### 4. Clone Errors

**Problem**: Repository cloning fails.

**Troubleshooting Steps**:

1. Verify repository URL:
```bash
gibson payload repository add test-repo URL --force
```

2. Check network connectivity:
```bash
curl -I URL
```

3. Test with different authentication:
```bash
gibson payload repository add repo URL --auth-type ssh
```

4. Use verbose mode for details:
```bash
gibson payload repository add repo URL --verbose
```

5. Get error help:
```bash
gibson payload repository add --help-errors
```

#### 5. Disk Space Issues

**Problem**: Clone fails due to insufficient disk space.

**Solutions**:
```bash
# Use shallow clone to reduce size
gibson payload repository add repo URL --depth 1

# Check disk space
df -h ~/.gibson/repositories/

# Clean up old repositories
gibson payload repository remove old-repo1 old-repo2
```

### Error Help

For detailed error guidance, use the `--help-errors` flag:

```bash
gibson payload repository add --help-errors
gibson payload repository sync --help-errors
```

This provides specific troubleshooting steps for common Git and network issues.

## Examples

### Complete Workflow Example

```bash
# 1. Add a public repository with auto-sync
gibson payload repository add community-payloads \
  https://github.com/community/security-payloads.git \
  --auto-sync \
  --description "Community security testing payloads" \
  --tags community,web,injection

# 2. Add a private repository with SSH
gibson payload repository add private-payloads \
  git@github.com:myorg/private-payloads.git \
  --auth-type ssh \
  --full \
  --description "Private organizational payloads"

# 3. List repositories to verify
gibson payload repository list --show-status

# 4. Sync all repositories
gibson payload repository sync --progress

# 5. Check sync results
gibson payload repository list --output json
```

### Repository Management Best Practices

1. **Use Meaningful Names**: Choose descriptive repository names
2. **Tag Appropriately**: Use tags for organization and filtering
3. **Monitor Sync Status**: Regularly check sync status
4. **Use Shallow Clones**: Use shallow clones for large repositories unless history is needed
5. **Automate Syncing**: Enable auto-sync for frequently updated repositories
6. **Regular Cleanup**: Remove unused repositories to save disk space

### Integration with Payloads

Once repositories are added and synced, their payloads are automatically discovered and can be used:

```bash
# List payloads from repositories
gibson payload list --repository community-payloads

# Search for specific payloads
gibson payload search --query "SQL injection" --repository private-payloads

# Run scans with repository payloads
gibson scan start target1 --payload-repository community-payloads
```